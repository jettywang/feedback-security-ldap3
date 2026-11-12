"""
DIGEST-MD5 mutual authentication tests (RFC 2831).

The real sasl_digest_md5 negotiation code is driven against a scripted, in-process
LDAP server that issues a fixed challenge and computes the rspauth proof independently.
No network connection is required.
"""

# Copyright 2025 Giovanni Cannata
#
# This file is part of ldap3.
#
# ldap3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ldap3 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

import unittest
from types import SimpleNamespace

import ldap3.protocol.sasl.digestMd5 as digest_md5_module
from ldap3 import SIGN, ENCRYPT
from ldap3.core.exceptions import LDAPCommunicationError
from ldap3.core.results import RESULT_SASL_BIND_IN_PROGRESS, RESULT_SUCCESS, RESULT_INVALID_CREDENTIALS
from ldap3.protocol.sasl.digestMd5 import (
    sasl_digest_md5,
    decode_directives,
    md5_h,
    md5_hex,
    md5_kd,
    HANDSHAKE_NOT_STARTED,
    HANDSHAKE_COMPLETED,
)

FIXED_NONCE = 'OAqZ+BCmZQyHCCNGZvxr2JLDsnDSj6PqhrSSzl6eHwTg59QS'
FIXED_REALM = 'example.org'
FIXED_HOST = 'ldap.example.org'
FIXED_USER = 'chris'
FIXED_PASSWORD = 'secret'
FIXED_AUTHZ_ID = 'dn:uid=chris,ou=people,dc=example,dc=org'
FIXED_CNONCE = '0a1b2c3d4e5f60718293a4b5c6d7e8f9'


def independent_rspauth(client_directives, password):
    # independent server-side implementation of the RFC 2831 rspauth calculation,
    # written separately from the production code path
    charset = 'utf-8'
    user = client_directives['username'].encode(charset)
    realm = client_directives['realm'].encode(charset)
    nonce = client_directives['nonce'].encode(charset)
    cnonce = client_directives['cnonce'].encode(charset)
    qop = client_directives['qop'].encode(charset)
    authz_id = client_directives['authzid'].encode(charset) if 'authzid' in client_directives else b''

    a0 = md5_h(b':'.join([user, realm, password.encode(charset)]))
    a1 = b':'.join([a0, nonce, cnonce, authz_id]) if authz_id else b':'.join([a0, nonce, cnonce])
    # RFC 2831 step Three: A2 = ":" digest-uri-value (plus the 32 zeros for auth-int/auth-conf)
    a2_value = b':' + b'ldap/' + FIXED_HOST.encode(charset)
    if qop in (b'auth-int', b'auth-conf'):
        a2_value += b':00000000000000000000000000000000'
    a2 = md5_h(a2_value)
    # RFC 2831 rspauth KD join does not carry an authzid field; the identity is bound through A1
    return md5_hex(md5_kd(md5_hex(md5_h(a1)),
                          b':'.join([nonce, b'00000001', cnonce, qop, md5_hex(a2)]))).decode('ascii')


class ScriptedDigestMd5Server:
    """Scripted SASL peer recording every bind payload the client sends."""

    def __init__(self, proof_mode='valid', include_authz=True, final_mode='success', keep_alive_proofs=False):
        self.proof_mode = proof_mode
        self.include_authz = include_authz
        self.final_mode = final_mode
        self.keep_alive_proofs = keep_alive_proofs
        self.payloads = []
        self.aborted = False
        self.client_directives = None

    def challenge(self):
        directives = 'realm="%s",nonce="%s",qop="auth,auth-int,auth-conf",cipher="rc4-40,rc4-56,rc4",' \
                     'algorithm=md5-sess,charset=utf-8' % (FIXED_REALM, FIXED_NONCE)
        return directives.encode('utf-8')

    def proof_credentials(self):
        directives = dict(self.client_directives)
        if not self.include_authz:
            directives.pop('authzid', None)
        rspauth = independent_rspauth(directives, FIXED_PASSWORD)
        if self.proof_mode == 'tampered':
            rspauth = '0' * len(rspauth)
        elif self.proof_mode == 'foreign':
            # a proof computed for a different nonce, as replayed from an ended handshake
            foreign_directives = dict(directives)
            foreign_directives['nonce'] = 'deadbeef' * 8
            rspauth = independent_rspauth(foreign_directives, FIXED_PASSWORD)

        credentials = ('rspauth="%s"' % rspauth).encode('utf-8')
        if self.proof_mode == 'duplicated':
            credentials += b',rspauth="' + rspauth.encode('ascii') + b'"'
        return credentials

    def send_sasl_negotiation(self, connection, controls, payload):
        self.payloads.append(payload)
        step = len(self.payloads)
        if step == 1:
            if payload is not None:
                raise AssertionError('first bind payload must be empty')
            return {'result': RESULT_SASL_BIND_IN_PROGRESS, 'saslCreds': self.challenge(),
                    'description': 'saslBindInProgress', 'dn': '', 'message': '', 'referrals': None,
                    'type': 'bindResponse'}

        if step == 2:
            self.client_directives = decode_directives(payload)
            if self.proof_mode == 'missing':
                return {'result': RESULT_SASL_BIND_IN_PROGRESS, 'saslCreds': None,
                        'description': 'saslBindInProgress', 'dn': '', 'message': '', 'referrals': None,
                        'type': 'bindResponse'}
            if self.proof_mode == 'success_instead_of_inprogress':
                return {'result': RESULT_SUCCESS, 'saslCreds': self.proof_credentials(),
                        'description': 'success', 'dn': '', 'message': '', 'referrals': None,
                        'type': 'bindResponse'}
            return {'result': RESULT_SASL_BIND_IN_PROGRESS, 'saslCreds': self.proof_credentials(),
                    'description': 'saslBindInProgress', 'dn': '', 'message': '', 'referrals': None,
                    'type': 'bindResponse'}

        if step == 3:
            if payload != b'':
                raise AssertionError('final confirmation must be an empty response, got %r' % payload)
            if self.final_mode == 'in_progress_again':
                # misbehaving server keeps challenging instead of confirming: the client must not loop
                return {'result': RESULT_SASL_BIND_IN_PROGRESS, 'saslCreds': None,
                        'description': 'saslBindInProgress', 'dn': '', 'message': '', 'referrals': None,
                        'type': 'bindResponse'}
            if self.final_mode == 'failure':
                return {'result': RESULT_INVALID_CREDENTIALS, 'saslCreds': None,
                        'description': 'invalidCredentials', 'dn': '', 'message': '', 'referrals': None,
                        'type': 'bindResponse'}
            if self.final_mode == 'unexpected_creds':
                return {'result': RESULT_SUCCESS, 'saslCreds': b'rspauth="deadbeef"',
                        'description': 'success', 'dn': '', 'message': '', 'referrals': None,
                        'type': 'bindResponse'}
            return {'result': RESULT_SUCCESS, 'saslCreds': None,
                    'description': 'success', 'dn': '', 'message': '', 'referrals': None,
                    'type': 'bindResponse'}

        raise AssertionError('client sent an unexpected fourth bind payload (empty response loop): %r' % payload)

    def abort_sasl_negotiation(self, connection, controls):
        self.aborted = True
        return True


def build_connection(security=None, ssl=False):
    server = SimpleNamespace(host=FIXED_HOST, ssl=ssl)
    credentials = (FIXED_REALM, FIXED_USER, FIXED_PASSWORD, FIXED_AUTHZ_ID)
    if security is not None:
        credentials = credentials + (security,)
    connection = SimpleNamespace(
        sasl_credentials=credentials,
        server=server,
        _digest_md5_kic=None,
        _digest_md5_kis=None,
        _digest_md5_kcc_cipher=None,
        _digest_md5_kcs_cipher=None,
        _digest_md5_sec_num=0,
        _digest_md5_handshake_state=HANDSHAKE_NOT_STARTED,
    )
    return connection


def run_handshake(server, security=None, ssl=False):
    connection = build_connection(security=security, ssl=ssl)
    original_send = digest_md5_module.send_sasl_negotiation
    original_abort = digest_md5_module.abort_sasl_negotiation
    original_cnonce = digest_md5_module.random_hex_string
    digest_md5_module.send_sasl_negotiation = server.send_sasl_negotiation
    digest_md5_module.abort_sasl_negotiation = server.abort_sasl_negotiation
    digest_md5_module.random_hex_string = lambda size: FIXED_CNONCE
    try:
        result = sasl_digest_md5(connection, None)
    finally:
        digest_md5_module.send_sasl_negotiation = original_send
        digest_md5_module.abort_sasl_negotiation = original_abort
        digest_md5_module.random_hex_string = original_cnonce
    return connection, result


class TestDigestMd5MutualAuthentication(unittest.TestCase):
    def assertNoSessionResidue(self, connection):
        self.assertIsNone(connection._digest_md5_kic)
        self.assertIsNone(connection._digest_md5_kis)
        self.assertIsNone(connection._digest_md5_kcc_cipher)
        self.assertIsNone(connection._digest_md5_kcs_cipher)
        self.assertEqual(connection._digest_md5_sec_num, 0)
        self.assertEqual(connection._digest_md5_handshake_state, HANDSHAKE_NOT_STARTED)

    def test_successful_auth_exchange_installs_no_signing_context(self):
        server = ScriptedDigestMd5Server()
        connection, result = run_handshake(server)
        self.assertEqual(result['result'], RESULT_SUCCESS)
        self.assertEqual(connection._digest_md5_handshake_state, HANDSHAKE_COMPLETED)
        self.assertEqual(len(server.payloads), 3)
        self.assertIsNone(server.payloads[0])
        self.assertIn(b'qop=auth', server.payloads[1])
        self.assertEqual(server.payloads[2], b'')
        self.assertIsNone(connection._digest_md5_kic)
        self.assertIsNone(connection._digest_md5_kis)
        self.assertFalse(server.aborted)

    def test_successful_auth_int_exchange_installs_signing_context_only_at_end(self):
        server = ScriptedDigestMd5Server()
        connection, result = run_handshake(server, security=SIGN)
        self.assertEqual(result['result'], RESULT_SUCCESS)
        self.assertEqual(connection._digest_md5_handshake_state, HANDSHAKE_COMPLETED)
        self.assertIn(b'qop=auth-int', server.payloads[1])
        self.assertIsNotNone(connection._digest_md5_kic)
        self.assertIsNotNone(connection._digest_md5_kis)
        self.assertIsNone(connection._digest_md5_kcc_cipher)
        self.assertIsNone(connection._digest_md5_kcs_cipher)
        self.assertEqual(connection._digest_md5_sec_num, 0)
        self.assertEqual(server.payloads[2], b'')

    def test_successful_auth_conf_exchange_installs_sealing_context_only_at_end(self):
        server = ScriptedDigestMd5Server()
        connection, result = run_handshake(server, security=ENCRYPT)
        self.assertEqual(result['result'], RESULT_SUCCESS)
        self.assertEqual(connection._digest_md5_handshake_state, HANDSHAKE_COMPLETED)
        self.assertIn(b'qop=auth-conf', server.payloads[1])
        self.assertIn(b'cipher="rc4"', server.payloads[1])
        self.assertIsNotNone(connection._digest_md5_kic)
        self.assertIsNotNone(connection._digest_md5_kis)
        self.assertIsNotNone(connection._digest_md5_kcc_cipher)
        self.assertIsNotNone(connection._digest_md5_kcs_cipher)

    def test_rspauth_is_bound_to_authorization_identity(self):
        # server computes the proof without the requested authzid: the client must reject it
        server = ScriptedDigestMd5Server(include_authz=False)
        with self.assertRaises(LDAPCommunicationError):
            run_handshake(server)
        self.assertTrue(server.aborted)
        self.assertEqual(len(server.payloads), 2)

    def test_tampered_rspauth_is_rejected_and_cleaned_up(self):
        server = ScriptedDigestMd5Server(proof_mode='tampered')
        connection = build_connection(security=ENCRYPT)
        original_send = digest_md5_module.send_sasl_negotiation
        original_abort = digest_md5_module.abort_sasl_negotiation
        original_cnonce = digest_md5_module.random_hex_string
        digest_md5_module.send_sasl_negotiation = server.send_sasl_negotiation
        digest_md5_module.abort_sasl_negotiation = server.abort_sasl_negotiation
        digest_md5_module.random_hex_string = lambda size: FIXED_CNONCE
        try:
            with self.assertRaises(LDAPCommunicationError):
                sasl_digest_md5(connection, None)
        finally:
            digest_md5_module.send_sasl_negotiation = original_send
            digest_md5_module.abort_sasl_negotiation = original_abort
            digest_md5_module.random_hex_string = original_cnonce
        self.assertTrue(server.aborted)
        self.assertEqual(len(server.payloads), 2)
        self.assertNoSessionResidue(connection)

    def test_replayed_rspauth_from_foreign_handshake_is_rejected(self):
        server = ScriptedDigestMd5Server(proof_mode='foreign')
        with self.assertRaises(LDAPCommunicationError):
            run_handshake(server, security=SIGN)
        self.assertTrue(server.aborted)
        self.assertEqual(len(server.payloads), 2)

    def test_missing_rspauth_is_rejected(self):
        server = ScriptedDigestMd5Server(proof_mode='missing')
        with self.assertRaises(LDAPCommunicationError):
            run_handshake(server)
        self.assertTrue(server.aborted)

    def test_duplicated_rspauth_is_rejected(self):
        server = ScriptedDigestMd5Server(proof_mode='duplicated')
        with self.assertRaises(LDAPCommunicationError):
            run_handshake(server)
        self.assertTrue(server.aborted)

    def test_success_without_in_progress_is_rejected(self):
        server = ScriptedDigestMd5Server(proof_mode='success_instead_of_inprogress')
        with self.assertRaises(LDAPCommunicationError):
            run_handshake(server)
        self.assertTrue(server.aborted)

    def test_final_confirmation_repeated_in_progress_does_not_loop(self):
        server = ScriptedDigestMd5Server(final_mode='in_progress_again')
        with self.assertRaises(LDAPCommunicationError):
            run_handshake(server, security=SIGN)
        self.assertEqual(len(server.payloads), 3)
        self.assertTrue(server.aborted)

    def test_final_confirmation_failure_cleans_up(self):
        server = ScriptedDigestMd5Server(final_mode='failure')
        with self.assertRaises(LDAPCommunicationError):
            run_handshake(server, security=SIGN)
        self.assertTrue(server.aborted)

    def test_final_confirmation_with_unexpected_credentials_is_rejected(self):
        server = ScriptedDigestMd5Server(final_mode='unexpected_creds')
        with self.assertRaises(LDAPCommunicationError):
            run_handshake(server)
        self.assertTrue(server.aborted)

    def test_no_authenticated_identity_or_keys_before_proof_verification(self):
        # capture the connection state immediately after the client response is sent,
        # before the rspauth message is evaluated
        seen = {}

        class ProbeServer(ScriptedDigestMd5Server):
            def send_sasl_negotiation(self, connection, controls, payload):
                result = super().send_sasl_negotiation(connection, controls, payload)
                if len(self.payloads) == 2:
                    seen['state_after_client_response'] = connection._digest_md5_handshake_state
                    seen['kic'] = connection._digest_md5_kic
                    seen['kis'] = connection._digest_md5_kis
                    seen['kcs'] = connection._digest_md5_kcs_cipher
                return result

        server = ProbeServer()
        connection, result = run_handshake(server, security=ENCRYPT)
        self.assertEqual(result['result'], RESULT_SUCCESS)
        self.assertEqual(seen['state_after_client_response'], 'challenge-sent')
        self.assertIsNone(seen['kic'])
        self.assertIsNone(seen['kis'])
        self.assertIsNone(seen['kcs'])


if __name__ == '__main__':
    unittest.main()
