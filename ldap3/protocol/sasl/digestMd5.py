"""
"""

# Created on 2014.01.04
#
# Author: Giovanni Cannata
#
# Copyright 2014 - 2025 Giovanni Cannata
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

from binascii import hexlify
import hashlib
import hmac

from Cryptodome.Cipher import ARC4

from ... import SEQUENCE_TYPES, ENCRYPT, SIGN
from ...protocol.sasl.sasl import abort_sasl_negotiation, send_sasl_negotiation, random_hex_string
from ...core.exceptions import LDAPCommunicationError, LDAPSASLBindInProgressError
from ...core.results import RESULT_SASL_BIND_IN_PROGRESS, RESULT_SUCCESS


STATE_KEY = 0
STATE_VALUE = 1

# DIGEST-MD5 handshake states used to validate the server proof (RFC 2831)
HANDSHAKE_NOT_STARTED = 'not-started'
HANDSHAKE_CHALLENGE_SENT = 'challenge-sent'      # step one completed, client response sent
HANDSHAKE_RSPAUTH_VERIFIED = 'rspauth-verified'  # step three proof checked, final confirmation pending
HANDSHAKE_COMPLETED = 'completed'                # final confirmation received, session established


def md5_h(value):
    if not isinstance(value, bytes):
        value = value.encode()

    return hashlib.md5(value).digest()


def md5_kd(k, s):
    if not isinstance(k, bytes):
        k = k.encode()

    if not isinstance(s, bytes):
        s = s.encode()

    return md5_h(k + b':' + s)


def md5_hex(value):
    if not isinstance(value, bytes):
        value = value.encode()

    return hexlify(value)


def md5_hmac(k, s):
    if not isinstance(k, bytes):
        k = k.encode()

    if not isinstance(s, bytes):
        s = s.encode()

    return hmac.new(k, s, digestmod=hashlib.md5).hexdigest()


def _reset_digest_md5_session(connection):
    # remove any keying material left over from a previous (failed) handshake
    connection._digest_md5_kis = None
    connection._digest_md5_kic = None
    connection._digest_md5_kcc_cipher = None
    connection._digest_md5_kcs_cipher = None
    connection._digest_md5_sec_num = 0


def _count_directive(directives_string, key):
    # counts top-level occurrences of key (respecting quoted values), so duplicated
    # directives such as two rspauth entries can be detected
    occurrences = 0
    state = STATE_KEY
    tmp_buffer = ''
    quoting = False
    current_key = ''
    for c in directives_string.decode('utf-8'):
        if state == STATE_KEY and c == '=':
            current_key = tmp_buffer
            tmp_buffer = ''
            state = STATE_VALUE
        elif state == STATE_VALUE and c == '"' and not quoting and not tmp_buffer:
            quoting = True
        elif state == STATE_VALUE and c == '"' and quoting:
            quoting = False
        elif state == STATE_VALUE and c == ',' and not quoting:
            if current_key == key:
                occurrences += 1
            tmp_buffer = ''
            current_key = ''
            state = STATE_KEY
        else:
            tmp_buffer += c

    if current_key and tmp_buffer:
        if current_key == key:
            occurrences += 1

    return occurrences


def _expected_rspauth(a1, nonce, nc, cnonce, qop, uri):
    # RFC 2831 step Three: rspauth is computed like the client response but with
    # A2 = ":" digest-uri-value (plus the 32 zeros suffix for auth-int/auth-conf).
    # The authorization identity only enters A1, so it is not part of the KD join.
    rspauth_a2 = b':' + uri + (b':00000000000000000000000000000000' if qop in [b'auth-int', b'auth-conf'] else b'')
    return md5_hex(md5_kd(md5_hex(md5_h(a1)),
                          b':'.join([nonce, nc, cnonce, qop, md5_hex(md5_h(rspauth_a2))]))).decode('ascii')


def _verify_server_proof(connection, controls, result, a1, nonce, nc, cnonce, qop, uri, raw_credentials):
    # step Three of RFC2831: the server proves it knows the shared secret through rspauth
    failure_message = None
    if result is None or result.get('result') != RESULT_SASL_BIND_IN_PROGRESS:
        failure_message = 'DIGEST-MD5 server proof expected but not received'
    elif not raw_credentials:
        failure_message = 'DIGEST-MD5 server proof missing'
    elif connection._digest_md5_handshake_state != HANDSHAKE_CHALLENGE_SENT:
        # a proof is only accepted once, against the current pending handshake
        failure_message = 'DIGEST-MD5 server proof received outside of the expected handshake state'
    elif _count_directive(raw_credentials, 'rspauth') != 1:
        # missing or duplicated rspauth directives are both invalid
        failure_message = 'DIGEST-MD5 server proof missing or duplicated'
    else:
        server_directives = decode_directives(raw_credentials)
        if 'rspauth' not in server_directives:
            failure_message = 'DIGEST-MD5 server proof missing'
        else:
            expected_rspauth = _expected_rspauth(a1, nonce, nc, cnonce, qop, uri)
            if not hmac.compare_digest(expected_rspauth, server_directives['rspauth']):
                failure_message = 'DIGEST-MD5 server proof does not match the current nonce, cnonce, qop, digest-uri and authorization identity'

    if failure_message is not None:
        _reset_digest_md5_session(connection)
        connection._digest_md5_handshake_state = HANDSHAKE_NOT_STARTED
        abort_sasl_negotiation(connection, controls)
        raise LDAPCommunicationError(failure_message)


def sasl_digest_md5(connection, controls):
    # sasl_credential must be a tuple made up of the following elements: (realm, user, password, authorization_id) or (realm, user, password, authorization_id, enable_signing)
    # if realm is None will be used the realm received from the server, if available
    if not isinstance(connection.sasl_credentials, SEQUENCE_TYPES) or not len(connection.sasl_credentials) in (4, 5):
        return None

    # no keying material or authenticated identity may be left over from a previous exchange
    _reset_digest_md5_session(connection)
    connection._digest_md5_handshake_state = HANDSHAKE_NOT_STARTED

    # step One of RFC2831
    result = send_sasl_negotiation(connection, controls, None)
    if 'saslCreds' in result and result['saslCreds'] is not None:
        server_directives = decode_directives(result['saslCreds'])
    else:
        return None

    if 'realm' not in server_directives or 'nonce' not in server_directives or 'algorithm' not in server_directives:  # mandatory directives, as per RFC2831
        abort_sasl_negotiation(connection, controls)
        return None

    # step Two of RFC2831
    # TODO support more ciphers and give choice to user
    supported_ciphers = ['rc4']

    charset = server_directives['charset'] if 'charset' in server_directives and server_directives['charset'].lower() == 'utf-8' else 'iso8859-1'
    cipher=b''
    qop = b'auth'
    if len(connection.sasl_credentials) == 5 and not connection.server.ssl:
        if connection.sasl_credentials[4] == SIGN:
            qop = b'auth-int'
        elif connection.sasl_credentials[4] == ENCRYPT:
            for c in supported_ciphers:
                if c in server_directives['cipher']:
                    cipher = c.encode(charset)
                    break
            if cipher == b'':
                abort_sasl_negotiation(connection, controls)
                raise LDAPSASLBindInProgressError(f'Cipher negociation failed, Client only supports {supported_ciphers} and Server {server_directives["cipher"]}')
            qop = b'auth-conf'

    user = connection.sasl_credentials[1].encode(charset)
    realm = (connection.sasl_credentials[0] if connection.sasl_credentials[0] else (server_directives['realm'] if 'realm' in server_directives else '')).encode(charset)
    password = connection.sasl_credentials[2].encode(charset)
    authz_id = connection.sasl_credentials[3].encode(charset) if connection.sasl_credentials[3] else b''
    nonce = server_directives['nonce'].encode(charset)
    cnonce = random_hex_string(16).encode(charset)
    nc = b'00000001'
    uri = b'ldap/' + connection.server.host.encode(charset)

    digest_response = b'username="' + user + b'",'
    digest_response += b'realm="' + realm + b'",'
    digest_response += (b'authzid="' + authz_id + b'",') if authz_id else b''
    digest_response += b'nonce="' + nonce + b'",'
    digest_response += b'cnonce="' + cnonce + b'",'
    digest_response += b'digest-uri="' + uri + b'",'
    digest_response += b'qop=' + qop + b','
    if cipher != b'':
        digest_response += b'cipher="' + cipher + b'",'
    digest_response += b'nc=' + nc + b','
    if charset == 'utf-8':
        digest_response += b'charset="utf-8",'

    a0 = md5_h(b':'.join([user, realm, password]))
    a1 = b':'.join([a0, nonce, cnonce, authz_id]) if authz_id else b':'.join([a0, nonce, cnonce])
    a2 = b'AUTHENTICATE:' + uri + (b':00000000000000000000000000000000' if qop in [b'auth-int', b'auth-conf'] else b'')

    # protection keys are derived locally first: they must not be exposed on the
    # connection (and thus usable for signing/sealing) before the server is authenticated
    kis = md5_h(md5_h(a1) + b"Digest session key to server-to-client signing key magic constant") if qop != b'auth' else None
    kic = md5_h(md5_h(a1) + b"Digest session key to client-to-server signing key magic constant") if qop != b'auth' else None
    kcs_cipher = ARC4.new(md5_h(md5_h(a1) + b"Digest H(A1) to server-to-client sealing key magic constant")) if qop == b'auth-conf' else None
    kcc_cipher = ARC4.new(md5_h(md5_h(a1) + b"Digest H(A1) to client-to-server sealing key magic constant")) if qop == b'auth-conf' else None

    digest_response += b'response="' + md5_hex(md5_kd(md5_hex(md5_h(a1)), b':'.join([nonce, nc, cnonce, qop, md5_hex(md5_h(a2))]))) + b'"'

    connection._digest_md5_handshake_state = HANDSHAKE_CHALLENGE_SENT
    result = send_sasl_negotiation(connection, controls, digest_response)

    # step Three of RFC2831: validate rspauth before trusting the server or installing any session key
    _verify_server_proof(connection, controls, result, a1, nonce, nc, cnonce, qop, uri,
                         result.get('saslCreds') if result else None)

    # server authenticated: only now install the negotiated protection keys
    connection._digest_md5_kis = kis
    connection._digest_md5_kic = kic
    connection._digest_md5_kcs_cipher = kcs_cipher
    connection._digest_md5_kcc_cipher = kcc_cipher
    connection._digest_md5_sec_num = 0
    connection._digest_md5_handshake_state = HANDSHAKE_RSPAUTH_VERIFIED

    # step Four of RFC2831: final confirmation with a single explicit empty response
    result = send_sasl_negotiation(connection, controls, b'')
    if result is None or result.get('result') != RESULT_SUCCESS or result.get('saslCreds'):
        _reset_digest_md5_session(connection)
        connection._digest_md5_handshake_state = HANDSHAKE_NOT_STARTED
        abort_sasl_negotiation(connection, controls)
        raise LDAPCommunicationError('DIGEST-MD5 final confirmation failed')

    connection._digest_md5_handshake_state = HANDSHAKE_COMPLETED
    return result


def decode_directives(directives_string):
    """
    converts directives to dict, unquote values
    """

    # old_directives = dict((attr[0], attr[1].strip('"')) for attr in [line.split('=') for line in directives_string.split(',')])
    state = STATE_KEY
    tmp_buffer = ''
    quoting = False
    key = ''
    directives = dict()
    for c in directives_string.decode('utf-8'):
        if state == STATE_KEY and c == '=':
            key = tmp_buffer
            tmp_buffer = ''
            state = STATE_VALUE
        elif state == STATE_VALUE and c == '"' and not quoting and not tmp_buffer:
            quoting = True
        elif state == STATE_VALUE and c == '"' and quoting:
            quoting = False
        elif state == STATE_VALUE and c == ',' and not quoting:
            directives[key] = tmp_buffer
            tmp_buffer = ''
            key = ''
            state = STATE_KEY
        else:
            tmp_buffer += c

    if key and tmp_buffer:
        directives[key] = tmp_buffer

    return directives
