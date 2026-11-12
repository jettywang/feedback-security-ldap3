"""
In-memory multi-step SASL (DIGEST-MD5) failure state tests.

These tests drive the real DIGEST-MD5 negotiation code in
ldap3.protocol.sasl.digestMd5 against a scripted LDAP server that lives
entirely in memory (a fake socket, no network, no real DSA). Failures are
injected at every step of the exchange:

  1. first challenge parsing (mandatory directives missing / empty creds)
  2. client response generation (cipher negotiation failure, transport drop)
  3. server final confirmation (invalid credentials)
  4. the abort exchange itself

For every failure the tests verify, on both the synchronous and the
asynchronous strategy:

  * the API state (bound/closed/sasl_in_progress/result/last_error)
  * the actual abort message emitted on the wire (empty SASL mechanism,
    no credentials, distinct bind message id)
  * that a later ordinary request is sent as a plain, unsigned BER message
    and can never borrow keys derived during the failed negotiation
  * that re-authentication starts from a clean, unauthenticated state and
    succeeds once the server cooperates

A happy-path exchange is included as a control: it proves the same signing
context really is installed on success, so "context is None after failure"
is a meaningful assertion rather than an always-true one.
"""

import unittest
from threading import Condition

from ldap3 import Server, Connection, SASL, DIGEST_MD5, SIGN, ENCRYPT, SYNC, ASYNC, SUBTREE, get_config_parameter, set_config_parameter
from ldap3.utils.asn1 import encode, decoder
from ldap3.protocol.rfc4511 import LDAPMessage, ProtocolOp, SearchResultDone
from ldap3.operation.bind import bind_response_operation
from ldap3.protocol.sasl.digestMd5 import md5_hmac
from ldap3.core.results import (RESULT_SUCCESS,
                                RESULT_SASL_BIND_IN_PROGRESS,
                                RESULT_INVALID_CREDENTIALS,
                                RESULT_AUTH_METHOD_NOT_SUPPORTED,
                                RESULT_UNWILLING_TO_PERFORM)
from ldap3.core.exceptions import (LDAPSASLBindInProgressError,
                                   LDAPSessionTerminatedByServerError,
                                   LDAPSocketReceiveError,
                                   LDAPResponseTimeoutError)

# RFC 2831 DIGEST-MD5 challenges, served from memory.
CHALLENGE_AUTH = (b'realm="testrealm",nonce="OAQ9MgAA5T2Pwq==",'
                  b'qop="auth",algorithm=md5-sess,charset=utf-8')
CHALLENGE_SIGN = (b'realm="testrealm",nonce="OAQ9MgAA5T2Pwq==",'
                  b'qop="auth-int",algorithm=md5-sess,charset=utf-8')
CHALLENGE_ENCRYPT = (b'realm="testrealm",nonce="OAQ9MgAA5T2Pwq==",'
                     b'qop="auth-conf",cipher="rc4",algorithm=md5-sess,charset=utf-8')
CHALLENGE_UNSUPPORTED_CIPHER = (b'realm="testrealm",nonce="OAQ9MgAA5T2Pwq==",'
                                b'qop="auth-conf",cipher="3des",algorithm=md5-sess,charset=utf-8')
# Missing the mandatory realm/nonce/algorithm directives of RFC 2831.
CHALLENGE_MALFORMED = b'qop="auth",charset=utf-8'

SASL_CONTEXT_ATTRS = ('_digest_md5_kic', '_digest_md5_kis',
                      '_digest_md5_kcc_cipher', '_digest_md5_kcs_cipher')


def _bind_response(message_id, result_code, sasl_creds=None, message=''):
    ldap_message = LDAPMessage()
    ldap_message['messageID'] = message_id
    ldap_message['protocolOp'] = ProtocolOp().setComponentByName(
        'bindResponse',
        bind_response_operation(result_code,
                                diagnostic_message=message,
                                server_sasl_credentials=sasl_creds))
    return encode(ldap_message)


def _search_done(message_id, result_code=RESULT_SUCCESS, message=''):
    done = SearchResultDone()
    done.setComponentByName('resultCode', result_code)
    done.setComponentByName('matchedDN', '')
    done.setComponentByName('diagnosticMessage', message)
    ldap_message = LDAPMessage()
    ldap_message['messageID'] = message_id
    ldap_message['protocolOp'] = ProtocolOp().setComponentByName('searchResDone', done)
    return encode(ldap_message)


def _is_plain_ldap_message(raw):
    # A signed/sealed message is a 4-byte SASL buffer length wrapping BER; a
    # plain LDAP message decodes directly as an LDAPMessage.
    try:
        decoder.decode(raw, asn1Spec=LDAPMessage())
        return True
    except Exception:
        return False


def _sasl_sign(encoded_message, connection, sec_num):
    # Mirrors BaseStrategy.sending / SyncStrategy.receiving: the server side of
    # the DIGEST-MD5 auth-int layer signs with the server-to-client key (kis).
    signature = bytes.fromhex(md5_hmac(connection._digest_md5_kis,
                                       int(sec_num).to_bytes(4, 'big') + encoded_message)[0:20])
    payload = encoded_message + signature
    return int(len(payload) + 2 + 4).to_bytes(4, 'big') + payload + int(1).to_bytes(2, 'big') + int(sec_num).to_bytes(4, 'big')


class InMemoryServer(object):
    """Scripted LDAP server: every client message is fed to the next handler.

    Handlers receive the decoded request and return the raw BER bytes to put
    on the wire, or None to stay silent (used to simulate a dropped server).
    """

    def __init__(self, handlers):
        self._handlers = list(handlers)
        self._next = 0
        self.transcript = []  # (message_id, op_name, sasl_detail, raw_bytes)
        self.closed = False

    def handle(self, raw):
        try:
            decoded, _ = decoder.decode(raw, asn1Spec=LDAPMessage())
        except Exception:
            # Signed/sealed messages are a SASL buffer, not plain BER LDAP.
            # RFC 2831 layout: 4-byte length + BER message + 10-byte signature
            # + 2-byte layer id + 4-byte secNum. Peel the envelope so the real
            # message id can be recovered and the scripted answer is usable.
            buffer_length = int.from_bytes(raw[0:4], 'big')
            inner = raw[4:4 + buffer_length - 6]
            decoded, _ = decoder.decode(inner, asn1Spec=LDAPMessage())
            message_id = int(decoded['messageID'])
            self.transcript.append((message_id, 'saslWrappedMessage', None, raw))
            if self._next >= len(self._handlers):
                return None
            handler = self._handlers[self._next]
            self._next += 1
            return handler(decoded, message_id, 'saslWrappedMessage', None)
        message_id = int(decoded['messageID'])
        op = decoded['protocolOp']
        op_name = op.getName()
        component = op.getComponent()
        detail = None
        if op_name == 'bindRequest':
            auth = component['authentication']
            if auth.getName() == 'sasl':
                sasl = auth.getComponent()
                creds = bytes(sasl['credentials']) if sasl['credentials'].hasValue() else None
                detail = (str(sasl['mechanism']), creds)
        self.transcript.append((message_id, op_name, detail, raw))
        if self._next >= len(self._handlers):
            return None
        handler = self._handlers[self._next]
        self._next += 1
        return handler(decoded, message_id, op_name, component)


class FakeSocket(object):
    """Socket substitute backed by an InMemoryServer; works for both strategies."""

    def __init__(self, server):
        self._server = server
        self._buffer = b''
        self.closed = False
        self._condition = Condition()

    def sendall(self, data):
        response = self._server.handle(data)
        if response is not None:
            with self._condition:
                self._buffer += response
                self._condition.notify_all()

    def recv(self, size):
        with self._condition:
            while not self._buffer and not self.closed:
                self._condition.wait(timeout=0.5)
            if not self._buffer:
                return b''
            chunk = self._buffer[:size]
            self._buffer = self._buffer[size:]
            return chunk

    def close(self):
        with self._condition:
            self.closed = True
            self._server.closed = True
            self._condition.notify_all()

    def shutdown(self, *args):
        pass

    def settimeout(self, timeout):
        pass

    def setsockopt(self, *args):
        pass


def challenge(creds, result=RESULT_SASL_BIND_IN_PROGRESS):
    return lambda decoded, mid, name, component: _bind_response(mid, result, sasl_creds=creds)


def final_bind(result=RESULT_SUCCESS, creds=None, message=''):
    return lambda decoded, mid, name, component: _bind_response(mid, result, creds, message)


def abort_ack(result=RESULT_AUTH_METHOD_NOT_SUPPORTED):
    return lambda decoded, mid, name, component: _bind_response(mid, result)


def search_answer(result=RESULT_SUCCESS):
    return lambda decoded, mid, name, component: _search_done(mid, result)


def signed_search_answer():
    # Answers an auth-int search: the response is BER-encoded and then signed
    # with the negotiated server-to-client key, exactly as a real server would.
    def handler(decoded, mid, name, component):
        connection = handler.harness.connection
        sec_num = connection._digest_md5_sec_num - 1  # client already incremented on send
        return _sasl_sign(_search_done(mid, RESULT_SUCCESS), connection, sec_num)
    handler.harness = None
    handler.needs_harness = True
    return handler


def server_disconnects():
    # Simulates the server dropping the connection mid-negotiation: closing
    # the fake socket makes the next recv() return b'' (TCP FIN semantics).
    # The harness injects itself before open() so the handler reaches the socket.
    def handler(decoded, mid, name, component):
        handler.harness.socket.close()
        return None
    handler.harness = None
    handler.closes_socket = True
    return handler


class DigestMd5Harness(object):
    """Builds a Connection wired to an in-memory scripted server."""

    def __init__(self, strategy, handlers, qop=None, raise_exceptions=False):
        server = Server('ldap.harness.local', get_info=None)
        credentials = (None, 'harness-user', 'harness-password', None)
        if qop is not None:
            credentials = (None, 'harness-user', 'harness-password', None, qop)
        self.connection = Connection(
            server,
            authentication=SASL,
            sasl_mechanism=DIGEST_MD5,
            sasl_credentials=credentials,
            client_strategy=strategy,
            raise_exceptions=raise_exceptions,
            receive_timeout=2,
            auto_bind=False)
        self.server = InMemoryServer(handlers)
        # no_real_dsa keeps BaseStrategy.open from doing real DNS/socket work;
        # the fake socket is installed before open() so _start_listen() uses it.
        self.connection.strategy.no_real_dsa = True
        self.socket = FakeSocket(self.server)
        for handler in handlers:
            if getattr(handler, 'closes_socket', False) or getattr(handler, 'needs_harness', False):
                handler.harness = self
        self.connection.socket = self.socket
        self.connection.closed = False
        self.connection.open(read_server_info=False)

    def close(self):
        try:
            self.connection.unbind()
        except Exception:
            pass
        receiver = getattr(self.connection.strategy, 'receiver', None)
        if receiver is not None:
            receiver.join(timeout=2)

    # -- assertions shared by every failure scenario -----------------------

    def assert_no_security_context(self, test_case):
        for attr in SASL_CONTEXT_ATTRS:
            test_case.assertIsNone(getattr(self.connection, attr),
                                   '%s must be cleared after a failed negotiation' % attr)
        test_case.assertEqual(self.connection._digest_md5_sec_num, 0)
        test_case.assertFalse(self.connection.sasl_in_progress)

    def assert_unauthenticated(self, test_case):
        test_case.assertFalse(self.connection.bound)
        self.assert_no_security_context(test_case)

    def assert_abort_emitted(self, test_case):
        abort_messages = [entry for entry in self.server.transcript
                          if entry[1] == 'bindRequest' and entry[2] is not None and entry[2][0] == '']
        test_case.assertEqual(1, len(abort_messages),
                              'exactly one SASL abort bind request must be sent')
        message_id, op_name, detail, raw = abort_messages[0]
        test_case.assertEqual('', detail[0], 'abort uses an empty SASL mechanism')
        test_case.assertIsNone(detail[1], 'abort must carry no credentials')
        test_case.assertTrue(_is_plain_ldap_message(raw), 'abort must not be SASL wrapped')
        # The abort must be a new bind request, not the initial negotiation one.
        first_bind_id = self.server.transcript[0][0]
        test_case.assertNotEqual(first_bind_id, message_id)
        return abort_messages[0]

    def assert_ordinary_request_is_unsigned(self, test_case):
        returned = self.connection.search('ou=test', '(cn=anyone)', SUBTREE)
        if self.connection.strategy.sync:
            # sync strategy returns the boolean outcome directly
            test_case.assertFalse(returned)
        else:
            # async strategy returns a message id; resolve it before asserting
            _, result = self.connection.get_response(returned)
            test_case.assertEqual(RESULT_SUCCESS, result['result'])
            test_case.assertFalse(self.connection.bound,
                                  'a failed SASL negotiation must not leave the connection bound')
        search_messages = [entry for entry in self.server.transcript
                           if entry[1] == 'searchRequest']
        test_case.assertEqual(1, len(search_messages))
        message_id, op_name, detail, raw = search_messages[0]
        test_case.assertTrue(_is_plain_ldap_message(raw),
                             'post-failure request must be plain BER, not signed/sealed with stale keys')
        # A signed message carries a leading 4-byte SASL buffer length and is
        # longer than the bare BER search request.
        test_case.assertLessEqual(len(raw), 200)

    def assert_connection_closed_after_transport_failure(self, test_case):
        # The server dropped the TCP connection: no further request can be
        # emitted, and no half-derived key material may survive the failure.
        self.assert_no_security_context(test_case)
        test_case.assertTrue(self.socket.closed)
        with test_case.assertRaises(Exception):
            self.connection.search('ou=test', '(cn=anyone)', SUBTREE)

    def bind(self):
        # SASL binds always resolve synchronously inside ldap3, but the async
        # strategy still hands back a message id while sync returns a bool.
        # Normalize on the authoritative bound flag.
        self.connection.bind(read_server_info=False)
        return self.connection.bound

    def assert_rebind_succeeds(self, test_case, extra_handlers):
        # Handlers are appended only now: earlier scripted answers must not be
        # consumed by the requests issued during the failed first negotiation.
        self.server._handlers.extend(extra_handlers)
        self.connection.bind(read_server_info=False)
        test_case.assertTrue(self.connection.bound)
        test_case.assertFalse(self.connection.sasl_in_progress)


class TestDigestMd5FailureState(unittest.TestCase):

    # -- 1. first challenge parsing failures -------------------------------

    def _test_malformed_first_challenge(self, strategy):
        harness = DigestMd5Harness(strategy,
                                   [challenge(CHALLENGE_MALFORMED), abort_ack(),
                                    search_answer()])
        try:
            ok = harness.bind()
            self.assertFalse(ok)
            harness.assert_unauthenticated(self)
            harness.assert_abort_emitted(self)
            self.assertEqual('authMethodNotSupported', harness.connection.last_error)
            harness.assert_ordinary_request_is_unsigned(self)
            # re-authentication against a cooperative server must work; this
            # harness uses plain auth qop, so no signing layer is expected
            harness.assert_rebind_succeeds(self,
                                           [challenge(CHALLENGE_AUTH), final_bind()])
        finally:
            harness.close()

    def test_malformed_first_challenge_sync(self):
        self._test_malformed_first_challenge(SYNC)

    def test_malformed_first_challenge_async(self):
        self._test_malformed_first_challenge(ASYNC)

    def _test_empty_first_challenge_credentials(self, strategy):
        harness = DigestMd5Harness(strategy,
                                   [challenge(None), search_answer()])
        try:
            # The server answers the initial empty bind without saslCreds:
            # the negotiation cannot start, no abort is possible and the
            # connection must stay unauthenticated with a clean context.
            ok = harness.bind()
            self.assertFalse(ok)
            harness.assert_unauthenticated(self)
            self.assertFalse(any(entry[2] is not None and entry[2][0] == ''
                                 for entry in harness.server.transcript))
            harness.assert_ordinary_request_is_unsigned(self)
        finally:
            harness.close()

    def test_empty_first_challenge_credentials_sync(self):
        self._test_empty_first_challenge_credentials(SYNC)

    def test_empty_first_challenge_credentials_async(self):
        self._test_empty_first_challenge_credentials(ASYNC)

    def _test_abort_not_acknowledged_properly(self, strategy):
        harness = DigestMd5Harness(strategy,
                                   [challenge(CHALLENGE_MALFORMED),
                                    abort_ack(RESULT_UNWILLING_TO_PERFORM),
                                    search_answer()])
        try:
            ok = harness.bind()
            self.assertFalse(ok)
            harness.assert_unauthenticated(self)
            harness.assert_abort_emitted(self)
            self.assertEqual('unwillingToPerform', harness.connection.last_error)
            harness.assert_ordinary_request_is_unsigned(self)
        finally:
            harness.close()

    def test_abort_not_acknowledged_properly_sync(self):
        self._test_abort_not_acknowledged_properly(SYNC)

    def test_abort_not_acknowledged_properly_async(self):
        self._test_abort_not_acknowledged_properly(ASYNC)

    # -- 2. client response generation failures ----------------------------

    def _test_cipher_negotiation_failure(self, strategy):
        harness = DigestMd5Harness(strategy,
                                   [challenge(CHALLENGE_UNSUPPORTED_CIPHER), abort_ack(),
                                    search_answer()],
                                   qop=ENCRYPT)
        try:
            with self.assertRaises(LDAPSASLBindInProgressError):
                harness.bind()
            harness.assert_unauthenticated(self)
            harness.assert_abort_emitted(self)
            harness.assert_ordinary_request_is_unsigned(self)
            # The failed ENCRYPT negotiation must not leave RC4 ciphers behind.
            self.assertIsNone(harness.connection._digest_md5_kcc_cipher)
            self.assertIsNone(harness.connection._digest_md5_kcs_cipher)
            harness.assert_rebind_succeeds(self,
                                           [challenge(CHALLENGE_ENCRYPT), final_bind()])
            self.assertIsNotNone(harness.connection._digest_md5_kcc_cipher)
        finally:
            harness.close()

    def test_cipher_negotiation_failure_sync(self):
        # Confidentiality (auth-conf/RC4) is only supported by the synchronous
        # strategy, see AsyncStrategy receiver: an async bind with ENCRYPT
        # raises LDAPConfigurationError before any cipher is negotiated.
        self._test_cipher_negotiation_failure(SYNC)

    def test_encrypt_qop_rejected_on_async_strategy(self):
        # On the async strategy the unsupported cipher aborts during the bind
        # itself; no half-built sealing context may survive the exception.
        harness = DigestMd5Harness(ASYNC,
                                   [challenge(CHALLENGE_UNSUPPORTED_CIPHER), abort_ack(),
                                    search_answer()],
                                   qop=ENCRYPT)
        try:
            with self.assertRaises(LDAPSASLBindInProgressError):
                harness.bind()
            harness.assert_unauthenticated(self)
            harness.assert_abort_emitted(self)
            self.assertIsNone(harness.connection._digest_md5_kcc_cipher)
            self.assertIsNone(harness.connection._digest_md5_kcs_cipher)
        finally:
            harness.close()

    def _test_transport_drop_during_response_step(self, strategy):
        # Server delivers a valid challenge then drops the connection while the
        # client's signed response proof is in flight.
        harness = DigestMd5Harness(strategy,
                                   [challenge(CHALLENGE_SIGN),
                                    server_disconnects()],
                                   qop=SIGN)
        try:
            with self.assertRaises((LDAPSessionTerminatedByServerError,
                                    LDAPSocketReceiveError,
                                    LDAPResponseTimeoutError)):
                harness.bind()
            harness.assert_unauthenticated(self)
            bind_messages = [entry for entry in harness.server.transcript
                             if entry[1] == 'bindRequest']
            # initial request plus the response-proof request were really sent
            self.assertEqual(2, len(bind_messages))
            # the proof message carries the digest response directives
            self.assertIn(b'response=', bind_messages[1][2][1])
            harness.assert_connection_closed_after_transport_failure(self)
        finally:
            # the socket is already gone; avoid a second unbind on the dead socket
            receiver = getattr(harness.connection.strategy, 'receiver', None)
            if receiver is not None:
                receiver.join(timeout=2)

    def test_transport_drop_during_response_step_sync(self):
        self._test_transport_drop_during_response_step(SYNC)

    def test_transport_drop_during_response_step_async(self):
        # On the async strategy the receiver notices the closed socket but
        # cannot tear the session down while the bind holds the connection
        # lock, so the waiting get_response() hits the response timeout and
        # raises LDAPResponseTimeoutError. Shrink that timeout for the test.
        from ldap3 import set_config_parameter
        previous = get_config_parameter('RESPONSE_WAITING_TIMEOUT')
        set_config_parameter('RESPONSE_WAITING_TIMEOUT', 2)
        try:
            self._test_transport_drop_during_response_step(ASYNC)
        finally:
            set_config_parameter('RESPONSE_WAITING_TIMEOUT', previous)

    # -- 3. server final confirmation failures -----------------------------

    def _test_final_confirmation_rejected_sign(self, strategy):
        harness = DigestMd5Harness(
            strategy,
            [challenge(CHALLENGE_SIGN),
             final_bind(RESULT_INVALID_CREDENTIALS, message='invalid credentials'),
             search_answer()],
            qop=SIGN)
        try:
            ok = harness.bind()
            self.assertFalse(ok)
            self.assertEqual('invalidCredentials', harness.connection.last_error)
            harness.assert_unauthenticated(self)
            harness.assert_ordinary_request_is_unsigned(self)
            # re-authentication succeeds and signing keys are freshly derived
            harness.assert_rebind_succeeds(self,
                                           [challenge(CHALLENGE_SIGN), final_bind()])
            self.assertIsNotNone(harness.connection._digest_md5_kic)
            self.assertIsNotNone(harness.connection._digest_md5_kis)
        finally:
            harness.close()

    def test_final_confirmation_rejected_sign_sync(self):
        self._test_final_confirmation_rejected_sign(SYNC)

    def test_final_confirmation_rejected_sign_async(self):
        self._test_final_confirmation_rejected_sign(ASYNC)

    def _test_final_confirmation_rejected_encrypt(self, strategy):
        harness = DigestMd5Harness(
            strategy,
            [challenge(CHALLENGE_ENCRYPT),
             final_bind(RESULT_INVALID_CREDENTIALS, message='invalid credentials'),
             search_answer()],
            qop=ENCRYPT)
        try:
            ok = harness.bind()
            self.assertFalse(ok)
            harness.assert_unauthenticated(self)
            # every sealing artifact must be gone
            for attr in SASL_CONTEXT_ATTRS:
                self.assertIsNone(getattr(harness.connection, attr))
            harness.assert_ordinary_request_is_unsigned(self)
        finally:
            harness.close()

    def test_final_confirmation_rejected_encrypt_sync(self):
        # auth-conf sealing is a synchronous-only feature, see AsyncStrategy
        self._test_final_confirmation_rejected_encrypt(SYNC)

    # -- 4. control: the happy path really installs the context ------------

    def _test_successful_signing_negotiation(self, strategy):
        harness = DigestMd5Harness(strategy,
                                   [challenge(CHALLENGE_SIGN), final_bind(),
                                    signed_search_answer()],
                                   qop=SIGN)
        try:
            ok = harness.bind()
            self.assertTrue(ok)
            self.assertTrue(harness.connection.bound)
            self.assertIsNotNone(harness.connection._digest_md5_kic)
            self.assertIsNotNone(harness.connection._digest_md5_kis)
            self.assertFalse(harness.connection.sasl_in_progress)
            # a post-bind request must now be signed (not plain BER); the
            # scripted server returns zero entries, so success is read from
            # the result code rather than the boolean search outcome
            returned = harness.connection.search('ou=test', '(cn=x)', SUBTREE)
            if harness.connection.strategy.sync:
                result_code = harness.connection.result['result']
            else:
                _, result = harness.connection.get_response(returned)
                result_code = result['result']
            self.assertEqual(RESULT_SUCCESS, result_code)
            search_messages = [entry for entry in harness.server.transcript
                               if entry[1] in ('searchRequest', 'saslWrappedMessage')]
            self.assertEqual(1, len(search_messages))
            self.assertEqual('saslWrappedMessage', search_messages[0][1])
            self.assertFalse(_is_plain_ldap_message(search_messages[0][3]),
                             'happy-path request must be SASL signed')
        finally:
            harness.close()

    def test_successful_signing_negotiation_sync(self):
        self._test_successful_signing_negotiation(SYNC)

    def test_successful_signing_negotiation_async(self):
        self._test_successful_signing_negotiation(ASYNC)

    # -- 5. early-abort failures must also purge a pre-existing context -----

    def test_malformed_challenge_clears_previous_signing_context(self):
        # A previous successful auth-int bind leaves real signing keys on the
        # connection. A later bind whose first challenge is malformed takes the
        # early abort path: those keys must be purged, not silently retained.
        harness = DigestMd5Harness(SYNC,
                                   [challenge(CHALLENGE_SIGN), final_bind()],
                                   qop=SIGN)
        try:
            self.assertTrue(harness.bind())
            previous_kic = harness.connection._digest_md5_kic
            self.assertIsNotNone(previous_kic)
            self.assertIsNotNone(harness.connection._digest_md5_kis)

            harness.server._handlers.extend(
                [challenge(CHALLENGE_MALFORMED), abort_ack(), search_answer()])
            self.assertFalse(harness.bind())
            harness.assert_abort_emitted(self)
            harness.assert_unauthenticated(self)
            # the stale signing material from the first, successful bind is gone
            self.assertIsNone(harness.connection._digest_md5_kic)
            self.assertIsNone(harness.connection._digest_md5_kis)
            harness.assert_ordinary_request_is_unsigned(self)
        finally:
            harness.close()

    def test_cipher_failure_clears_previous_encrypt_context(self):
        # A previous successful auth-conf bind leaves RC4 sealing ciphers on the
        # connection. A later bind whose offered cipher is unsupported aborts:
        # the old ciphers and signing keys must be purged.
        harness = DigestMd5Harness(SYNC,
                                   [challenge(CHALLENGE_ENCRYPT), final_bind()],
                                   qop=ENCRYPT)
        try:
            self.assertTrue(harness.bind())
            self.assertIsNotNone(harness.connection._digest_md5_kcc_cipher)
            self.assertIsNotNone(harness.connection._digest_md5_kcs_cipher)

            harness.server._handlers.extend(
                [challenge(CHALLENGE_UNSUPPORTED_CIPHER), abort_ack()])
            with self.assertRaises(LDAPSASLBindInProgressError):
                harness.bind()
            harness.assert_abort_emitted(self)
            # The rebind aborts with an exception, so the prior bound flag is
            # not rewritten; the security property under test is that no
            # half-derived sealing material (and no stale keys) survive.
            harness.assert_no_security_context(self)
            self.assertIsNone(harness.connection._digest_md5_kcc_cipher)
            self.assertIsNone(harness.connection._digest_md5_kcs_cipher)
            self.assertIsNone(harness.connection._digest_md5_kic)
            self.assertIsNone(harness.connection._digest_md5_kis)
        finally:
            harness.close()


if __name__ == '__main__':
    unittest.main()
