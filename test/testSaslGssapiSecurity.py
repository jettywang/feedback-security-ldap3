"""
Tests for the GSSAPI (Kerberos v5 SASL mechanism) security layer boundary.

No real Kerberos environment is needed: minimal fake ``gssapi`` (POSIX) and
``winkerberos`` (Windows) packages exercise the real negotiation handling in
:mod:`ldap3.protocol.sasl.kerberos` and the real message framing code in the
strategy layer.
"""

import base64
import struct
import sys
import types
import unittest
from unittest import mock

from ldap3 import GSSAPI, ENCRYPT
from ldap3.core.exceptions import LDAPCommunicationError
from ldap3.protocol.sasl import kerberos
from ldap3.strategy.base import BaseStrategy


WRAP_OVERHEAD = 16
UNWRAPPED_END_TOKEN_MARKER = b'END-'


class FakeWrapResult(object):
    def __init__(self, message):
        self.message = message


class FakeUnwrapResult(object):
    def __init__(self, message):
        self.message = message


class FakeGSSError(Exception):
    pass


class FakeMissingContextError(Exception):
    pass


class FakeSecurityContext(object):
    """Minimal stand-in for gssapi.SecurityContext.

    Two ``step`` rounds complete the handshake; tokens produced by
    :func:`FakeSecurityContext.wrap` add a fixed 16 byte overhead so chunking
    and frame limit enforcement can be asserted deterministically.
    """

    def __init__(self, *args, **kwargs):
        self._steps = 0
        self.complete = False

    def step(self, in_token):
        self._steps += 1
        if self._steps >= 2:
            self.complete = True
            return b'server-final-token'
        return b'client-initial-token'

    def wrap(self, message, confidential):
        if not self.complete:
            raise FakeGSSError('context not complete')
        token = b'W' + struct.pack('!I', len(message)) + message + b'P' * (WRAP_OVERHEAD - 5)
        return FakeWrapResult(token)

    def unwrap(self, token):
        if token.startswith(UNWRAPPED_END_TOKEN_MARKER):
            # the server end token travels inside a GSSAPI token
            return FakeUnwrapResult(token[len(UNWRAPPED_END_TOKEN_MARKER):])
        length = struct.unpack('!I', token[1:5])[0]
        return FakeUnwrapResult(token[5:5 + length])

    def get_wrap_size_limit(self, desired_size):
        return max(0, desired_size - WRAP_OVERHEAD)


def build_fake_gssapi_module():
    module = types.ModuleType('gssapi')

    class FakeName(object):
        def __init__(self, value, name_type=None):
            self.value = value

    class FakeNameType(object):
        hostbased_service = 'hostbased'

    class FakeMechType(object):
        kerberos = 'kerberos'

    class FakeCredentials(object):
        def __init__(self, *args, **kwargs):
            pass

    module.Name = FakeName
    module.NameType = FakeNameType
    module.MechType = FakeMechType
    module.Credentials = FakeCredentials
    module.SecurityContext = FakeSecurityContext
    exceptions = types.ModuleType('gssapi.exceptions')
    exceptions.GSSError = FakeGSSError
    exceptions.MissingContextError = FakeMissingContextError
    module.exceptions = exceptions
    raw = types.ModuleType('gssapi.raw')

    class ChannelBindings(object):
        def __init__(self, application_data=None):
            self.application_data = application_data

    raw.ChannelBindings = ChannelBindings
    module.raw = raw
    module.__path__ = []
    sys.modules['gssapi.raw'] = raw
    return module


def build_fake_winkerberos_module():
    module = types.ModuleType('winkerberos')
    module.GSS_C_MUTUAL_FLAG = 1
    module.GSS_C_SEQUENCE_FLAG = 2
    module.GSS_C_INTEG_FLAG = 4
    module.GSS_C_CONF_FLAG = 8
    module.AUTH_GSS_COMPLETE = 1

    class FakeWinGSSError(Exception):
        pass

    class FakeWinContext(object):
        def __init__(self):
            self._steps = 0
            self._wrapped = None
            self._unwrapped = None
            self._last_response = None

    module.GSSError = FakeWinGSSError

    def authGSSClientInit(target_name, gssflags=0):
        return 1, FakeWinContext()

    def authGSSClientStep(ctx, token_b64, channel_bindings=None):
        ctx._steps += 1
        ctx._last_response = base64.b64encode(b'win-step-token').decode('utf-8')
        return module.AUTH_GSS_COMPLETE if ctx._steps >= 2 else 0

    def authGSSClientResponse(ctx):
        return ctx._last_response

    def authGSSClientUnwrap(ctx, token_b64):
        ctx._unwrapped = base64.b64decode(token_b64)
        if ctx._unwrapped.startswith(UNWRAPPED_END_TOKEN_MARKER):
            ctx._unwrapped = ctx._unwrapped[len(UNWRAPPED_END_TOKEN_MARKER):]
        ctx._last_response = base64.b64encode(ctx._unwrapped).decode('utf-8')

    def authGSSClientWrap(ctx, message_b64, user=None, conf=0):
        raw = base64.b64decode(message_b64)
        ctx._wrapped = b'W' + struct.pack('!I', len(raw)) + raw + b'P' * (WRAP_OVERHEAD - 5)
        ctx._last_response = base64.b64encode(ctx._wrapped).decode('utf-8')

    module.authGSSClientInit = authGSSClientInit
    module.authGSSClientStep = authGSSClientStep
    module.authGSSClientResponse = authGSSClientResponse
    module.authGSSClientUnwrap = authGSSClientUnwrap
    module.authGSSClientWrap = authGSSClientWrap

    class FakeChannelBindings(object):
        def __init__(self, application_data=None):
            self.application_data = application_data

    module.channelBindings = FakeChannelBindings
    return module


class FakeServer(object):
    def __init__(self, host='ldap.example.com'):
        self.host = host


class FakeSocket(object):
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)

    def getpeername(self):
        return ('10.0.0.1', 389)


class FakeConnection(object):
    def __init__(self, session_security=ENCRYPT, server_max_output=65536):
        self.server = FakeServer()
        self.socket = FakeSocket()
        self.sasl_mechanism = GSSAPI
        self.session_security = session_security
        self.sasl_credentials = None
        self.user = None
        self.cred_store = None
        self.controls = None
        self.krb_ctx = None
        self.krb_wrap_size_limit = None
        self.server_max_output = server_max_output
        self.negotiation_attempts = 0
        self.aborted = False
        # the last response token sent during negotiation drives the next step
        self._pending_result = None

    def _next_sasl_result(self, out_token):
        self.negotiation_attempts += 1
        if self.negotiation_attempts == 1:
            # first server challenge: another GSSAPI step is needed
            return {'saslCreds': b'server-challenge-token'}
        # second response: GSSAPI token wrapping the RFC 4752 end token
        layers = (kerberos.CONFIDENTIALITY_PROTECTION |
                  kerberos.INTEGRITY_PROTECTION |
                  kerberos.NO_SECURITY_LAYER)
        end_token = bytes([layers]) + struct.pack('!I', self.server_max_output)[1:]
        return {'saslCreds': UNWRAPPED_END_TOKEN_MARKER + end_token}

    def post_send_single_response(self, message_id):
        return message_id


def patched_sasl_negotiation(connection, controls, payload):
    return connection._next_sasl_result(payload)


def patched_abort(connection, controls):
    connection.aborted = True
    return True


class GssapiModulePatcher(object):
    """Install a fake gssapi/winkerberos module and reload the kerberos code."""

    def __init__(self, posix=True):
        self.posix = posix
        self._saved = {}

    def __enter__(self):
        if self.posix:
            fake = build_fake_gssapi_module()
            self._saved['gssapi'] = sys.modules.get('gssapi')
            self._saved['gssapi.raw'] = sys.modules.get('gssapi.raw')
            sys.modules['gssapi'] = fake
            sys.modules['gssapi.raw'] = fake.raw
        else:
            fake = build_fake_winkerberos_module()
            self._saved['winkerberos'] = sys.modules.get('winkerberos')
            sys.modules['winkerberos'] = fake
        import importlib
        self._kerberos = importlib.reload(kerberos)
        return self._kerberos

    def __exit__(self, exc_type, exc, tb):
        for name, previous in self._saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
        import importlib
        importlib.reload(kerberos)


class TestEndTokenValidation(unittest.TestCase):
    def test_reject_malformed_token_length(self):
        with GssapiModulePatcher() as krb:
            self.assertRaises(LDAPCommunicationError,
                              krb._common_process_end_token_get_security_layers, b'\x01\x00\x00', ENCRYPT)

    def test_reject_non_bytes_token(self):
        with GssapiModulePatcher() as krb:
            self.assertRaises(LDAPCommunicationError,
                              krb._common_process_end_token_get_security_layers, None, ENCRYPT)

    def test_reject_server_without_any_protection_layer(self):
        with GssapiModulePatcher() as krb:
            token = bytes([krb.NO_SECURITY_LAYER]) + b'\x00\x00\x00'
            self.assertRaises(LDAPCommunicationError,
                              krb._common_process_end_token_get_security_layers, token, ENCRYPT)

    def test_reject_integrity_only_server_when_confidentiality_required(self):
        with GssapiModulePatcher() as krb:
            token = bytes([krb.INTEGRITY_PROTECTION]) + struct.pack('!I', 4096)[1:]
            self.assertRaises(LDAPCommunicationError,
                              krb._common_process_end_token_get_security_layers, token, ENCRYPT)

    def test_reject_zero_mask_server(self):
        with GssapiModulePatcher() as krb:
            token = b'\x00\x00\x00\x00'
            self.assertRaises(LDAPCommunicationError,
                              krb._common_process_end_token_get_security_layers, token, ENCRYPT)

    def test_reject_zero_max_output_size(self):
        with GssapiModulePatcher() as krb:
            token = bytes([krb.CONFIDENTIALITY_PROTECTION]) + b'\x00\x00\x00'
            self.assertRaises(LDAPCommunicationError,
                              krb._common_process_end_token_get_security_layers, token, ENCRYPT)

    def test_reject_tiny_max_output_size(self):
        with GssapiModulePatcher() as krb:
            # only room for the 4 byte framing header, no room for any protected payload
            token = bytes([krb.CONFIDENTIALITY_PROTECTION]) + struct.pack('!I', krb.SASL_GSSAPI_WRAP_HEADER_SIZE)[1:]
            self.assertRaises(LDAPCommunicationError,
                              krb._common_process_end_token_get_security_layers, token, ENCRYPT)

    def test_reject_unknown_security_layer_bits(self):
        with GssapiModulePatcher() as krb:
            token = bytes([krb.CONFIDENTIALITY_PROTECTION | 0x08 | 0x80]) + struct.pack('!I', 4096)[1:]
            self.assertRaises(LDAPCommunicationError,
                              krb._common_process_end_token_get_security_layers, token, ENCRYPT)

    def test_no_security_layer_requires_zero_buffer(self):
        with GssapiModulePatcher() as krb:
            token = bytes([krb.NO_SECURITY_LAYER]) + b'\x01\x00\x00'
            self.assertRaises(LDAPCommunicationError,
                              krb._common_process_end_token_get_security_layers, token, None)

    def test_auth_only_negotiation_accepted(self):
        with GssapiModulePatcher() as krb:
            token = bytes([krb.NO_SECURITY_LAYER]) + b'\x00\x00\x00'
            layers, limit = krb._common_process_end_token_get_security_layers(token, None)
            self.assertEqual(layers[0], krb.NO_SECURITY_LAYER)
            self.assertEqual(limit, 0)

    def test_valid_confidentiality_negotiation(self):
        with GssapiModulePatcher() as krb:
            token = bytes([krb.CONFIDENTIALITY_PROTECTION]) + struct.pack('!I', 8192)[1:]
            layers, limit = krb._common_process_end_token_get_security_layers(token, ENCRYPT)
            self.assertEqual(layers[0], krb.CONFIDENTIALITY_PROTECTION)
            self.assertEqual(limit, 8192)


class TestNegotiationBoundary(unittest.TestCase):
    def _bind(self, krb, connection):
        with mock.patch.object(krb, 'send_sasl_negotiation', side_effect=patched_sasl_negotiation):
            return krb.sasl_gssapi(connection, None)

    def test_successful_posix_negotiation_publishes_protection(self):
        with GssapiModulePatcher(posix=True) as krb:
            connection = FakeConnection()
            self._bind(krb, connection)
            self.assertIsNotNone(connection.krb_ctx)
            self.assertEqual(connection.krb_wrap_size_limit, connection.server_max_output)

    def test_failed_negotiation_leaves_no_usable_context_posix(self):
        with GssapiModulePatcher(posix=True) as krb:
            connection = FakeConnection(server_max_output=0)
            with mock.patch.object(krb, 'send_sasl_negotiation', side_effect=patched_sasl_negotiation), \
                    mock.patch.object(krb, 'abort_sasl_negotiation', side_effect=patched_abort):
                self.assertRaises(LDAPCommunicationError, krb.sasl_gssapi, connection, None)
            self.assertIsNone(connection.krb_ctx)
            self.assertIsNone(connection.krb_wrap_size_limit)
            self.assertTrue(connection.aborted)

    def test_failed_negotiation_clears_stale_context(self):
        with GssapiModulePatcher(posix=True) as krb:
            connection = FakeConnection(server_max_output=0)
            connection.krb_ctx = object()
            connection.krb_wrap_size_limit = 9999
            with mock.patch.object(krb, 'send_sasl_negotiation', side_effect=patched_sasl_negotiation), \
                    mock.patch.object(krb, 'abort_sasl_negotiation', side_effect=patched_abort):
                self.assertRaises(LDAPCommunicationError, krb.sasl_gssapi, connection, None)
            self.assertIsNone(connection.krb_ctx)
            self.assertIsNone(connection.krb_wrap_size_limit)

    def test_successful_windows_negotiation_publishes_protection(self):
        with GssapiModulePatcher(posix=False) as krb:
            connection = FakeConnection()
            self._bind(krb, connection)
            self.assertIsNotNone(connection.krb_ctx)
            self.assertEqual(connection.krb_wrap_size_limit, connection.server_max_output)

    def test_failed_windows_negotiation_leaves_no_usable_context(self):
        with GssapiModulePatcher(posix=False) as krb:
            connection = FakeConnection(server_max_output=0)
            with mock.patch.object(krb, 'send_sasl_negotiation', side_effect=patched_sasl_negotiation), \
                    mock.patch.object(krb, 'abort_sasl_negotiation', side_effect=patched_abort):
                self.assertRaises(LDAPCommunicationError, krb.sasl_gssapi, connection, None)
            self.assertIsNone(connection.krb_ctx)
            self.assertIsNone(connection.krb_wrap_size_limit)
            self.assertTrue(connection.aborted)


class TestMessageWrapping(unittest.TestCase):
    def _protected_connection(self, krb, posix, max_output=100):
        connection = FakeConnection(server_max_output=max_output)
        with mock.patch.object(krb, 'send_sasl_negotiation', side_effect=patched_sasl_negotiation):
            krb.sasl_gssapi(connection, None)
        return connection

    def _decode_frames(self, data):
        frames = []
        offset = 0
        while offset < len(data):
            length = struct.unpack('!I', data[offset:offset + 4])[0]
            offset += 4
            frames.append(data[offset:offset + length])
            offset += length
        self.assertEqual(offset, len(data))
        return frames

    def test_unencrypted_token_never_sent_without_context(self):
        with GssapiModulePatcher(posix=True) as krb:
            connection = FakeConnection()
            # simulate a connection that authenticated but never established protection
            connection.krb_ctx = None
            connection.krb_wrap_size_limit = None
            self.assertRaises(LDAPCommunicationError, krb.wrap_gssapi_message, connection, b'secret-payload')
            self.assertEqual(connection.socket.sent, [])

    def test_posix_wrapping_chunks_and_respects_frame_limit(self):
        with GssapiModulePatcher(posix=True) as krb:
            max_output = 60
            connection = self._protected_connection(krb, True, max_output=max_output)
            message = b'x' * 200
            framed = krb.wrap_gssapi_message(connection, message)
            frames = self._decode_frames(framed)
            self.assertGreater(len(frames), 1)
            for frame in frames:
                # frame plus its 4 byte length header must not exceed the negotiated limit
                self.assertLessEqual(len(frame) + krb.SASL_GSSAPI_WRAP_HEADER_SIZE, max_output)
            # round trip through the same fake context recovers the plaintext
            rebuilt = b''.join(connection.krb_ctx.unwrap(frame).message for frame in frames)
            self.assertEqual(rebuilt, message)

    def test_posix_small_message_uses_single_frame(self):
        with GssapiModulePatcher(posix=True) as krb:
            connection = self._protected_connection(krb, True, max_output=100)
            framed = krb.wrap_gssapi_message(connection, b'small')
            frames = self._decode_frames(framed)
            self.assertEqual(len(frames), 1)
            self.assertEqual(connection.krb_ctx.unwrap(frames[0]).message, b'small')

    def test_windows_wrapping_enforces_frame_limit(self):
        with GssapiModulePatcher(posix=False) as krb:
            connection = self._protected_connection(krb, False, max_output=4096)
            framed = krb.wrap_gssapi_message(connection, b'any-message')
            frames = self._decode_frames(framed)
            self.assertEqual(len(frames), 1)
            self.assertLessEqual(len(framed), 4096)

    def test_windows_oversized_message_rejected(self):
        with GssapiModulePatcher(posix=False) as krb:
            connection = self._protected_connection(krb, False, max_output=4096)
            connection.krb_wrap_size_limit = 20
            self.assertRaises(LDAPCommunicationError,
                              krb.wrap_gssapi_message, connection, b'y' * 500)

    def test_no_zero_progress_loop_when_overhead_exceeds_limit(self):
        with GssapiModulePatcher(posix=True) as krb:
            # limit large enough to pass negotiation (greater than 4) but too
            # small for the 16 byte GSSAPI overhead of the fake context
            connection = FakeConnection(server_max_output=10)
            connection.krb_ctx = FakeSecurityContext()
            connection.krb_ctx.complete = True
            connection.krb_wrap_size_limit = 10
            self.assertRaises(LDAPCommunicationError,
                              krb.wrap_gssapi_message, connection, b'data')

    def test_unwrap_without_context_rejected(self):
        with GssapiModulePatcher(posix=True) as krb:
            connection = FakeConnection()
            self.assertRaises(LDAPCommunicationError,
                              krb.unwrap_gssapi_message, connection, b'protected')

    def test_windows_unwrap_without_context_rejected(self):
        with GssapiModulePatcher(posix=False) as krb:
            connection = FakeConnection()
            self.assertRaises(LDAPCommunicationError,
                              krb.unwrap_gssapi_message, connection, b'protected')


class TestStrategySendingBoundary(unittest.TestCase):
    def _build_strategy(self, connection):
        strategy = BaseStrategy.__new__(BaseStrategy)
        strategy.connection = connection
        return strategy

    def test_sending_refuses_plaintext_when_encryption_required_but_context_missing(self):
        with GssapiModulePatcher(posix=True):
            from ldap3.strategy import base as base_module
            connection = FakeConnection()
            connection.authentication = 'SASL'
            connection.sasl_in_progress = False
            connection.usage = False
            connection.krb_ctx = None
            connection.krb_wrap_size_limit = None
            strategy = self._build_strategy(connection)
            ldap_message = {'messageId': 1, 'raw': b'ignored'}
            with mock.patch.object(base_module, 'encode', return_value=b'plaintext-secret'):
                self.assertRaises(LDAPCommunicationError, strategy.sending, ldap_message)
            # nothing reached the socket, so no unencrypted token leaves the client
            self.assertEqual(connection.socket.sent, [])

    def test_sending_wraps_application_message_with_negotiated_context(self):
        with GssapiModulePatcher(posix=True) as krb:
            from ldap3.strategy import base as base_module
            connection = FakeConnection(server_max_output=64)
            connection.authentication = 'SASL'
            connection.sasl_in_progress = False
            connection.usage = False
            with mock.patch.object(krb, 'send_sasl_negotiation', side_effect=patched_sasl_negotiation):
                krb.sasl_gssapi(connection, None)
            strategy = self._build_strategy(connection)
            plaintext = b'z' * 120
            ldap_message = {'messageId': 1, 'raw': b'ignored'}
            with mock.patch.object(base_module, 'encode', return_value=plaintext):
                strategy.sending(ldap_message)
            self.assertEqual(len(connection.socket.sent), 1)
            wire = connection.socket.sent[0]
            # every byte on the wire is part of length-prefixed wrapped frames
            offset = 0
            recovered = b''
            while offset < len(wire):
                length = struct.unpack('!I', wire[offset:offset + 4])[0]
                offset += 4
                frame = wire[offset:offset + length]
                offset += length
                self.assertLessEqual(length + krb.SASL_GSSAPI_WRAP_HEADER_SIZE,
                                     connection.krb_wrap_size_limit)
                recovered += connection.krb_ctx.unwrap(frame).message
            self.assertEqual(recovered, plaintext)
            self.assertNotIn(plaintext, wire)


if __name__ == '__main__':
    unittest.main()
