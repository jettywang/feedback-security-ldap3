# -*- coding: utf-8 -*-
"""
"""

# Created on 2026.11.12
#
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

from ldap3 import Server, Connection, MOCK_SYNC, MOCK_ASYNC, OFFLINE_AD_2012_R2, OFFLINE_SLAPD_2_4, \
    MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, ALL
from ldap3.core.exceptions import LDAPPasswordIsMandatoryError, LDAPOperationResult
from ldap3.extend.password import PasswordAdapter, PasswordResult, change_password, reset_password, \
    PASSWORD_CHANGE, PASSWORD_RESET, PASSWORD_BACKEND_AD, PASSWORD_BACKEND_STANDARD
from ldap3.operation.extended import extended_request_to_dict
from ldap3.operation.modify import modify_request_to_dict
from ldap3.protocol.rfc3062 import PasswdModifyRequestValue
from ldap3.utils.asn1 import decoder

USER_DN = 'cn=user1,ou=test,o=lab'
OLD_PASSWORD = 'OldPässwörd'
NEW_PASSWORD = 'NéwPässwörd'


class RecorderStrategy(object):
    sync = True
    thread_safe = False


class Recorder(object):
    """Substitute for the connection that records the exact request objects."""

    def __init__(self):
        self.calls = []
        self.result = {'result': 0, 'description': 'success', 'dn': '', 'message': '', 'type': 'modifyResponse'}
        self.response = None
        self.check_names = True
        self.strategy = RecorderStrategy()
        self.server = type('RecorderServer', (object,), {'info': None})()
        self.raise_exceptions = False

    def modify(self, dn, changes, controls=None):
        self.calls.append(('modify', dn, changes))
        return True

    def extended(self, request_name, request_value=None, controls=None, no_encode=None):
        self.calls.append(('extended', request_name, request_value))
        return True


class ExtendedRecorder(Recorder):
    result = None

    def extended(self, request_name, request_value=None, controls=None, no_encode=None):
        self.calls.append(('extended', request_name, request_value))
        self.result = {'result': 0, 'description': 'success', 'dn': '', 'message': '',
                       'type': 'extendedResp', 'responseName': '', 'responseValue': bytes()}
        return True


class AsyncRecorder(ExtendedRecorder):
    def __init__(self):
        Recorder.__init__(self)
        self.strategy = RecorderStrategy()
        self.strategy.sync = False
        self._pending = []

    def extended(self, request_name, request_value=None, controls=None, no_encode=None):
        self._pending.append(('extended', request_name, request_value))
        return 1

    def modify(self, dn, changes, controls=None):
        self._pending.append(('modify', dn, changes))
        return 1

    def get_response(self, message_id, timeout=None, get_request=False):
        self.calls.extend(self._pending)
        self._pending = []
        return None, dict(self.result)


def _decode_rfc3062(request_value):
    from ldap3.utils.asn1 import encode
    from pyasn1.type.univ import OctetString
    if isinstance(request_value, bytes):
        encoded = request_value  # already the raw SEQUENCE payload
    elif isinstance(request_value, OctetString):  # a [1] RequestValue wrapper, unwrap the bytes
        encoded = bytes(request_value)
    else:
        encoded = encode(request_value)
    decoded, _ = decoder.decode(encoded, asn1Spec=PasswdModifyRequestValue())
    sent = {}
    for field in ('userIdentity', 'oldPasswd', 'newPasswd'):
        if decoded[field].hasValue():
            sent[field] = bytes(decoded[field])
    return sent


def _changes(record):
    return record[2]['unicodePwd']


class TestPasswordIntentWireFormat(unittest.TestCase):
    def test_ad_change_sends_delete_then_add_with_quoted_utf16le(self):
        recorder = Recorder()
        result = PasswordAdapter(recorder).change_password(USER_DN, OLD_PASSWORD, NEW_PASSWORD, backend=PASSWORD_BACKEND_AD)

        self.assertEqual(len(recorder.calls), 1)
        self.assertEqual(recorder.calls[0][0], 'modify')
        changes = _changes(recorder.calls[0])
        self.assertEqual([change[0] for change in changes], [MODIFY_DELETE, MODIFY_ADD])
        self.assertEqual(changes[0][1], [('"%s"' % OLD_PASSWORD).encode('utf-16-le')])
        self.assertEqual(changes[1][1], [('"%s"' % NEW_PASSWORD).encode('utf-16-le')])
        # a real wire round-trip keeps the quoted Unicode bytes
        from ldap3.operation.modify import modify_operation
        request = modify_operation(USER_DN,
                                   {'unicodePwd': changes},
                                   auto_encode=False,
                                   check_names=False)
        decoded_changes = modify_request_to_dict(request)['changes']
        self.assertEqual(decoded_changes[0]['operation'], 1)
        self.assertEqual(decoded_changes[0]['attribute']['value'], [('"%s"' % OLD_PASSWORD).encode('utf-16-le')])
        self.assertEqual(decoded_changes[1]['operation'], 0)
        self.assertTrue(result)
        self.assertEqual(result.operation, PASSWORD_CHANGE)
        self.assertEqual(result.backend, PASSWORD_BACKEND_AD)

    def test_ad_reset_sends_single_replace(self):
        recorder = Recorder()
        result = PasswordAdapter(recorder).reset_password(USER_DN, NEW_PASSWORD, backend=PASSWORD_BACKEND_AD)

        self.assertEqual(len(recorder.calls), 1)
        changes = _changes(recorder.calls[0])
        self.assertEqual([change[0] for change in changes], [MODIFY_REPLACE])
        self.assertEqual(changes[0][1], [('"%s"' % NEW_PASSWORD).encode('utf-16-le')])
        self.assertTrue(result)
        self.assertEqual(result.operation, PASSWORD_RESET)

    def test_standard_change_requires_old_password_on_the_wire(self):
        recorder = ExtendedRecorder()
        result = PasswordAdapter(recorder).change_password(USER_DN, OLD_PASSWORD, NEW_PASSWORD, backend=PASSWORD_BACKEND_STANDARD)

        self.assertEqual(len(recorder.calls), 1)
        self.assertEqual(recorder.calls[0][1], '1.3.6.1.4.1.4203.1.11.1')
        sent = _decode_rfc3062(recorder.calls[0][2])
        self.assertIn('oldPasswd', sent)
        self.assertIn('newPasswd', sent)
        self.assertEqual(sent['oldPasswd'], OLD_PASSWORD.encode('utf-8'))
        self.assertEqual(sent['newPasswd'], NEW_PASSWORD.encode('utf-8'))
        self.assertTrue(result)
        self.assertEqual(result.operation, PASSWORD_CHANGE)
        self.assertEqual(result.backend, PASSWORD_BACKEND_STANDARD)

    def test_standard_reset_sends_no_old_password(self):
        recorder = ExtendedRecorder()
        result = PasswordAdapter(recorder).reset_password(USER_DN, NEW_PASSWORD, backend=PASSWORD_BACKEND_STANDARD)

        self.assertEqual(len(recorder.calls), 1)
        sent = _decode_rfc3062(recorder.calls[0][2])
        self.assertNotIn('oldPasswd', sent)
        self.assertIn('newPasswd', sent)
        self.assertTrue(result)
        self.assertEqual(result.operation, PASSWORD_RESET)

    def test_empty_old_password_is_sent_as_supplied_value_and_differs_from_omission(self):
        change_recorder = ExtendedRecorder()
        result = PasswordAdapter(change_recorder).change_password(USER_DN, '', NEW_PASSWORD, backend=PASSWORD_BACKEND_STANDARD)
        sent = _decode_rfc3062(change_recorder.calls[0][2])
        self.assertIn('oldPasswd', sent)
        self.assertEqual(sent['oldPasswd'], b'')

        reset_recorder = ExtendedRecorder()
        PasswordAdapter(reset_recorder).reset_password(USER_DN, NEW_PASSWORD, backend=PASSWORD_BACKEND_STANDARD)
        reset_sent = _decode_rfc3062(reset_recorder.calls[0][2])
        self.assertNotIn('oldPasswd', reset_sent)
        self.assertFalse(result == False)
        self.assertTrue(result)
        self.assertTrue(result == True)


class TestNoImplicitPrivilegeEscalation(unittest.TestCase):
    def test_missing_old_password_sends_nothing(self):
        for recorder_class in (Recorder, ExtendedRecorder):
            recorder = recorder_class()
            with self.assertRaises(LDAPPasswordIsMandatoryError):
                PasswordAdapter(recorder).change_password(USER_DN, None, NEW_PASSWORD, backend=PASSWORD_BACKEND_AD)
            self.assertEqual(recorder.calls, [])

        ad_missing = Recorder()
        with self.assertRaises(LDAPPasswordIsMandatoryError):
            PasswordAdapter(ad_missing).change_password(USER_DN, None, NEW_PASSWORD, backend=PASSWORD_BACKEND_STANDARD)
        self.assertEqual(ad_missing.calls, [])

    def test_ad_legacy_none_raises_and_empty_string_stays_a_change(self):
        from ldap3.extend.microsoft.modifyPassword import ad_modify_password

        omitted_recorder = Recorder()
        with self.assertRaises(LDAPPasswordIsMandatoryError):
            ad_modify_password(omitted_recorder, USER_DN, NEW_PASSWORD, None)
        self.assertEqual(omitted_recorder.calls, [])

        change_recorder = Recorder()
        ad_modify_password(change_recorder, USER_DN, NEW_PASSWORD, '')
        # an empty old password is supplied, so this remains a change (DELETE + ADD), never a REPLACE reset
        self.assertEqual([change[0] for change in _changes(change_recorder.calls[0])], [MODIFY_DELETE, MODIFY_ADD])
        self.assertEqual(_changes(change_recorder.calls[0])[0][1], ['""'.encode('utf-16-le')])

    def test_failed_change_never_sends_reset(self):
        class FailingRecorder(Recorder):
            def __init__(self):
                Recorder.__init__(self)
                self.result = {'result': 19, 'description': 'constraintViolation', 'dn': '', 'message': 'policy', 'type': 'modifyResponse'}

        recorder = FailingRecorder()
        result = PasswordAdapter(recorder).change_password(USER_DN, OLD_PASSWORD, NEW_PASSWORD, backend=PASSWORD_BACKEND_AD)
        self.assertFalse(result)
        self.assertEqual(len(recorder.calls), 1)
        self.assertEqual([change[0] for change in _changes(recorder.calls[0])], [MODIFY_DELETE, MODIFY_ADD])
        self.assertEqual(result.operation, PASSWORD_CHANGE)
        self.assertEqual(result.failed_operation, PASSWORD_CHANGE)
        self.assertEqual(result.description, 'constraintViolation')

    def test_failed_standard_change_never_sends_reset(self):
        class FailingRecorder(ExtendedRecorder):
            def extended(self, request_name, request_value=None, controls=None, no_encode=None):
                ExtendedRecorder.extended(self, request_name, request_value, controls, no_encode)
                self.result = {'result': 53, 'description': 'unwillingToPerform', 'dn': '', 'message': 'policy',
                               'type': 'extendedResp', 'responseName': '', 'responseValue': bytes()}
                return True

        recorder = FailingRecorder()
        result = PasswordAdapter(recorder).change_password(USER_DN, OLD_PASSWORD, NEW_PASSWORD, backend=PASSWORD_BACKEND_STANDARD)
        self.assertEqual(len(recorder.calls), 1)
        self.assertFalse(result)
        self.assertEqual(result.operation, PASSWORD_CHANGE)
        self.assertEqual(result.backend, PASSWORD_BACKEND_STANDARD)
        self.assertEqual(result.description, 'unwillingToPerform')

    def test_raise_exceptions_still_identifies_operation(self):
        class RaisingRecorder(Recorder):
            def __init__(self):
                Recorder.__init__(self)
                self.raise_exceptions = True
                self.result = {'result': 19, 'description': 'constraintViolation', 'dn': '', 'message': 'policy', 'type': 'modifyResponse'}

        recorder = RaisingRecorder()
        with self.assertRaises(LDAPOperationResult) as context:
            PasswordAdapter(recorder).change_password(USER_DN, OLD_PASSWORD, NEW_PASSWORD, backend=PASSWORD_BACKEND_AD)
        self.assertEqual(context.exception.result, 19)
        self.assertEqual(context.exception.operation, PASSWORD_CHANGE)
        self.assertEqual(context.exception.backend, PASSWORD_BACKEND_AD)
        self.assertEqual(len(recorder.calls), 1)


class TestAdapterContracts(unittest.TestCase):
    def test_result_identifies_intent_in_both_directions(self):
        success = PasswordResult(PASSWORD_CHANGE, PASSWORD_BACKEND_AD, True)
        self.assertTrue(success)
        self.assertIsNone(success.failed_operation)
        failure = PasswordResult(PASSWORD_RESET, PASSWORD_BACKEND_STANDARD, False, result={'result': 53,
                                                                                          'description': 'unwillingToPerform',
                                                                                          'message': 'policy',
                                                                                          'dn': ''})
        self.assertFalse(failure)
        self.assertEqual(failure.failed_operation, PASSWORD_RESET)
        self.assertEqual(failure.operation, PASSWORD_RESET)
        self.assertEqual(failure.backend, PASSWORD_BACKEND_STANDARD)
        self.assertEqual(failure.result_code, 53)
        self.assertEqual(failure.description, 'unwillingToPerform')

    def test_adapter_exposes_both_explicit_operations(self):
        recorder = Recorder()
        adapter = PasswordAdapter(recorder)
        self.assertTrue(hasattr(adapter, 'change_password'))
        self.assertTrue(hasattr(adapter, 'reset_password'))
        with self.assertRaises(LDAPPasswordIsMandatoryError):
            adapter.change_password(USER_DN, None, NEW_PASSWORD, backend=PASSWORD_BACKEND_AD)
        self.assertEqual(recorder.calls, [])

    def test_server_policy_rejection_is_surfaced_with_intent(self):
        class PolicyRecorder(Recorder):
            def __init__(self):
                Recorder.__init__(self)
                self.result = {'result': 19, 'description': 'constraintViolation', 'dn': '', 'message': 'policy violation', 'type': 'modifyResponse'}

        recorder = PolicyRecorder()
        result = PasswordAdapter(recorder).reset_password(USER_DN, NEW_PASSWORD, backend=PASSWORD_BACKEND_AD)
        self.assertFalse(result)
        self.assertEqual(result.operation, PASSWORD_RESET)
        self.assertEqual(result.result_code, 19)
        self.assertEqual(result.message, 'policy violation')


class TestMockWireRoundTrip(unittest.TestCase):
    """Uses the mock LDAP server so the real ASN.1 encoders/decoders are exercised."""

    def setUp(self):
        self.server = Server('dummy')  # no schema: the mock DIT applies AD unicodePwd semantics as a plain attribute
        self.connection = Connection(self.server, user='cn=admin,o=lab', password='admin', client_strategy=MOCK_SYNC, raise_exceptions=False)
        self.connection.open()
        self.connection.strategy.add_entry(USER_DN, {'userPassword': 'old',
                                                      'unicodePwd': ('"%s"' % OLD_PASSWORD).encode('utf-16-le')})

    def tearDown(self):
        self.connection.unbind()

    def test_ad_change_updates_unicode_pwd_atomically(self):
        result = self.connection.extend.password.change_password(USER_DN, OLD_PASSWORD, NEW_PASSWORD, backend=PASSWORD_BACKEND_AD)
        self.assertTrue(result)
        self.assertEqual(result.operation, PASSWORD_CHANGE)
        stored = self.connection.server.dit[USER_DN]['unicodePwd'][0]
        self.assertEqual(stored, ('"%s"' % NEW_PASSWORD).encode('utf-16-le'))

    def test_ad_reset_replaces_unicode_pwd(self):
        result = self.connection.extend.password.reset_password(USER_DN, NEW_PASSWORD, backend=PASSWORD_BACKEND_AD)
        self.assertTrue(result)
        self.assertEqual(result.operation, PASSWORD_RESET)
        stored = self.connection.server.dit[USER_DN]['unicodePwd'][0]
        self.assertEqual(stored, ('"%s"' % NEW_PASSWORD).encode('utf-16-le'))

    def test_ad_wrong_old_password_fails_without_reset(self):
        recorder_calls = []
        result = self.connection.extend.password.change_password(USER_DN, 'WrongPassword', NEW_PASSWORD, backend=PASSWORD_BACKEND_AD)
        self.assertFalse(result)
        self.assertEqual(result.operation, PASSWORD_CHANGE)
        self.assertEqual(result.failed_operation, PASSWORD_CHANGE)
        self.assertEqual(result.backend, PASSWORD_BACKEND_AD)
        # the stored password is unchanged: no reset fallback was issued
        stored = self.connection.server.dit[USER_DN]['unicodePwd'][0]
        self.assertEqual(stored, ('"%s"' % OLD_PASSWORD).encode('utf-16-le'))

    def test_ad_async_change_returns_intent_bound_result(self):
        server = Server('dummy')
        connection = Connection(server, user='cn=admin,o=lab', password='admin', client_strategy=MOCK_ASYNC, raise_exceptions=False)
        connection.open()
        connection.strategy.add_entry(USER_DN, {'userPassword': 'old',
                                                 'unicodePwd': ('"%s"' % OLD_PASSWORD).encode('utf-16-le')})
        result = connection.extend.password.change_password(USER_DN, OLD_PASSWORD, NEW_PASSWORD, backend=PASSWORD_BACKEND_AD)
        self.assertEqual(result.operation, PASSWORD_CHANGE)
        self.assertTrue(result)
        connection.unbind()


class WireCapture(object):
    """Wraps connection.send to keep the exact request objects that go on the wire."""

    def __init__(self, connection):
        self.connection = connection
        self.messages = []
        self._original_send = connection.send
        connection.send = self._send

    def _send(self, message_type, request, controls=None):
        self.messages.append((message_type, request))
        return self._original_send(message_type, request, controls)

    def close(self):
        self.connection.send = self._original_send


class TestCapturedWireBytes(unittest.TestCase):
    def _connection(self, strategy=MOCK_SYNC):
        server = Server('dummy')
        connection = Connection(server, user='cn=admin,o=lab', password='admin', client_strategy=strategy, raise_exceptions=False)
        connection.open()
        connection.strategy.add_entry(USER_DN, {'userPassword': 'old',
                                                'unicodePwd': ('"%s"' % OLD_PASSWORD).encode('utf-16-le')})
        return connection

    def test_ad_change_and_reset_produce_different_wire_bytes(self):
        from ldap3.utils.asn1 import encode
        from ldap3.protocol.rfc4511 import ModifyRequest

        change_connection = self._connection()
        change_capture = WireCapture(change_connection)
        change_connection.extend.microsoft.change_password(USER_DN, OLD_PASSWORD, NEW_PASSWORD)
        change_capture.close()
        self.assertEqual(len(change_capture.messages), 1)
        change_message_type, change_request = change_capture.messages[0]
        self.assertEqual(change_message_type, 'modifyRequest')
        change_bytes = encode(change_request)
        change_decoded, _ = decoder.decode(change_bytes, asn1Spec=ModifyRequest())
        self.assertEqual(len(change_decoded['changes']), 2)  # DELETE old + ADD new
        change_connection.unbind()

        reset_connection = self._connection()
        reset_capture = WireCapture(reset_connection)
        reset_connection.extend.microsoft.reset_password(USER_DN, NEW_PASSWORD)
        reset_capture.close()
        self.assertEqual(len(reset_capture.messages), 1)
        reset_message_type, reset_request = reset_capture.messages[0]
        self.assertEqual(reset_message_type, 'modifyRequest')
        reset_decoded, _ = decoder.decode(encode(reset_request), asn1Spec=ModifyRequest())
        self.assertEqual(len(reset_decoded['changes']), 1)  # single REPLACE
        reset_connection.unbind()

        self.assertNotEqual(change_bytes, encode(reset_request))

    def test_rfc3062_old_password_tag_presence_drives_the_wire(self):
        from ldap3.utils.asn1 import encode
        from ldap3.protocol.rfc4511 import ExtendedRequest

        change_connection = self._connection()
        change_capture = WireCapture(change_connection)
        change_connection.extend.standard.change_password(USER_DN, OLD_PASSWORD, NEW_PASSWORD)
        change_capture.close()
        self.assertEqual(len(change_capture.messages), 1)
        request = change_capture.messages[0][1]
        sent = _decode_rfc3062(request['requestValue'])
        self.assertIn('oldPasswd', sent)
        self.assertIn('newPasswd', sent)
        self.assertEqual(sent['oldPasswd'], OLD_PASSWORD.encode('utf-8'))
        self.assertEqual(sent['newPasswd'], NEW_PASSWORD.encode('utf-8'))
        change_connection.unbind()

        reset_connection = self._connection()
        reset_capture = WireCapture(reset_connection)
        reset_connection.extend.standard.reset_password(USER_DN, NEW_PASSWORD)
        reset_capture.close()
        self.assertEqual(len(reset_capture.messages), 1)
        request = reset_capture.messages[0][1]
        sent = _decode_rfc3062(request['requestValue'])
        self.assertNotIn('oldPasswd', sent)
        self.assertIn('newPasswd', sent)
        self.assertEqual(sent['newPasswd'], NEW_PASSWORD.encode('utf-8'))
        reset_connection.unbind()

    def test_omitted_old_password_produces_zero_messages(self):
        connection = self._connection()
        capture = WireCapture(connection)
        with self.assertRaises(LDAPPasswordIsMandatoryError):
            connection.extend.password.change_password(USER_DN, None, NEW_PASSWORD, backend=PASSWORD_BACKEND_STANDARD)
        with self.assertRaises(LDAPPasswordIsMandatoryError):
            connection.extend.password.change_password(USER_DN, None, NEW_PASSWORD, backend=PASSWORD_BACKEND_AD)
        with self.assertRaises(LDAPPasswordIsMandatoryError):
            connection.extend.standard.modify_password(USER_DN, old_password=None, new_password=NEW_PASSWORD)
        capture.close()
        self.assertEqual(capture.messages, [])
        connection.unbind()


if __name__ == '__main__':
    unittest.main()
