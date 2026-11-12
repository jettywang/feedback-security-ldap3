"""
"""

# Created on 2026.11.12
#
# Author: Giovanni Cannata
#
# Copyright 2026 Giovanni Cannata
#
# This file is part of ldap3.
#
# ldap3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
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

from ldap3 import Server, Connection, MOCK_SYNC, SUBTREE, BASE, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPControlError, LDAPExtensionError
from ldap3.core.results import (RESULT_SUCCESS,
                                RESULT_UNAVAILABLE_CRITICAL_EXTENSION,
                                RESULT_INSUFFICIENT_ACCESS_RIGHTS,
                                RESULT_AUTHORIZATION_DENIED)
from ldap3.protocol.controls import build_control
from ldap3.protocol.rfc4370 import (PROXY_AUTHORIZATION_OID,
                                    OLD_PROXIED_AUTHORIZATION_OID,
                                    proxy_authorization_control,
                                    parse_proxy_authorization_control)
from ldap3.strategy.base import BaseStrategy
from ldap3.extend.standard.proxyAuthorization import proxied_search, assert_proxy_authorization_applied
from ldap3.utils.asn1 import encode, decode_sequence

SERVICE_ACCOUNT = 'cn=svc,ou=services,o=lab'
ALICE = 'cn=alice,ou=people,o=lab'
BOB = 'cn=bob,ou=people,o=lab'
ALICE_AUTHZ = 'dn:' + ALICE
BOB_AUTHZ = 'dn:' + BOB


class TestProxyAuthorizationEncoding(unittest.TestCase):
    def test_control_is_critical_by_default_and_carries_authzid(self):
        control = proxy_authorization_control(ALICE_AUTHZ)
        self.assertEqual(str(control['controlType']), PROXY_AUTHORIZATION_OID)
        self.assertTrue(bool(control['criticality']))
        oid, criticality, authz_id = parse_proxy_authorization_control(control)
        self.assertEqual(oid, PROXY_AUTHORIZATION_OID)
        self.assertTrue(criticality)
        self.assertEqual(authz_id, ALICE_AUTHZ)

    def test_bare_dn_is_qualified_with_dn_prefix(self):
        control = proxy_authorization_control(ALICE)
        self.assertEqual(parse_proxy_authorization_control(control)[2], ALICE_AUTHZ)

    def test_user_authzid_is_preserved(self):
        control = proxy_authorization_control('u:carol@example.com', criticality=False)
        oid, criticality, authz_id = parse_proxy_authorization_control(control)
        self.assertEqual(authz_id, 'u:carol@example.com')
        self.assertFalse(criticality)

    def test_legacy_netscape_control_uses_bare_dn_value(self):
        control = proxy_authorization_control(ALICE, oid=OLD_PROXIED_AUTHORIZATION_OID)
        oid, criticality, authz_id = parse_proxy_authorization_control(control)
        self.assertEqual(oid, OLD_PROXIED_AUTHORIZATION_OID)
        self.assertTrue(criticality)
        self.assertEqual(authz_id, ALICE)

    def test_legacy_control_rejects_user_authzid(self):
        self.assertRaises(LDAPControlError,
                          proxy_authorization_control,
                          'u:carol@example.com',
                          oid=OLD_PROXIED_AUTHORIZATION_OID)

    def test_empty_authorization_id_is_rejected(self):
        self.assertRaises(LDAPControlError, proxy_authorization_control, '   ')

    def test_non_boolean_criticality_is_rejected(self):
        self.assertRaises(LDAPControlError, proxy_authorization_control, ALICE_AUTHZ, criticality='yes')

    def test_each_call_builds_a_fresh_bound_control(self):
        first = proxy_authorization_control(ALICE_AUTHZ)
        second = proxy_authorization_control(BOB_AUTHZ)
        self.assertIsNot(first, second)
        self.assertEqual(parse_proxy_authorization_control(first)[2], ALICE_AUTHZ)
        self.assertEqual(parse_proxy_authorization_control(second)[2], BOB_AUTHZ)
        # mutating one request's controls list cannot touch the other request
        bundle = [first]
        bundle.append(second)
        self.assertEqual(parse_proxy_authorization_control(bundle[0])[2], ALICE_AUTHZ)

    def test_wire_encoding_round_trips_through_both_decoders(self):
        control = proxy_authorization_control(ALICE_AUTHZ)
        encoded = encode(control)
        # the controlValue is the BER-encoded proxyAuthzID OCTET STRING, tag 0x04
        self.assertIn(b'dn:' + ALICE.encode('utf-8'), encoded)
        decoded = BaseStrategy.decode_control(control)
        self.assertEqual(decoded[0], PROXY_AUTHORIZATION_OID)
        self.assertEqual(decoded[1]['value'], ALICE_AUTHZ)
        outer = decode_sequence(encoded, 0, len(encoded))[0]
        fast_decoded = BaseStrategy.decode_control_fast(outer[3])
        self.assertEqual(fast_decoded[0], PROXY_AUTHORIZATION_OID)
        self.assertEqual(fast_decoded[1]['value'], ALICE_AUTHZ)
        self.assertTrue(fast_decoded[1]['criticality'])


class TestProxiedSearchOnMockServer(unittest.TestCase):
    def setUp(self):
        server = Server('mock-proxy-authz')
        self.connection = Connection(server, user=SERVICE_ACCOUNT, password='svc-pw', client_strategy=MOCK_SYNC)
        self.connection.strategy.add_entry(SERVICE_ACCOUNT, {'userPassword': 'svc-pw', 'sn': 'service_account'})
        self.connection.bind()
        self.connection.strategy.add_entry(ALICE, {'userPassword': 'alice-pw', 'sn': 'alice_sn', 'owner': 'alice-only'})
        self.connection.strategy.add_entry(BOB, {'userPassword': 'bob-pw', 'sn': 'bob_sn', 'owner': 'bob-only'})
        # the mock DSA only lets the service account impersonate the two known users
        self.connection.strategy.proxy_authorization_allowed = {ALICE_AUTHZ, BOB_AUTHZ}

    def tearDown(self):
        self.connection.unbind()

    def _encoded_request_control(self):
        self.assertEqual(len(self.connection.request['controls']), 1)
        control = self.connection.request['controls'][0]
        return parse_proxy_authorization_control(control)

    def test_interleaved_searches_keep_their_own_identity(self):
        caller_controls = []  # deliberately reused mutable list across requests
        proxied_search(self.connection, ALICE_AUTHZ, 'o=lab', '(owner=alice-only)', SUBTREE, attributes=['sn'], controls=caller_controls)
        self.assertEqual(self.connection.result['result'], RESULT_SUCCESS)
        self.assertEqual(self.connection.strategy.last_proxy_authorization_id, ALICE_AUTHZ)
        self.assertEqual(self._encoded_request_control(), (PROXY_AUTHORIZATION_OID, True, ALICE_AUTHZ))
        alice_entries = [entry['dn'] for entry in self.connection.response]

        proxied_search(self.connection, BOB_AUTHZ, 'o=lab', '(owner=bob-only)', SUBTREE, attributes=['sn'], controls=caller_controls)
        self.assertEqual(self.connection.result['result'], RESULT_SUCCESS)
        self.assertEqual(self.connection.strategy.last_proxy_authorization_id, BOB_AUTHZ)
        self.assertEqual(self._encoded_request_control(), (PROXY_AUTHORIZATION_OID, True, BOB_AUTHZ))
        bob_entries = [entry['dn'] for entry in self.connection.response]

        # the caller's list is never mutated, so no previous user can leak into a request
        self.assertEqual(caller_controls, [])
        self.assertEqual(alice_entries, [ALICE])
        self.assertEqual(bob_entries, [BOB])

        # interleave again in the opposite order, identity must follow the latest call
        proxied_search(self.connection, ALICE_AUTHZ, 'o=lab', '(sn=*)', SUBTREE, attributes=['sn'])
        self.assertEqual(self.connection.strategy.last_proxy_authorization_id, ALICE_AUTHZ)
        proxied_search(self.connection, BOB_AUTHZ, 'o=lab', '(sn=*)', SUBTREE, attributes=['sn'])
        self.assertEqual(self.connection.strategy.last_proxy_authorization_id, BOB_AUTHZ)

    def test_proxy_control_is_sent_even_without_extra_controls(self):
        proxied_search(self.connection, ALICE_AUTHZ, ALICE, '(objectclass=*)', BASE, attributes=[ALL_ATTRIBUTES])
        oid, criticality, authz_id = self._encoded_request_control()
        self.assertEqual(oid, PROXY_AUTHORIZATION_OID)
        self.assertTrue(criticality)
        self.assertEqual(authz_id, ALICE_AUTHZ)
        self.assertEqual(self.connection.strategy.last_proxy_authorization_id, ALICE_AUTHZ)

    def test_nested_proxy_control_in_extra_controls_is_rejected(self):
        smuggled = [proxy_authorization_control('dn:cn=attacker,o=lab')]
        self.assertRaises(LDAPControlError,
                          proxied_search,
                          self.connection,
                          ALICE_AUTHZ,
                          'o=lab',
                          '(sn=*)',
                          SUBTREE,
                          controls=smuggled)
        # nothing was sent, so no identity got recorded
        self.assertIsNone(self.connection.strategy.last_proxy_authorization_id)

    def test_authorization_denied_returns_distinct_result_and_no_service_account_entries(self):
        self.connection.strategy.proxy_authorization_allowed = {ALICE_AUTHZ}
        proxied_search(self.connection, BOB_AUTHZ, 'o=lab', '(sn=*)', SUBTREE, attributes=['sn'])
        self.assertEqual(self.connection.result['result'], RESULT_AUTHORIZATION_DENIED)
        self.assertEqual(self.connection.result['description'], 'authorizationDenied')
        self.assertEqual(self.connection.response, [])
        self.assertIsNone(self.connection.strategy.last_proxy_authorization_id)
        # the request still carried the (rejected) control, and no control-less retry happened
        self.assertEqual(self._encoded_request_control()[2], BOB_AUTHZ)
        with self.assertRaises(LDAPExtensionError) as raised:
            assert_proxy_authorization_applied(self.connection)
        self.assertIn('authorizationDenied', str(raised.exception))

    def test_unknown_dn_identity_returns_insufficient_access_rights(self):
        proxied_search(self.connection, 'dn:cn=ghost,ou=people,o=lab', 'o=lab', '(sn=*)', SUBTREE, attributes=['sn'])
        self.assertEqual(self.connection.result['result'], RESULT_INSUFFICIENT_ACCESS_RIGHTS)
        self.assertEqual(self.connection.result['description'], 'insufficientAccessRights')
        self.assertEqual(self.connection.response, [])

    def test_unsupported_critical_extension_never_returns_service_account_data(self):
        # a critical control the mock DSA does not know must fail the whole request;
        # the test double must not treat every unknown control as success, and the
        # client must never retry the search without the control.
        unknown_critical = build_control('9.9.999.999.1', True, None)
        ok = self.connection.search('o=lab', '(sn=*)', SUBTREE, attributes=['sn'], controls=[unknown_critical])
        self.assertFalse(ok)
        self.assertEqual(self.connection.result['result'], RESULT_UNAVAILABLE_CRITICAL_EXTENSION)
        self.assertEqual(self.connection.result['description'], 'unavailableCriticalExtension')
        # decisive: zero entries, the service account would otherwise see both users
        self.assertEqual(self.connection.response, [])
        self.assertIsNone(self.connection.strategy.last_proxy_authorization_id)
        # the failed request is not retried: a second, still-critical control gets the same rejection
        unknown_critical_2 = build_control('9.9.999.999.2', True, None)
        self.connection.search('o=lab', '(sn=*)', SUBTREE, attributes=['sn'], controls=[unknown_critical_2])
        self.assertEqual(self.connection.result['result'], RESULT_UNAVAILABLE_CRITICAL_EXTENSION)
        self.assertEqual(self.connection.response, [])

    def test_unknown_non_critical_control_is_ignored_but_does_not_change_identity(self):
        unknown_soft = build_control('9.9.999.999.3', False, None)
        ok = self.connection.search('o=lab', '(sn=*)', SUBTREE, attributes=['sn'], controls=[unknown_soft])
        self.assertTrue(ok)
        self.assertEqual(self.connection.result['result'], RESULT_SUCCESS)
        # the non-critical unknown control is ignored and the plain search sees every DIT entry
        self.assertEqual(len(self.connection.response), 3)
        self.assertIsNone(self.connection.strategy.last_proxy_authorization_id)

    def test_failure_is_not_retried_without_the_proxy_control(self):
        send_count = {'value': 0}
        # Connection.send is bound to the strategy at open() time, wrap that reference
        original_send = self.connection.send

        def counting_send(message_type, request, controls=None):
            if message_type == 'searchRequest':
                send_count['value'] += 1
                # every search attempt must carry the proxy control
                self.assertIsNotNone(controls)
                self.assertEqual(parse_proxy_authorization_control(controls[-1])[2], BOB_AUTHZ)
            return original_send(message_type, request, controls)

        self.connection.send = counting_send
        self.connection.strategy.proxy_authorization_allowed = {ALICE_AUTHZ}
        proxied_search(self.connection, BOB_AUTHZ, 'o=lab', '(sn=*)', SUBTREE, attributes=['sn'])
        self.assertEqual(send_count['value'], 1)  # exactly one attempt, no control-less fallback
        self.assertEqual(self.connection.result['result'], RESULT_AUTHORIZATION_DENIED)
        self.assertEqual(self.connection.response, [])

    def test_assertion_helper_rejects_results_without_proxy_control(self):
        # a plain service-account search must never be accepted as a proxied result
        self.connection.search('o=lab', '(sn=*)', SUBTREE, attributes=['sn'])
        self.assertEqual(self.connection.result['result'], RESULT_SUCCESS)
        with self.assertRaises(LDAPExtensionError) as raised:
            assert_proxy_authorization_applied(self.connection)
        self.assertIn('not sent with a proxy authorization control', str(raised.exception))


class TestProxyAuthorizationOnRebind(unittest.TestCase):
    def test_rebind_does_not_reuse_a_previous_identity(self):
        server = Server('mock-proxy-authz-rebind')
        connection = Connection(server, user=SERVICE_ACCOUNT, password='svc-pw', client_strategy=MOCK_SYNC)
        connection.strategy.add_entry(SERVICE_ACCOUNT, {'userPassword': 'svc-pw', 'sn': 'service_account'})
        connection.bind()
        self.assertTrue(connection.bound)
        connection.strategy.add_entry(ALICE, {'userPassword': 'alice-pw', 'sn': 'alice_sn'})
        connection.strategy.add_entry(BOB, {'userPassword': 'bob-pw', 'sn': 'bob_sn'})
        connection.strategy.proxy_authorization_allowed = {ALICE_AUTHZ, BOB_AUTHZ}

        proxied_search(connection, ALICE_AUTHZ, 'o=lab', '(sn=*)', SUBTREE, attributes=['sn'])
        self.assertEqual(connection.strategy.last_proxy_authorization_id, ALICE_AUTHZ)

        # the connection re-binds (e.g. the DSA forced a rebind); the next proxied
        # request must state its own identity again rather than inheriting Alice's
        connection.rebind(user=SERVICE_ACCOUNT, password='svc-pw')
        self.assertTrue(connection.bound)
        proxied_search(connection, BOB_AUTHZ, 'o=lab', '(sn=*)', SUBTREE, attributes=['sn'])
        self.assertEqual(connection.strategy.last_proxy_authorization_id, BOB_AUTHZ)
        self.assertEqual(str(connection.request['controls'][0]['controlType']), PROXY_AUTHORIZATION_OID)
        self.assertEqual(parse_proxy_authorization_control(connection.request['controls'][0]),
                         (PROXY_AUTHORIZATION_OID, True, BOB_AUTHZ))
        connection.unbind()
