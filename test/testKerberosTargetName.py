""" Regression tests for Kerberos service-principal (target name) selection.

These tests exercise the POSIX/Windows shared selector
ldap3.protocol.sasl.kerberos._common_determine_target_name with a controllable
reverse-DNS stub and a fake connection, so no gssapi/winkerberos package,
domain controller or ticket is required.
"""

import socket
import unittest
from unittest import mock

from ldap3.core.rdns import ReverseDnsSetting
from ldap3.protocol.sasl import kerberos


class FakeSocket(object):
    def __init__(self, peer_ip):
        self._peer = (peer_ip, 389)

    def getpeername(self):
        return self._peer


class FakeServer(object):
    def __init__(self, host):
        self.host = host


class FakeConnection(object):
    def __init__(self, host, peer_ip, sasl_credentials):
        self.server = FakeServer(host)
        self.socket = FakeSocket(peer_ip)
        self.sasl_credentials = sasl_credentials


PTR = {
    '10.0.0.10': 'ldap-3.internal.example.com',
    '10.0.0.11': 'alias-result.internal.example.com',
    'fd00::10': 'ldap-v6.internal.example.com',
}


def fake_gethostbyaddr(addr):
    if addr in PTR:
        return (PTR[addr], [], [addr])
    raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')


class Test(unittest.TestCase):

    def setUp(self):
        def fake_lookup(addr, success_required=True):
            try:
                return fake_gethostbyaddr(addr)[0]
            except socket.gaierror:
                if success_required:
                    raise
                return None

        self.rdns_patcher = mock.patch('ldap3.protocol.sasl.kerberos.get_hostname_by_addr',
                                       side_effect=fake_lookup)
        self.mock_rdns = self.rdns_patcher.start()
        self.addCleanup(self.rdns_patcher.stop)

    def target(self, host, peer, creds):
        return kerberos._common_determine_target_name(FakeConnection(host, peer, creds))

    # --- identity of the authenticated principal --------------------------------

    def test_default_uses_configured_server_host(self):
        self.assertEqual(self.target('ldap.example.com', '10.0.0.10', None), 'ldap@ldap.example.com')
        self.assertEqual(self.target('ldap.example.com', '10.0.0.10', (False,)), 'ldap@ldap.example.com')
        self.assertEqual(self.target('ldap.example.com', '10.0.0.10', (ReverseDnsSetting.OFF,)),
                         'ldap@ldap.example.com')
        self.assertEqual(self.mock_rdns.call_count, 0)

    def test_explicit_string_override_is_pinned_and_never_resolves(self):
        self.assertEqual(self.target('ldap.example.com', '10.0.0.10', ('ldap-3.example.com',)),
                         'ldap@ldap-3.example.com')
        self.assertEqual(self.mock_rdns.call_count, 0)

    def test_legacy_true_and_require_all_use_ptr_name(self):
        self.assertEqual(self.target('ldap.example.com', '10.0.0.10', (True,)),
                         'ldap@ldap-3.internal.example.com')
        self.assertEqual(self.target('ldap.example.com', '10.0.0.10',
                                     (ReverseDnsSetting.REQUIRE_RESOLVE_ALL_ADDRESSES,)),
                         'ldap@ldap-3.internal.example.com')

    def test_optional_all_silently_switches_principal_when_ptr_answers(self):
        # security-relevant: DNS answer is trusted and changes the target
        self.assertEqual(self.target('ldap-alias.example.com', '10.0.0.11',
                                     (ReverseDnsSetting.OPTIONAL_RESOLVE_ALL_ADDRESSES,)),
                         'ldap@alias-result.internal.example.com')

    def test_ip_only_modes_skip_resolution_for_hostname_servers(self):
        self.assertEqual(self.target('ldap.example.com', '10.0.0.10',
                                     (ReverseDnsSetting.REQUIRE_RESOLVE_IP_ADDRESSES_ONLY,)),
                         'ldap@ldap.example.com')
        self.assertEqual(self.target('ldap.example.com', '10.0.0.10',
                                     (ReverseDnsSetting.OPTIONAL_RESOLVE_IP_ADDRESSES_ONLY,)),
                         'ldap@ldap.example.com')
        self.assertEqual(self.mock_rdns.call_count, 0)

    def test_ip_only_modes_resolve_ipv4_and_ipv6_literal_hosts(self):
        self.assertEqual(self.target('10.0.0.10', '10.0.0.10',
                                     (ReverseDnsSetting.REQUIRE_RESOLVE_IP_ADDRESSES_ONLY,)),
                         'ldap@ldap-3.internal.example.com')
        self.assertEqual(self.target('fd00::10', 'fd00::10',
                                     (ReverseDnsSetting.OPTIONAL_RESOLVE_IP_ADDRESSES_ONLY,)),
                         'ldap@ldap-v6.internal.example.com')

    def test_off_keeps_literal_ip_as_target(self):
        self.assertEqual(self.target('10.0.0.10', '10.0.0.10', (ReverseDnsSetting.OFF,)), 'ldap@10.0.0.10')
        self.assertEqual(self.target('fd00::10', 'fd00::10', (ReverseDnsSetting.OFF,)), 'ldap@fd00::10')

    # --- availability vs. principal-changing fallbacks --------------------------

    def test_required_lookup_failure_is_availability_error(self):
        with self.assertRaises(socket.gaierror):
            self.target('ldap.example.com', '10.0.0.99',
                        (ReverseDnsSetting.REQUIRE_RESOLVE_ALL_ADDRESSES,))
        with self.assertRaises(socket.gaierror):
            self.target('10.0.0.99', '10.0.0.99',
                        (ReverseDnsSetting.REQUIRE_RESOLVE_IP_ADDRESSES_ONLY,))

    def test_optional_lookup_failure_falls_back_to_server_host(self):
        self.assertEqual(self.target('ldap.example.com', '10.0.0.99',
                                     (ReverseDnsSetting.OPTIONAL_RESOLVE_ALL_ADDRESSES,)),
                         'ldap@ldap.example.com')
        self.assertEqual(self.target('10.0.0.99', '10.0.0.99',
                                     (ReverseDnsSetting.OPTIONAL_RESOLVE_IP_ADDRESSES_ONLY,)),
                         'ldap@10.0.0.99')

    # --- documented integer semantics -------------------------------------------

    def test_integer_literals_behave_like_enum_members(self):
        # regression: trailing commas used to make enum members tuples and the
        # documented integer values fell through to string concatenation errors
        self.assertEqual(self.target('ldap.example.com', '10.0.0.10', (0,)), 'ldap@ldap.example.com')
        self.assertEqual(self.target('ldap.example.com', '10.0.0.10', (1,)),
                         'ldap@ldap-3.internal.example.com')
        self.assertEqual(self.target('ldap.example.com', '10.0.0.10', (3,)),
                         'ldap@ldap-3.internal.example.com')
        self.assertIsInstance(ReverseDnsSetting.OFF, int)
        self.assertFalse(ReverseDnsSetting.OFF)


if __name__ == '__main__':
    unittest.main()
