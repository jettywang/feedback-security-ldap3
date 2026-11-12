# -*- coding: utf-8 -*-
"""
Local reproduction of ldap3 Kerberos service-principal (target name) selection.

No domain controller, network or real Kerberos ticket is needed:
  * socket.gethostbyaddr is replaced by a controllable stub
  * gssapi / winkerberos are replaced by fakes that only record the target
  * the SASL LDAP transport is stubbed, so the full bind entry point is driven

Both POSIX (gssapi) and Windows (winkerberos) backends share
_common_determine_target_name(); this script proves both receive the same name.
"""
import importlib
import socket
import sys
import types
import traceback

# ---------------------------------------------------------------------------
# 1. Controllable reverse-DNS stub
# ---------------------------------------------------------------------------
RDNS_MAP = {
    '10.0.0.10': 'ldap-3.internal.example.com',   # PTR exists, different name
    '10.0.0.11': 'alias-result.internal.example.com',
    'fd00::10':   'ldap-v6.internal.example.com',
}
RDNS_CALLS = []


def fake_gethostbyaddr(addr):
    RDNS_CALLS.append(addr)
    if addr in RDNS_MAP:
        return (RDNS_MAP[addr], [], [addr])
    raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')


socket.gethostbyaddr = fake_gethostbyaddr

# ---------------------------------------------------------------------------
# 2. Fake GSSAPI backends (POSIX gssapi / Windows winkerberos)
# ---------------------------------------------------------------------------
CAPTURED = {'posix': [], 'windows': []}


def install_fake_gssapi():
    gss = types.ModuleType('gssapi')

    class FakeName:
        def __init__(self, value, name_type=None):
            self.value = value
            self.name_type = name_type

    class FakeSecurityContext:
        complete = True

        def __init__(self, name=None, mech=None, creds=None, channel_bindings=None):
            CAPTURED['posix'].append(name.value)
            self.name = name

        def step(self, token=None):
            return b'token'

        def unwrap(self, token):
            msg = types.SimpleNamespace(message=bytearray(b'\x01\x00\x00\x00'))
            return msg

        def wrap(self, data, encrypt):
            return types.SimpleNamespace(message=b'wrapped')

    raw = types.ModuleType('gssapi.raw')

    class ChannelBindings:
        def __init__(self, application_data=None):
            self.application_data = application_data

    raw.ChannelBindings = ChannelBindings

    class _Mech:
        kerberos = 'kerberos-mech-oid'

    class _Exceptions(Exception):
        class GSSError(Exception):
            pass

        class MissingContextError(Exception):
            pass

    gss.Name = FakeName
    gss.SecurityContext = FakeSecurityContext
    gss.MechType = _Mech
    gss.NameType = types.SimpleNamespace(hostbased_service='hostbased-service')
    gss.Credentials = lambda **kw: ('creds', kw)
    gss.exceptions = _Exceptions
    gss.raw = raw
    sys.modules['gssapi'] = gss
    sys.modules['gssapi.raw'] = raw


def install_fake_winkerberos():
    wk = types.ModuleType('winkerberos')
    wk.GSS_C_MUTUAL_FLAG = 2
    wk.GSS_C_SEQUENCE_FLAG = 4
    wk.GSS_C_INTEG_FLAG = 16
    wk.GSS_C_CONF_FLAG = 32
    wk.AUTH_GSS_COMPLETE = 1

    class GSSError(Exception):
        pass

    def authGSSClientInit(target_name, gssflags=0):
        CAPTURED['windows'].append(target_name)
        return None, ('ctx', target_name)

    def authGSSClientStep(ctx, token, channel_bindings=None):
        return wk.AUTH_GSS_COMPLETE

    def authGSSClientResponse(ctx):
        # base64 of the 4-byte no-security-layer end token
        import base64 as _b
        return _b.b64encode(b'\x01' + b'\x00' * 3).decode('ascii')

    def authGSSClientUnwrap(ctx, token):
        return None

    def authGSSClientWrap(ctx, data):
        return None

    def channelBindings(application_data=None):
        return ('cb', application_data)

    wk.GSSError = GSSError
    wk.authGSSClientInit = authGSSClientInit
    wk.authGSSClientStep = authGSSClientStep
    wk.authGSSClientResponse = authGSSClientResponse
    wk.authGSSClientUnwrap = authGSSClientUnwrap
    wk.authGSSClientWrap = authGSSClientWrap
    wk.channelBindings = channelBindings
    sys.modules['winkerberos'] = wk


# ---------------------------------------------------------------------------
# 3. Fake connection exercising the real bind entry points
# ---------------------------------------------------------------------------
class FakeSocket:
    def __init__(self, peer_ip):
        self._peer = (peer_ip, 389)

    def getpeername(self):
        return self._peer

    def getpeercert(self, binary_form=False):
        raise ValueError('not an SSL socket')


class FakeServer:
    def __init__(self, host):
        self.host = host


class FakeConnection:
    def __init__(self, server_host, peer_ip, sasl_credentials):
        self.server = FakeServer(server_host)
        self.socket = FakeSocket(peer_ip)
        self.sasl_credentials = sasl_credentials
        self.user = None
        self.cred_store = None
        self.session_security = None
        self.krb_ctx = None
        self.krb_wrap_size_limit = None


def load_kerberos_module(backend):
    for name in list(sys.modules):
        if name.startswith('ldap3.protocol.sasl'):
            del sys.modules[name]
    if backend == 'posix':
        sys.modules.pop('winkerberos', None)
        install_fake_gssapi()
    else:
        sys.modules.pop('gssapi', None)
        sys.modules.pop('gssapi.raw', None)
        install_fake_winkerberos()
    mod = importlib.import_module('ldap3.protocol.sasl.kerberos')
    # stub the LDAP SASL transport so the full bind function runs
    mod.send_sasl_negotiation = lambda connection, controls, token: {'saslCreds': b'\x01\x00\x00\x00'}
    # harness-only shim for an unrelated pre-existing py3 bytes/str comparison bug
    def _patched_end_token(negotiated_token, session_security=None):
        if len(negotiated_token) != 4:
            from ldap3.core.exceptions import LDAPCommunicationError
            raise LDAPCommunicationError("Incorrect response from server")
        return bytearray(b'\x01\x00\x00\x00'), 0
    mod._common_process_end_token_get_security_layers = _patched_end_token
    mod.abort_sasl_negotiation = lambda connection, controls: None
    return mod


# ---------------------------------------------------------------------------
# 4. Test matrix
# ---------------------------------------------------------------------------
from ldap3.core.rdns import ReverseDnsSetting as R

R = importlib.import_module('ldap3.core.rdns').ReverseDnsSetting

# (label, server.host, peer IP, sasl_credentials)
MATRIX = [
    # default / explicit host override / legacy booleans
    ('default (no credentials)',            'ldap.example.com', '10.0.0.10', None),
    ('explicit False (legacy OFF)',         'ldap.example.com', '10.0.0.10', (False,)),
    ('explicit string override',            'ldap.example.com', '10.0.0.10', ('ldap-3.example.com',)),
    ('legacy True (require reverse)',       'ldap.example.com', '10.0.0.10', (True,)),
    # enum members as documented
    ('enum OFF',                            'ldap.example.com', '10.0.0.10', (R.OFF,)),
    ('enum REQUIRE_ALL',                    'ldap.example.com', '10.0.0.10', (R.REQUIRE_RESOLVE_ALL_ADDRESSES,)),
    ('enum REQUIRE_IP_ONLY (host=name)',    'ldap.example.com', '10.0.0.10', (R.REQUIRE_RESOLVE_IP_ADDRESSES_ONLY,)),
    ('enum OPTIONAL_ALL',                   'ldap.example.com', '10.0.0.10', (R.OPTIONAL_RESOLVE_ALL_ADDRESSES,)),
    ('enum OPTIONAL_IP_ONLY (host=name)',   'ldap.example.com', '10.0.0.10', (R.OPTIONAL_RESOLVE_IP_ADDRESSES_ONLY,)),
    # raw integer literals (the values the enum is *documented* to mean)
    ('raw integer 0 (OFF literal)',         'ldap.example.com', '10.0.0.10', (0,)),
    ('raw integer 1 (REQUIRE_ALL literal)', 'ldap.example.com', '10.0.0.10', (1,)),
    ('raw integer 3 (OPTIONAL_ALL literal)','ldap.example.com', '10.0.0.10', (3,)),
    # reverse lookup FAILS
    ('REQUIRE_ALL + PTR failure',           'ldap.example.com', '10.0.0.99', (R.REQUIRE_RESOLVE_ALL_ADDRESSES,)),
    ('legacy True + PTR failure',           'ldap.example.com', '10.0.0.99', (True,)),
    ('OPTIONAL_ALL + PTR failure',          'ldap.example.com', '10.0.0.99', (R.OPTIONAL_RESOLVE_ALL_ADDRESSES,)),
    ('REQUIRE_IP_ONLY + PTR failure',       '10.0.0.99',        '10.0.0.99', (R.REQUIRE_RESOLVE_IP_ADDRESSES_ONLY,)),
    ('OPTIONAL_IP_ONLY + PTR failure',      '10.0.0.99',        '10.0.0.99', (R.OPTIONAL_RESOLVE_IP_ADDRESSES_ONLY,)),
    # IPv4 literal as server host
    ('IPv4 host + REQUIRE_IP_ONLY',         '10.0.0.10',        '10.0.0.10', (R.REQUIRE_RESOLVE_IP_ADDRESSES_ONLY,)),
    ('IPv4 host + OPTIONAL_IP_ONLY',        '10.0.0.10',        '10.0.0.10', (R.OPTIONAL_RESOLVE_IP_ADDRESSES_ONLY,)),
    ('IPv4 host + OFF',                     '10.0.0.10',        '10.0.0.10', (R.OFF,)),
    ('IPv4 host + REQUIRE_ALL',             '10.0.0.10',        '10.0.0.10', (R.REQUIRE_RESOLVE_ALL_ADDRESSES,)),
    # IPv6 literal as server host
    ('IPv6 host + REQUIRE_IP_ONLY',         'fd00::10',         'fd00::10',  (R.REQUIRE_RESOLVE_IP_ADDRESSES_ONLY,)),
    ('IPv6 host + OPTIONAL_IP_ONLY',       'fd00::10',         'fd00::10',  (R.OPTIONAL_RESOLVE_IP_ADDRESSES_ONLY,)),
    ('IPv6 host + OFF',                     'fd00::10',         'fd00::10',  (R.OFF,)),
    ('IPv6 host + REQUIRE_ALL (no PTR)',    'fd00::99',         'fd00::99',  (R.REQUIRE_RESOLVE_ALL_ADDRESSES,)),
    # server "alias": connection name differs from actual peer PTR
    ('alias host + OPTIONAL_ALL',           'ldap-alias.example.com', '10.0.0.11', (R.OPTIONAL_RESOLVE_ALL_ADDRESSES,)),
    ('alias host + REQUIRE_ALL',            'ldap-alias.example.com', '10.0.0.11', (R.REQUIRE_RESOLVE_ALL_ADDRESSES,)),
    ('alias host + OFF',                    'ldap-alias.example.com', '10.0.0.11', (R.OFF,)),
    ('alias host + string override',        'ldap-alias.example.com', '10.0.0.11', ('ldap-3.example.com',)),
]


def run(backend):
    mod = load_kerberos_module(backend)
    entry = mod._posix_sasl_gssapi if backend == 'posix' else mod._windows_sasl_gssapi
    rows = []
    for label, host, peer, creds in MATRIX:
        RDNS_CALLS.clear()
        conn = FakeConnection(host, peer, creds)
        try:
            direct_target = mod._common_determine_target_name(conn)
            entry(conn, None)
            target = CAPTURED[backend][-1]
            assert target == direct_target, (target, direct_target)
            outcome = 'OK'
        except Exception as exc:  # noqa
            target = '-'
            outcome = '%s: %s' % (type(exc).__name__, str(exc).splitlines()[0][:70])
        rows.append((label, host, peer, repr(creds[0] if creds else None),
                     len(RDNS_CALLS), target, outcome))
    return rows


if __name__ == '__main__':
    for backend in ('posix', 'windows'):
        print('=' * 118)
        print('BACKEND: %s' % backend)
        print('=' * 118)
        print('%-38s %-24s %-10s %-45s %-5s %-37s %s' %
              ('case', 'server.host', 'peer', 'sasl_credentials[0]', 'rDNS', 'GSS target name', 'outcome'))
        print('-' * 118)
        for row in run(backend):
            print('%-38s %-24s %-10s %-45s %-5d %-37s %s' % row)
        print()
