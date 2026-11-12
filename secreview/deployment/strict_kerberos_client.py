# -*- coding: utf-8 -*-
"""
Strict ldap3 Kerberos SSO client configuration.

Security rule enforced here:
  The Kerberos service principal is ALWAYS taken from configuration the client
  administrator controls. A DNS PTR answer can never silently change which
  service (and therefore which KDC-issued ticket) is used.

  * Default / ReverseDnsSetting.OFF: target = 'ldap@' + Server(host)
  * Explicit string override:        target = 'ldap@' + pinned name (no DNS)
  * OPTIONAL_* / REQUIRE_* reverse lookup modes are intentionally NOT used:
    they turn an attacker-influenced DNS response into the authenticated
    principal. REQUIRE_* additionally turns a missing PTR record into an
    availability outage (bind raises gaierror).

Run a self-check without any LDAP server / KDC:
    python strict_kerberos_client.py --self-check
"""
import ssl
import sys

from ldap3 import Connection, KERBEROS, SASL, Server, Tls
from ldap3.core.rdns import ReverseDnsSetting
from ldap3.protocol.sasl.kerberos import _common_determine_target_name

# --- deployment-specific configuration ------------------------------------------------
LDAP_HOST = 'ldap.corp.example.com'          # name the client dials (A/AAAA record)
PINNED_SERVICE_HOST = 'ldap.corp.example.com'  # host part of the real ldap/ SPN
USE_SSL = True
# --------------------------------------------------------------------------------------


def build_connection():
    tls = Tls(
        validate=ssl.CERT_REQUIRED,          # never CERT_NONE in production
        version=ssl.PROTOCOL_TLS_CLIENT,
    )
    server = Server(LDAP_HOST, use_ssl=USE_SSL, tls=tls, connect_timeout=5)

    if PINNED_SERVICE_HOST == LDAP_HOST:
        # default path already pins the principal to the configured host;
        # stating OFF documents the intent explicitly and forbids reverse DNS
        sasl_credentials = (ReverseDnsSetting.OFF,)
    else:
        # explicit override: principal is fixed by config, never by DNS
        sasl_credentials = (PINNED_SERVICE_HOST,)

    return Connection(
        server,
        authentication=SASL,
        sasl_mechanism=KERBEROS,
        sasl_credentials=sasl_credentials,
        # optional: enforce confidentiality instead of auth-only SASL
        # session_security=ENCRYPT,
        auto_bind=False,
    )


def _self_check():
    class _Socket:
        def __init__(self, peer):
            self._peer = peer

        def getpeername(self):
            return (self._peer, 636)

    class _Server:
        def __init__(self, host):
            self.host = host

    class _Conn:
        def __init__(self, host, peer, creds):
            self.server = _Server(host)
            self.socket = _Socket(peer)
            self.sasl_credentials = creds

    expected = 'ldap@' + PINNED_SERVICE_HOST
    # even if the peer address and a (possibly poisoned) PTR record differ,
    # the strict config must never resolve a different principal
    for peer in ('10.0.0.10', '10.0.0.99', 'fd00::10'):
        chosen = _common_determine_target_name(_Conn(LDAP_HOST, peer, build_connection().sasl_credentials))
        assert chosen == expected, (peer, chosen, expected)
        print('peer=%s -> %s (OK)' % (peer, chosen))
    print('self-check passed: reverse DNS cannot alter the authenticated principal')


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--self-check':
        _self_check()
    else:
        conn = build_connection()
        conn.open()
        conn.bind()
        print(conn.extend.standard.who_am_i())
        conn.unbind()
