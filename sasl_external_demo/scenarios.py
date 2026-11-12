"""Wire-level scenario runner for the SASL EXTERNAL contract.

Each scenario stands up a fresh protocol double, runs the genuine ldap3 client
through the full TLS + EXTERNAL bind + WhoAmI path, and records what every
artifact proves. No external directory and no listening TCP port are required.
"""

import os
import traceback

from protocol_double import ProtocolDouble
from transport_shim import SocketInterceptor
from directory_client import ExternalDirectoryClient, AuthorizationError

HERE = os.path.dirname(os.path.abspath(__file__))
PKI = os.path.join(HERE, 'pki')
HOST = 'ldap.example.test'

SCENARIOS = [
    ('empty_authzid_server_delegation', 'empty_authzid', None),
    ('explicit_authzid_authorized', 'explicit_authorized',
     'dn:cn=alice,ou=people,dc=example,dc=test'),
    ('explicit_authzid_rejected', 'rejected_proxy',
     'dn:cn=bob,ou=people,dc=example,dc=test'),
    ('granted_differs_from_requested', 'different_identity',
     'dn:cn=alice,ou=people,dc=example,dc=test'),
]


def run_one(label, scenario, requested_authzid):
    double = ProtocolDouble(scenario, PKI)
    client_endpoint = double.start()
    record = {
        'label': label,
        'scenario': scenario,
        'requested_authzid': requested_authzid,
        'events': double.events,
        'outcome': None,
        'granted_authzid': None,
        'user_query_attempted': False,
        'user_query_blocked': False,
        'entries_returned': [],
        'error': None,
    }
    client = ExternalDirectoryClient(HOST, PKI, SocketInterceptor(client_endpoint))
    try:
        granted = client.connect_and_bind(requested_authzid)
        record['outcome'] = 'bind_and_identity_confirmed'
        record['granted_authzid'] = granted
        try:
            entries = client.search_users('ou=people,dc=example,dc=test', '(objectClass=person)')
            record['user_query_attempted'] = True
            record['entries_returned'] = [str(entry.entry_dn) for entry in entries]
        except AuthorizationError as exc:
            record['user_query_attempted'] = True
            record['user_query_blocked'] = True
            record['error'] = 'post-gate search: %s' % exc
    except AuthorizationError as exc:
        record['outcome'] = 'authorization_failed'
        record['error'] = str(exc)
        # Prove the application never even attempts a user query after denial:
        # the client raises before search_users is reachable.
        record['user_query_attempted'] = False
        record['user_query_blocked'] = True
    except Exception as exc:  # pragma: no cover - surface unexpected failures
        record['outcome'] = 'unexpected_error'
        record['error'] = '%s: %s' % (type(exc).__name__, exc)
        record['traceback'] = traceback.format_exc()
    finally:
        try:
            client.unbind()
        except Exception:
            pass
        double.join(timeout=3)
    record['server_side_search_count'] = double.searches_attempted
    record['events'] = double.events
    return record


def run_all():
    return [run_one(*spec) for spec in SCENARIOS]


if __name__ == '__main__':
    from report import print_report
    print_report(run_all())
