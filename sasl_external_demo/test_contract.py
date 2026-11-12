"""Contract assertions for the SASL EXTERNAL identity model.

Run with: python -m pytest test_contract.py -v
These use the in-process double, so no directory or listening TCP port is needed.
"""

import ber
from scenarios import run_all, run_one
from report import _event


def _by_label(records, label):
    return next(r for r in records if r['label'] == label)


def test_ber_class_numbers_follow_asn1():
    assert ber.CLASS_UNIVERSAL == 0
    assert ber.CLASS_APPLICATION == 1
    assert ber.CLASS_CONTEXT == 2
    assert ber.CLASS_PRIVATE == 3


def test_empty_authzid_omits_credentials_octet():
    rec = run_one('empty', 'empty_authzid', None)
    bind_req = _event(rec['events'], 'bind_request')
    assert bind_req['mechanism'] == 'EXTERNAL'
    assert bind_req['credentials_present'] is False
    assert bind_req['bind_name_dn'] == ''


def test_explicit_authzid_is_carried_in_credentials():
    rec = run_one('explicit', 'explicit_authorized',
                  'dn:cn=alice,ou=people,dc=example,dc=test')
    bind_req = _event(rec['events'], 'bind_request')
    assert bind_req['credentials_present'] is True
    assert bind_req['requested_authzid'] == 'dn:cn=alice,ou=people,dc=example,dc=test'


def test_certificate_subject_is_never_the_directory_identity():
    records = run_all()
    for rec in records:
        subject = _event(rec['events'], 'tls_client_certificate_subject')
        assert subject is not None
        assert 'svc-connector' in subject
        whoami = _event(rec['events'], 'whoami_response')
        if whoami:
            assert 'svc-connector' not in whoami['authzid']
            assert whoami['authzid'].startswith('dn:cn=')


def test_empty_authzid_allows_server_delegation_and_query():
    rec = _by_label(run_all(), 'empty_authzid_server_delegation')
    assert rec['outcome'] == 'bind_and_identity_confirmed'
    assert rec['granted_authzid'] == \
        'dn:cn=connector-service,ou=service-accounts,dc=example,dc=test'
    assert rec['server_side_search_count'] == 1
    assert rec['entries_returned']


def test_explicit_authorized_identity_is_confirmed_and_queryable():
    rec = _by_label(run_all(), 'explicit_authzid_authorized')
    assert rec['outcome'] == 'bind_and_identity_confirmed'
    assert rec['granted_authzid'] == rec['requested_authzid']
    assert rec['server_side_search_count'] == 1


def test_rejected_proxy_never_reaches_user_query():
    rec = _by_label(run_all(), 'explicit_authzid_rejected')
    bind_resp = _event(rec['events'], 'bind_response')
    assert bind_resp['result_code'] == 123
    assert rec['outcome'] == 'authorization_failed'
    assert rec['granted_authzid'] is None
    assert rec['server_side_search_count'] == 0
    assert rec['user_query_blocked'] is True


def test_granted_identity_mismatch_fails_closed():
    rec = _by_label(run_all(), 'granted_differs_from_requested')
    assert rec['outcome'] == 'authorization_failed'
    assert rec['granted_authzid'] is None  # client refuses to adopt it
    assert rec['server_side_search_count'] == 0
    assert 'does not match requested authzid' in rec['error']


def test_final_identity_always_comes_from_whoami():
    for rec in run_all():
        if rec['outcome'] == 'bind_and_identity_confirmed':
            whoami = _event(rec['events'], 'whoami_response')
            assert whoami is not None
            assert rec['granted_authzid'] == whoami['authzid']
