"""Human-readable evidence report for the EXTERNAL contract scenarios."""


def _event(events, name):
    for kind, payload in events:
        if kind == name:
            return payload
    return None


def print_report(records):
    line = '=' * 78
    for rec in records:
        print(line)
        print('SCENARIO: %s' % rec['label'])
        print(line)
        bind_req = _event(rec['events'], 'bind_request')
        bind_resp = _event(rec['events'], 'bind_response')
        tls_subject = _event(rec['events'], 'tls_client_certificate_subject')
        whoami = _event(rec['events'], 'whoami_response')

        print('  requested authzid (client -> bind credentials): %r'
              % rec['requested_authzid'])
        if bind_req:
            print('  wire bindRequest   : mechanism=%s credentials_present=%s '
                  'bind_name_dn=%r'
                  % (bind_req['mechanism'], bind_req['credentials_present'],
                     bind_req['bind_name_dn']))
        print('  TLS cert subject    : %s' % tls_subject)
        if bind_resp:
            print('  wire bindResponse  : result_code=%s granted=%s'
                  % (bind_resp['result_code'], bind_resp['granted']))
            print('                        diagnostic=%s' % bind_resp['diagnostic'])
        if whoami:
            print('  WhoAmI authzid     : %s' % whoami['authzid'])
        print('  client outcome     : %s' % rec['outcome'])
        print('  granted (trusted)  : %s' % rec['granted_authzid'])
        print('  user query reached server: %s (blocked at app: %s)'
              % (rec['server_side_search_count'] > 0, rec['user_query_blocked']))
        if rec.get('entries_returned'):
            print('  entries returned   : %s' % ', '.join(rec['entries_returned']))
        if rec['error']:
            print('  error              : %s' % rec['error'])
        print()

    print(line)
    print('EVIDENCE: WHAT EACH ARTIFACT CAN AND CANNOT PROVE')
    print(line)
    notes = [
        ('TLS client certificate subject',
         'proves the TLS peer holds the certified key (authentication). '
         'It does NOT name a directory account and must never be used as the user.'),
        ('EXTERNAL bindRequest credentials',
         'records only the authzid the client requested (or its absence). '
         'It is a request, not a grant; the server may rewrite or refuse it.'),
        ('bindResponse result code',
         'shows whether the server accepted the authentication and any proxy '
         'request. authorizationDenied(123) means no authorized session exists.'),
        ('WhoAmI (RFC 4532) authzid',
         'the server-confirmed authorization identity actually in force. '
         'This is the sole value the application may treat as the directory user.'),
        ('constraint check in the client',
         'compares granted vs requested. A mismatch fails closed even when the '
         'bind itself returned success, preventing silent identity substitution.'),
        ('server-side search counter',
         'proves a denied/unsigned identity never issues a user query: the gate '
         'blocks before any searchRequest is placed on the wire.'),
    ]
    for title, text in notes:
        print('  - %-34s %s' % (title, text))
    print()
