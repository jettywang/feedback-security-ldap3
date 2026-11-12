Proxy Authorization (RFC 4370)
##############################

An SSO gateway usually binds to the LDAP DSA with a single *service account* but must execute searches on
behalf of many end users. The Proxy Authorization Control (OID ``2.16.840.1.113730.3.4.18``, defined in
RFC 4370) lets a bound account request that an operation runs under a different authorization identity
(an RFC 4513 ``authzId``, written as ``dn:<distinguished-name>`` or ``u:<username>``).

The key security property is that the control must be **critical**: if the server does not understand it
and the control is critical, RFC 4511 requires the server to fail the whole request with
``unavailableCriticalExtension`` (result code 12). A non-critical control could instead be silently
ignored, so the operation would execute with the bound service account's privileges. The helpers in
ldap3 default to ``criticality=True`` for exactly this reason.

Building the control
====================

Use :func:`ldap3.protocol.rfc4370.proxy_authorization_control` to build a fresh control for a single
request::

    from ldap3.protocol.rfc4370 import proxy_authorization_control

    control = proxy_authorization_control('dn:cn=alice,ou=people,o=lab')
    # a bare DN is accepted too and qualified automatically:
    control = proxy_authorization_control('cn=alice,ou=people,o=lab')
    # a username authzId is preserved:
    control = proxy_authorization_control('u:alice@example.com')

Every call returns a **new** control object, so you can keep the authorization id and the criticality
bound to one request. Never store a control in a long-lived list and mutate it between requests: the next
request could then be sent with the previous user's identity. The legacy Netscape proxied authorization
control (OID ``2.16.840.1.113730.3.4.12``, value is a bare DN) is available through the ``oid`` parameter.

Pass the resulting control in the ``controls`` argument of any operation::

    conn.search('o=lab', '(sn=*)', controls=[control])

Explicit proxied search wrapper
===============================

For gateway code, :func:`ldap3.extend.standard.proxyAuthorization.proxied_search` makes the intent explicit
and removes the footguns::

    from ldap3.extend.standard.proxyAuthorization import proxied_search

    proxied_search(conn,
                   'dn:cn=alice,ou=people,o=lab',
                   'o=lab',
                   '(owner=alice-only)',
                   attributes=['sn'])

The wrapper:

* builds the proxy authorization control **per call** and appends it to a copy of the ``controls`` list,
  so a list reused across requests never carries one user's identity into the next request;
* rejects a proxy authorization control found inside the caller-supplied ``controls`` to avoid two
  competing identities in the same request;
* sends the search **exactly once** — on failure it never retries without the control, so the service
  account cannot answer the query behind the caller's back;
* keeps the control critical by default and raises ``LDAPControlError`` on an invalid criticality value.

Distinguishing the failure outcomes
===================================

The result codes are kept distinct in ``conn.result`` instead of being collapsed into a generic error:

* ``unavailableCriticalExtension`` (12): the DSA does not know the control (or it was rejected as
  critical). No entries are returned and no control-less retry is performed.
* ``authorizationDenied`` (123): the DSA understood the request but the bound account is not allowed to
  impersonate that authzId.
* ``insufficientAccessRights`` (50): used for an unknown or inaccessible ``dn:`` authzId.
* ``success`` (0): the search ran under the proxied identity.

When the connection is created with ``raise_exceptions=False`` (the default), call
:func:`~ldap3.extend.standard.proxyAuthorization.assert_proxy_authorization_applied` after the search. It
raises ``LDAPExtensionError`` if the last request did not actually carry a proxy control, or if any of the
failure codes above was returned, so a plain service-account result can never be mistaken for a proxied
one::

    from ldap3.extend.standard.proxyAuthorization import assert_proxy_authorization_applied

    assert_proxy_authorization_applied(conn)  # raises unless the proxied request succeeded

Rebinds
=======

A proxy authorization identity is attached to a single request; it never survives a rebind. After
``conn.rebind(...)`` the next search must state its own authzId again. Because ``proxied_search`` builds
the control from the ``authorization_id`` argument on every call, interleaving users on the same
connection is safe: each wire request is independently encoded with its own OID, criticality and
authzId.

Testing with the mock strategy
==============================

The in-memory mock DSA (``MOCK_SYNC`` / ``MOCK_ASYNC``) implements the same semantics:

* the proxy authorization control is recognized and its authzId is recorded on
  ``conn.strategy.last_proxy_authorization_id``;
* ``conn.strategy.proxy_authorization_allowed`` holds the set of authzIds the bound account may
  impersonate. With the default (``None``) every authzId is accepted; set it to a set to exercise the
  ``authorizationDenied`` and ``insufficientAccessRights`` branches;
* an unknown **critical** control still returns ``unavailableCriticalExtension`` with zero entries — the
  mock never treats unknown controls as success, and an unknown *non-critical* control is ignored per
  RFC 4511 without changing the effective identity.

See ``test/testProxyAuthorization.py`` for end-to-end coverage including two users interleaved on one
connection.
