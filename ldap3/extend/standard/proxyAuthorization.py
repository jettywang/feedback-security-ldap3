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

# implements the Proxy Authorization Control as per RFC 4370

from ... import SUBTREE, DEREF_NEVER
from ...core.exceptions import LDAPControlError, LDAPExtensionError
from ...core.results import (RESULT_SUCCESS,
                             RESULT_UNAVAILABLE_CRITICAL_EXTENSION,
                             RESULT_INSUFFICIENT_ACCESS_RIGHTS,
                             RESULT_AUTHORIZATION_DENIED)
from ...protocol.rfc4370 import (PROXY_AUTHORIZATION_OID,
                                 OLD_PROXIED_AUTHORIZATION_OID,
                                 PROXY_AUTHORIZATION_OIDS,
                                 proxy_authorization_control)
from ...utils.log import log, log_enabled, ERROR, BASIC

# result codes that prove the proxy authorization attempt was rejected rather
# than silently downgraded to the bound (service) account
PROXY_AUTHORIZATION_FAILURE_RESULTS = (RESULT_UNAVAILABLE_CRITICAL_EXTENSION,
                                       RESULT_INSUFFICIENT_ACCESS_RIGHTS,
                                       RESULT_AUTHORIZATION_DENIED)


def _fresh_proxy_controls(authorization_id, criticality, oid, extra_controls):
    """Build a brand new controls list for one request.

    The proxy control is always the last element and the list is never shared
    with the caller, so mutating or reusing ``extra_controls`` cannot carry a
    previous user's authorization id into this request.
    """
    if extra_controls is None:
        controls = []
    else:
        controls = list(extra_controls)  # shallow copy, the caller's list is never mutated
    for control in controls:
        control_type = control[0] if not hasattr(control, 'getComponentByName') else str(control.getComponentByName('controlType'))
        if control_type in PROXY_AUTHORIZATION_OIDS:
            raise LDAPControlError('do not pass a proxy authorization control in extra_controls, pass the authorization_id explicitly')
    controls.append(proxy_authorization_control(authorization_id, criticality=criticality, oid=oid))
    return controls


def proxied_search(connection,
                   authorization_id,
                   search_base,
                   search_filter,
                   search_scope=SUBTREE,
                   dereference_aliases=DEREF_NEVER,
                   attributes=None,
                   size_limit=0,
                   time_limit=0,
                   types_only=False,
                   get_operational_attributes=False,
                   controls=None,
                   criticality=True,
                   oid=PROXY_AUTHORIZATION_OID,
                   auto_escape=None):
    """Perform a search strictly under another identity using RFC 4370 proxy authorization.

    The proxy authorization control is built fresh for this call with
    ``criticality`` defaulting to ``True``. The search is sent exactly once: a
    failure is never retried without the control, so the bound service account
    can never be used to answer the query behind the caller's back.

    :param authorization_id: RFC 4513 authzId to impersonate (``dn:...`` /
        ``u:...``) or a bare DN.
    :param criticality: keep ``True`` unless the server explicitly documents a
        reason to mark the control non-critical; a non-critical control can be
        ignored by the server and the request would run as the service account.
    :param controls: additional controls for this request only. A proxy
        authorization control here is rejected to avoid ambiguous identities.
    :returns: the ``Connection.search`` return value. Inspect
        ``connection.result['result']`` / ``['description']`` to distinguish
        ``unavailableCriticalExtension`` (12), ``authorizationDenied`` (123)
        and ``insufficientAccessRights`` (50) from ``success`` (0).
    """
    if not isinstance(criticality, bool):
        raise LDAPControlError('proxy authorization criticality must be a boolean')
    if not criticality and log_enabled(ERROR):
        log(ERROR, 'proxy authorization control for <%s> is non-critical, the server may ignore it and run as the bound account', authorization_id)

    request_controls = _fresh_proxy_controls(authorization_id, criticality, oid, controls)
    if log_enabled(BASIC):
        log(BASIC, 'sending proxied SEARCH as <%s> via <%s>', authorization_id, connection)

    return connection.search(search_base,
                             search_filter,
                             search_scope,
                             dereference_aliases,
                             attributes,
                             size_limit,
                             time_limit,
                             types_only,
                             get_operational_attributes,
                             request_controls,
                             auto_escape=auto_escape)


def assert_proxy_authorization_applied(connection):
    """Raise if the last proxied request did not run under the proxy control.

    Call this after :func:`proxied_search` when the connection uses
    ``raise_exceptions=False``. A successful result is only accepted when the
    request that produced it actually carried the control; every other outcome
    is returned as an :class:`LDAPExtensionError` carrying the server result
    code instead of being treated as an ordinary (possibly service-account)
    search result.
    """
    result = connection.result
    if not result:
        raise LDAPExtensionError('no result available for the proxied request')
    result_code = result.get('result')
    request = connection.request
    request_controls = request.get('controls') if isinstance(request, dict) else None
    has_proxy_control = False
    if request_controls:
        for control in request_controls:
            control_type = control[0] if isinstance(control, (tuple, list)) else str(control.getComponentByName('controlType'))
            if control_type in PROXY_AUTHORIZATION_OIDS:
                has_proxy_control = True
                break
    if not has_proxy_control:
        raise LDAPExtensionError('the request was not sent with a proxy authorization control, refusing to trust the result: ' + str(result.get('description')))
    if result_code in PROXY_AUTHORIZATION_FAILURE_RESULTS:
        raise LDAPExtensionError('proxy authorization rejected by server (%s): %s' % (result.get('description'), result.get('message')))
    if result_code != RESULT_SUCCESS:
        raise LDAPExtensionError('proxied request failed (%s): %s' % (result.get('description'), result.get('message')))
    return result
