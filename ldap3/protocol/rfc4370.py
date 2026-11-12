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

from pyasn1.type.univ import OctetString

from ..core.exceptions import LDAPControlError
from ..utils.asn1 import decoder
from ..utils.conv import to_raw, to_unicode
from .controls import build_control

# Proxy Authorization Control as per RFC 4370
PROXY_AUTHORIZATION_OID = '2.16.840.1.113730.3.4.18'
# Proxied Authorization Control as per the old Netscape draft (value is an LDAP DN)
OLD_PROXIED_AUTHORIZATION_OID = '2.16.840.1.113730.3.4.12'

PROXY_AUTHORIZATION_OIDS = (PROXY_AUTHORIZATION_OID, OLD_PROXIED_AUTHORIZATION_OID)

# proxyAuthzID ::= OCTET STRING
# (Short for authzId as defined in RFC 4513 section 5.2.1.8)


class ProxyAuthorizationValue(OctetString):
    # proxyAuthzID ::= OCTET STRING  -- an RFC 4513 authzId, "dn:<DN>" or "u:<user>"
    pass


def _normalize_authz_id(oid, authorization_id):
    authz_id = to_unicode(authorization_id)
    if not authz_id or not authz_id.strip():
        raise LDAPControlError('proxy authorization id must be a non-empty authzId string')
    if oid == PROXY_AUTHORIZATION_OID:
        # RFC 4370 section 3: the control value is an authzId (RFC 4513 5.2.1.8),
        # it must carry a "dn:" or "u:" prefix. A bare DN is accepted and qualified.
        if authz_id.startswith('dn:') or authz_id.startswith('u:'):
            return authz_id
        return 'dn:' + authz_id
    # The legacy Netscape control carries a bare LDAP DN in the control value.
    if authz_id.startswith('u:'):
        raise LDAPControlError('the legacy proxied authorization control only accepts a DN, not a user authzId: ' + authz_id)
    if authz_id.startswith('dn:'):
        return authz_id[3:]
    return authz_id


def proxy_authorization_control(authorization_id, criticality=True, oid=PROXY_AUTHORIZATION_OID):
    """Build a Proxy Authorization Control (RFC 4370) bound to a single request.

    A fresh control object is returned on every call so the authorization id
    and the criticality cannot leak into the next request through a reused,
    mutable controls list.

    :param authorization_id: the identity to act as, an RFC 4513 authzId such
        as ``dn:cn=user,ou=people,o=lab`` or ``u:user@example.com``. A bare DN
        is accepted and rewritten to the ``dn:`` form.
    :param criticality: defaults to ``True`` so a server that does not
        understand the control fails with unavailableCriticalExtension instead
        of silently executing the request with the bound (service) account.
    :param oid: the RFC 4370 OID by default, or OLD_PROXIED_AUTHORIZATION_OID
        for the legacy Netscape control.
    """
    if oid not in PROXY_AUTHORIZATION_OIDS:
        raise LDAPControlError('unknown proxy authorization control OID: ' + str(oid))
    if not isinstance(criticality, bool):
        raise LDAPControlError('proxy authorization criticality must be a boolean')

    authz_id = _normalize_authz_id(oid, authorization_id)
    control_value = ProxyAuthorizationValue(to_raw(authz_id))
    return build_control(oid, criticality, control_value)


def parse_proxy_authorization_control(control):
    """Decode a proxy authorization control received on the wire or from a mock.

    Returns a tuple ``(oid, criticality, authorization_id)``. Raises
    LDAPControlError if the control carries no decodable authzId.
    """
    control_type = str(control['controlType'])
    if control_type not in PROXY_AUTHORIZATION_OIDS:
        raise LDAPControlError('not a proxy authorization control: ' + control_type)
    criticality = bool(control['criticality'])
    if control['controlValue'].hasValue():
        decoded_value, _ = decoder.decode(bytes(control['controlValue']), asn1Spec=ProxyAuthorizationValue())
        authz_id = to_unicode(bytes(decoded_value))
    else:
        authz_id = ''
    if not authz_id:
        raise LDAPControlError('proxy authorization control has an empty authorization id')
    return control_type, criticality, authz_id
