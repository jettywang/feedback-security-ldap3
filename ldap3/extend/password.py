"""
"""

# Created on 2026.11.12
#
# Copyright 2025 Giovanni Cannata
#
# This file is part of ldap3.
#
# ldap3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
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

from ..core.exceptions import LDAPPasswordOperationError, LDAPPasswordIsMandatoryError, LDAPException

# password operation intents
PASSWORD_CHANGE = 'change'  # the user supplies the old password
PASSWORD_RESET = 'reset'  # a privileged caller replaces the password

# password backends
PASSWORD_BACKEND_AD = 'AD'
PASSWORD_BACKEND_STANDARD = 'RFC3062'

# AD-exclusive extension OIDs, used only as a positive detection hint
AD_EXTENSION_OIDS = ('1.2.840.113556.1.4.1781',  # Fast concurrent bind
                     '1.2.840.113556.1.4.2212')  # Batch request


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


class PasswordResult(object):
    """Outcome of an explicitly requested password operation.

    ``operation`` is ``'change'`` or ``'reset'`` and ``backend`` is ``'AD'`` or
    ``'RFC3062'``, so a failure always identifies which intent was attempted.
    On success the object is truthy; comparisons with booleans keep the
    historical ``result == True`` idiom working.
    """

    def __init__(self, operation, backend, success, result=None, response=None, user=None, new_password=None):
        self.operation = operation
        self.backend = backend
        self.success = bool(success)
        self.result = result
        self.response = response
        self.user = user
        self.new_password = new_password

    @property
    def failed(self):
        return not self.success

    @property
    def failed_operation(self):
        return self.operation if not self.success else None

    @property
    def result_code(self):
        return self.result['result'] if self.result else None

    @property
    def description(self):
        return self.result['description'] if self.result else None

    @property
    def message(self):
        return self.result['message'] if self.result else None

    @property
    def dn(self):
        return self.result['dn'] if self.result else None

    def __bool__(self):
        return self.success

    __nonzero__ = __bool__  # Python 2

    def __eq__(self, other):
        if isinstance(other, bool):
            return self.success == other
        if isinstance(other, PasswordResult):
            return self.operation == other.operation and self.backend == other.backend and self.success == other.success
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((self.operation, self.backend, self.success))

    def __repr__(self):
        return '<PasswordResult %s/%s %s>' % (self.backend,
                                             self.operation,
                                             'success' if self.success else 'failed (%s)' % (self.description or 'unknown'))


def is_ad_server(connection):
    """Best-effort detection of an Active Directory server.

    Uses vendor information, AD-only extension OIDs and the presence of AD
    schema attributes.  Returns None when the available information does not
    allow a safe decision, so callers can require an explicit backend instead
    of guessing.
    """
    server = getattr(connection, 'server', None)
    if server is None:
        return None
    info = getattr(server, 'info', None)
    if info is not None:
        vendor_name = getattr(info, 'vendor_name', None)
        if vendor_name:
            vendor_name = vendor_name[0] if isinstance(vendor_name, (list, tuple)) and len(vendor_name) == 1 else vendor_name
            if isinstance(vendor_name, str) and 'microsoft' in vendor_name.lower():
                return True
        for extension in _as_list(getattr(info, 'supported_extensions', None)):
            try:
                if extension and extension[0] in AD_EXTENSION_OIDS:
                    return True
            except (IndexError, TypeError):
                pass
    schema = getattr(server, 'schema', None)
    attribute_types = getattr(schema, 'attribute_types', None) if schema is not None else None
    if attribute_types:
        try:
            if 'unicodePwd' in attribute_types:
                return True
            if 'userPassword' in attribute_types:
                return False
        except TypeError:  # schema not queried
            pass
    return None


def resolve_backend(connection, backend=None):
    if backend is not None:
        backend = str(backend).upper()
        if backend in ('AD', 'MICROSOFT', 'ACTIVE_DIRECTORY', 'ACTIVE-DIRECTORY'):
            return PASSWORD_BACKEND_AD
        if backend in ('RFC3062', 'STANDARD', 'LDAP', 'RFC-3062'):
            return PASSWORD_BACKEND_STANDARD
        raise LDAPPasswordOperationError('unknown password backend %s' % backend)
    detected = is_ad_server(connection)
    if detected is None:
        raise LDAPPasswordOperationError('unable to determine password backend, specify the backend explicitly')
    return PASSWORD_BACKEND_AD if detected else PASSWORD_BACKEND_STANDARD


def change_password(connection, user, old_password, new_password=None, backend=None, controls=None, hash_algorithm=None, salt=None):
    """Change a password, requiring the old password to be supplied.

    ``old_password=None`` means "not supplied" and is rejected before any
    request is sent.  An empty string is supplied and is sent as such, so the
    difference is preserved at the protocol level.  No fallback to a reset is
    ever performed.
    """
    if old_password is None:
        raise LDAPPasswordIsMandatoryError('old password must be supplied to change a password')

    resolved = resolve_backend(connection, backend)
    try:
        if resolved == PASSWORD_BACKEND_AD:
            if hash_algorithm is not None:
                raise LDAPPasswordOperationError('hash_algorithm is not supported for AD password operations')
            from .microsoft.modifyPassword import ad_change_password
            return ad_change_password(connection, user, old_password, new_password, controls)

        from .standard.modifyPassword import standard_change_password
        return standard_change_password(connection,
                                        user=user,
                                        old_password=old_password,
                                        new_password=new_password,
                                        hash_algorithm=hash_algorithm,
                                        salt=salt,
                                        controls=controls)
    except LDAPException as error:
        error.operation = PASSWORD_CHANGE
        error.backend = resolved
        raise


def reset_password(connection, user, new_password=None, backend=None, controls=None, hash_algorithm=None, salt=None):
    """Explicitly perform an administrative password reset.

    This is the only operation that omits the old password.  It must be chosen
    by the caller; it is never attempted after a failed change.
    """
    resolved = resolve_backend(connection, backend)
    try:
        if resolved == PASSWORD_BACKEND_AD:
            if hash_algorithm is not None:
                raise LDAPPasswordOperationError('hash_algorithm is not supported for AD password operations')
            from .microsoft.modifyPassword import ad_reset_password
            return ad_reset_password(connection, user, new_password, controls)

        from .standard.modifyPassword import standard_reset_password
        return standard_reset_password(connection,
                                       user=user,
                                       new_password=new_password,
                                       hash_algorithm=hash_algorithm,
                                       salt=salt,
                                       controls=controls)
    except LDAPException as error:
        error.operation = PASSWORD_RESET
        error.backend = resolved
        raise


class PasswordAdapter(object):
    """Backend-neutral explicit password operations for an SSO account service."""

    def __init__(self, connection):
        self._connection = connection

    def change_password(self, user, old_password, new_password=None, backend=None, controls=None, hash_algorithm=None, salt=None):
        return change_password(self._connection,
                               user=user,
                               old_password=old_password,
                               new_password=new_password,
                               backend=backend,
                               controls=controls,
                               hash_algorithm=hash_algorithm,
                               salt=salt)

    def reset_password(self, user, new_password=None, backend=None, controls=None, hash_algorithm=None, salt=None):
        return reset_password(self._connection,
                              user=user,
                              new_password=new_password,
                              backend=backend,
                              controls=controls,
                              hash_algorithm=hash_algorithm,
                              salt=salt)
