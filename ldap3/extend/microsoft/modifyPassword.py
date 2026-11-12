"""
"""

# Created on 2015.11.27
#
# Author: Giovanni Cannata
#
# Copyright 2015 - 2025 Giovanni Cannata
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

from ... import MODIFY_REPLACE, MODIFY_DELETE, MODIFY_ADD
from ...utils.log import log, log_enabled, PROTOCOL
from ...core.results import RESULT_SUCCESS
from ...core.exceptions import LDAPOperationResult, LDAPPasswordIsMandatoryError
from ...utils.dn import safe_dn
from ...utils.conv import to_unicode
from ..password import PASSWORD_CHANGE, PASSWORD_RESET, PASSWORD_BACKEND_AD, PasswordResult


def _encode_unicode_password(password):
    """Encode a password for the AD unicodePwd attribute.

    AD stores unicodePwd as a UTF-16LE string surrounded by double quotes; any
    Unicode character (including non-ASCII ones) must survive untouched.
    """
    return ('"%s"' % password).encode('utf-16-le')


def _normalize_password(password):
    if isinstance(password, (bytes, bytearray)):
        password = to_unicode(password)
    return to_unicode(password)


def _check_password(password, role):
    if password is None:
        raise LDAPPasswordIsMandatoryError('%s must be supplied' % role)
    password = _normalize_password(password)
    if not password:
        raise LDAPPasswordIsMandatoryError('%s cannot be empty' % role)
    return password


def ad_change_password(connection, user_dn, old_password, new_password, controls=None):
    """Change a user's own password on Active Directory.

    Both passwords are required and the atomic DELETE(old) + ADD(new)
    combination is sent on unicodePwd, as AD expects.  It never falls back to
    an administrative reset.
    """
    if old_password is None:
        raise LDAPPasswordIsMandatoryError('old password must be supplied to change a password')
    old_password = _normalize_password(old_password)  # an empty string is supplied and is sent as such
    new_password = _check_password(new_password, 'new password')

    return _modify_password(connection,
                            user_dn,
                            [(MODIFY_DELETE, [_encode_unicode_password(old_password)]),
                             (MODIFY_ADD, [_encode_unicode_password(new_password)])],
                            controls,
                            PASSWORD_CHANGE)


def ad_reset_password(connection, user_dn, new_password, controls=None):
    """Reset a password on Active Directory with administrative privileges.

    Only the new password is sent, as a MODIFY_REPLACE on unicodePwd.  This is
    an explicitly privileged operation; it is never attempted as a fallback.
    """
    new_password = _check_password(new_password, 'new password')
    return _modify_password(connection,
                            user_dn,
                            [(MODIFY_REPLACE, [_encode_unicode_password(new_password)])],
                            controls,
                            PASSWORD_RESET)


def ad_modify_password(connection, user_dn, new_password, old_password=None, controls=None):
    """Legacy AD password entry point, kept for compatibility.

    A missing old password is no longer interpreted as an administrative
    reset: that would silently escalate a caller that forgot the argument.
    Use ``ad_reset_password`` (or ``reset_password``) to reset explicitly.
    ``None`` and the empty string are not equivalent: an empty string is a
    supplied old password and is sent as part of a change.
    """
    if old_password is None:
        raise LDAPPasswordIsMandatoryError('old password must be supplied to change a password, use reset_password() to reset it')
    return ad_change_password(connection, user_dn, old_password, new_password, controls)


def _modify_password(connection, user_dn, unicode_pwd_changes, controls, operation):
    if connection.check_names:
        user_dn = safe_dn(user_dn)
    result = connection.modify(user_dn,
                               {'unicodePwd': unicode_pwd_changes},
                               controls)

    if connection.strategy.thread_safe:  # thread-safe strategies return (status, result, response, request)
        result = result[1] if isinstance(result, tuple) else result
    elif not connection.strategy.sync:  # asynchronous strategies return the message id
        _, result = connection.get_response(result)
    else:
        result = connection.result

    success = bool(result and result['result'] == RESULT_SUCCESS)

    if not success and connection.raise_exceptions:
        if log_enabled(PROTOCOL):
            log(PROTOCOL, 'operation result <%s> for <%s>', result, connection)
        error = LDAPOperationResult(result=result['result'], description=result['description'], dn=result['dn'], message=result['message'], response_type=result['type'])
        error.operation = operation
        error.backend = PASSWORD_BACKEND_AD
        raise error

    return PasswordResult(operation,
                          PASSWORD_BACKEND_AD,
                          success,
                          result=result,
                          user=user_dn)

