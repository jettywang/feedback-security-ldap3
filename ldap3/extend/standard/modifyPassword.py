"""
"""

# Created on 2014.04.30
#
# Author: Giovanni Cannata
#
# Copyright 2014 - 2025 Giovanni Cannata
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

from ... import HASHED_NONE
from ...extend.operation import ExtendedOperation
from ...extend.password import PASSWORD_CHANGE, PASSWORD_RESET, PASSWORD_BACKEND_STANDARD, PasswordResult
from ...protocol.rfc3062 import PasswdModifyRequestValue, PasswdModifyResponseValue
from ...utils.hashed import hashed
from ...protocol.sasl.sasl import validate_simple_password
from ...utils.dn import safe_dn
from ...core.results import RESULT_SUCCESS
from ...core.exceptions import LDAPPasswordIsMandatoryError, LDAPException

# implements RFC3062


def _validate_password(value):
    """SASLprep and UTF-8 encode a password unless it already is raw bytes."""
    if isinstance(value, bytes):  # bytes are returned raw, as per RFC (4.2)
        return value
    return validate_simple_password(value, True)


class ModifyPassword(ExtendedOperation):
    def config(self):
        self.request_name = '1.3.6.1.4.1.4203.1.11.1'
        self.request_value = PasswdModifyRequestValue()
        self.asn1_spec = PasswdModifyResponseValue()
        self.response_attribute = 'new_password'

    def __init__(self, connection, user=None, old_password=None, new_password=None, hash_algorithm=None, salt=None, controls=None):
        ExtendedOperation.__init__(self, connection, controls)  # calls super __init__()
        if user:
            if connection.check_names:
                user = safe_dn(user)
            self.request_value['userIdentity'] = user
        if old_password is not None:  # an empty old password is still a supplied (and therefore invalid) old password
            self.request_value['oldPasswd'] = _validate_password(old_password)
        if new_password is not None:
            new_password = _validate_password(new_password)
            if hash_algorithm is None or hash_algorithm == HASHED_NONE:
                self.request_value['newPasswd'] = new_password
            else:
                self.request_value['newPasswd'] = hashed(hash_algorithm, new_password, salt)

    def populate_result(self):
        try:
            self.result[self.response_attribute] = str(self.decoded_response['genPasswd'])
        except TypeError:  # optional field can be absent (or response failed to decode), so returns True if operation is successful else False
            if self.result['result'] == RESULT_SUCCESS:
                self.result[self.response_attribute] = True
            else:  # change was not successful, raises exception if raise_exception = True in connection or returns the operation result, error code is in result['result']
                self.result[self.response_attribute] = False
                if self.connection.raise_exceptions:
                    from ...core.exceptions import LDAPOperationResult
                    raise LDAPOperationResult(result=self.result['result'], description=self.result['description'], dn=self.result['dn'], message=self.result['message'], response_type=self.result['type'])


def _operation_result(operation, intent):
    result = operation.result
    success = bool(result and result['result'] == RESULT_SUCCESS)
    generated = result.get('new_password') if result and 'new_password' in result else None
    return PasswordResult(intent,
                          PASSWORD_BACKEND_STANDARD,
                          success,
                          result=result,
                          new_password=generated if isinstance(generated, str) else None)


def standard_change_password(connection, user, old_password, new_password=None, hash_algorithm=None, salt=None, controls=None):
    """Change a password (or let the server generate one) via RFC3062.

    The old password must be explicitly supplied, even as an empty string;
    omitting it (``None``) is rejected instead of becoming a privileged
    password-set.  A failed change is returned as a result and is never retried
    as a reset.
    """
    if old_password is None:
        raise LDAPPasswordIsMandatoryError('old password must be supplied to change a password')
    operation = ModifyPassword(connection,
                               user=user,
                               old_password=old_password,
                               new_password=new_password,
                               hash_algorithm=hash_algorithm,
                               salt=salt,
                               controls=controls)
    try:
        operation.send()
    except LDAPException as error:
        error.operation = PASSWORD_CHANGE
        error.backend = PASSWORD_BACKEND_STANDARD
        raise
    return _operation_result(operation, PASSWORD_CHANGE)


def standard_reset_password(connection, user, new_password=None, hash_algorithm=None, salt=None, controls=None):
    """Set a password via RFC3062 without an old password.

    This is the explicit administrative operation; callers must opt in and the
    library never chooses it as a fallback for a failed change.
    """
    operation = ModifyPassword(connection,
                               user=user,
                               old_password=None,
                               new_password=new_password,
                               hash_algorithm=hash_algorithm,
                               salt=salt,
                               controls=controls)
    try:
        operation.send()
    except LDAPException as error:
        error.operation = PASSWORD_RESET
        error.backend = PASSWORD_BACKEND_STANDARD
        raise
    return _operation_result(operation, PASSWORD_RESET)
