"""Application-side SASL EXTERNAL integration, built on the real ldap3 API.

Identity model (the three names never collapse into one):

  cert_subject      what the local client certificate says. It authenticates the
                    TLS peer to the server but is NOT, by itself, a directory user.
  requested_authzid the authorization identity asked for in the EXTERNAL bind
                    credentials; empty/absent means "let the server decide".
  granted_authzid   the authorization identity actually in force after bind,
                    taken from the server's WhoAmI response (RFC 4532).

The application only ever trusts granted_authzid, and only after checking it
against the requested constraint. No user query runs unless that gate passes.
"""

import ssl

from ldap3 import Connection, Server, Tls, SASL, EXTERNAL, ALL, SUBTREE
from ldap3.core.results import RESULT_SUCCESS, RESULT_AUTHORIZATION_DENIED
from ldap3.core.exceptions import LDAPOperationResult, LDAPExceptionError

WHOAMI_OID = '1.3.6.1.4.1.4203.1.11.3'


class AuthorizationError(Exception):
    """Raised when the granted identity cannot be trusted for the request."""


class ExternalDirectoryClient:
    def __init__(self, host, pki_dir, socket_interceptor=None):
        self.host = host
        self.pki_dir = pki_dir
        self._interceptor = socket_interceptor
        self.connection = None
        self.cert_subject = None
        self.requested_authzid = None
        self.granted_authzid = None

    def _build_tls(self):
        # Client proves possession of its private key; server validates the chain.
        # CERT_REQUIRED means the client also verifies the server certificate.
        return Tls(
            local_certificate_file=self.pki_dir + '/client.crt',
            local_private_key_file=self.pki_dir + '/client.key',
            ca_certs_file=self.pki_dir + '/ca.crt',
            validate=ssl.CERT_REQUIRED,
            valid_names=['ldap.example.test'],
        )

    def connect_and_bind(self, requested_authzid=None):
        """Perform an EXTERNAL bind. requested_authzid=None sends no credentials
        octet (empty authzid, server-side delegation). A string is sent verbatim."""
        tls = self._build_tls()
        server = Server(self.host, port=636, use_ssl=True, tls=tls, get_info=ALL)

        # ldap3 passes sasl_credentials straight through as the EXTERNAL credentials
        # octet (see protocol/sasl/external.py -> send_sasl_negotiation). None means
        # the optional credentials field is omitted entirely.
        credentials = None if requested_authzid is None else requested_authzid
        self.requested_authzid = requested_authzid

        if self._interceptor is not None:
            with self._interceptor:
                self.connection = Connection(
                    server, authentication=SASL, sasl_mechanism=EXTERNAL,
                    sasl_credentials=credentials, auto_bind=False,
                    raise_exceptions=True, receive_timeout=10)
                self.connection.open(read_server_info=False)
                self._bind()
        else:
            self.connection = Connection(
                server, authentication=SASL, sasl_mechanism=EXTERNAL,
                sasl_credentials=credentials, auto_bind=False,
                raise_exceptions=True, receive_timeout=10)
            self.connection.open(read_server_info=False)
            self._bind()

        # The local cert subject is evidence for the TLS layer only. Record it,
        # but do not treat it as the directory identity.
        self.cert_subject = self._local_cert_subject()
        self.granted_authzid = self._confirm_identity_with_whoami()
        self._enforce_authorization_constraint()
        return self.granted_authzid

    def _bind(self):
        try:
            ok = self.connection.bind(read_server_info=False)
        except LDAPOperationResult as exc:
            # raise_exceptions=True surfaces result codes (e.g. authorizationDenied
            # 123) as exceptions. Normalize them so callers handle one type.
            raise AuthorizationError(
                'EXTERNAL bind rejected: %s' % exc.description
                if hasattr(exc, 'description') else str(exc))
        if not ok:
            result = self.connection.result or {}
            raise AuthorizationError(
                'EXTERNAL bind rejected: result=%s message=%s'
                % (result.get('description'), result.get('message')))

    def _local_cert_subject(self):
        # Read purely for logging/evidence; never used as an authorization input.
        der = self.connection.server.tls.peer_certificate
        if not der:
            return None
        return 'DER(%d bytes); subject is server-side authenticated, not a local claim' % len(der)

    def _confirm_identity_with_whoami(self):
        """Ask the server who the connection is authorized as. This is the only
        source of the final identity the application is allowed to use."""
        try:
            authzid = self.connection.extend.standard.who_am_i()
        except LDAPExceptionError as exc:
            raise AuthorizationError('WhoAmI failed: %s' % exc)
        if not authzid:
            raise AuthorizationError('WhoAmI returned an empty authorization identity')
        return authzid

    def _enforce_authorization_constraint(self):
        if self.requested_authzid is None:
            # Empty authzid: the server's delegation choice is acceptable, but it
            # must still be a concrete, non-anonymous identity.
            if not self.granted_authzid.startswith('dn:'):
                raise AuthorizationError(
                    'delegated identity is not a directory DN: %r' % self.granted_authzid)
            return
        if self.granted_authzid != self.requested_authzid:
            raise AuthorizationError(
                'granted identity %r does not match requested authzid %r'
                % (self.granted_authzid, self.requested_authzid))

    def search_users(self, search_base, search_filter, attributes=None):
        """User-query gate. Refuses to touch the directory unless the identity
        gate has passed, so a failed/denied bind can never reach a user query."""
        if self.connection is None or not self.connection.bound:
            raise AuthorizationError('no authorized session; user query blocked')
        if self.granted_authzid is None:
            raise AuthorizationError('identity not confirmed by WhoAmI; user query blocked')
        ok = self.connection.search(
            search_base, search_filter, search_scope=SUBTREE,
            attributes=attributes or ['cn', 'uid'])
        if not ok:
            result = self.connection.result or {}
            raise AuthorizationError(
                'search failed: result=%s message=%s'
                % (result.get('description'), result.get('message')))
        return self.connection.entries

    def unbind(self):
        if self.connection is not None:
            self.connection.unbind()
            self.connection = None


def describe_result_code(code):
    mapping = {
        RESULT_SUCCESS: 'success - authorization granted',
        RESULT_AUTHORIZATION_DENIED: 'authorizationDenied - proxy not allowed',
    }
    return mapping.get(code, 'result code %s' % code)
