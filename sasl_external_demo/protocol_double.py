"""In-process LDAP protocol double for SASL EXTERNAL contract tests.

It speaks enough RFC 4511/RFC 4513/RFC 4532 over a real TLS session to drive the
genuine ldap3 client stack, but no TCP port is opened and no directory exists.
The double deliberately keeps three names separate:

  * certificate identity  - subject of the client certificate from the TLS layer
  * requested authzid     - credentials octets of the SASL EXTERNAL bind
  * granted identity      - what the server authorizes, revealed by WhoAmI
"""

import socket
import ssl
import threading

import ber

WHOAMI_OID = '1.3.6.1.4.1.4203.1.11.3'

RESULT_SUCCESS = 0
RESULT_PROTOCOL_ERROR = 2
RESULT_AUTH_METHOD_NOT_SUPPORTED = 7
RESULT_INVALID_CREDENTIALS = 49
RESULT_INSUFFICIENT_ACCESS_RIGHTS = 50
RESULT_UNWILLING_TO_PERFORM = 53
RESULT_AUTHORIZATION_DENIED = 123

OP_BIND_REQUEST = 0
OP_UNBIND_REQUEST = 2
OP_SEARCH_REQUEST = 3
OP_EXTENDED_REQUEST = 23


class ScriptedDirectory:
    """Server-side authorization policy and the only place a DN is minted."""

    def __init__(self, scenario):
        self.scenario = scenario
        # The certificate maps, via server-side provisioning, to this bind account.
        # It is intentionally different from the certificate subject CN/UID.
        self.certificate_account = 'cn=connector-service,ou=service-accounts,dc=example,dc=test'
        self.allowed_proxy_targets = {
            'dn:cn=alice,ou=people,dc=example,dc=test': 'dn:cn=alice,ou=people,dc=example,dc=test',
        }

    def external_bind(self, tls_subject, requested_authzid, has_credentials):
        """Return (result_code, diagnostic, granted_authzid_or_None)."""
        if tls_subject is None:
            return (RESULT_UNWILLING_TO_PERFORM,
                    'EXTERNAL requires a verified client certificate', None)

        if self.scenario == 'rejected_proxy':
            # Server refuses to act on the requested authorization identity.
            return (RESULT_AUTHORIZATION_DENIED,
                    'client is not authorized to assume %s' % requested_authzid, None)

        if not has_credentials:
            # Empty/absent authzid: server performs normal delegation selection
            # (RFC 4513 5.2.1.2) using the certificate-derived account.
            return (RESULT_SUCCESS,
                    'normal delegation: server-derived identity from certificate',
                    'dn:' + self.certificate_account)

        granted = self.allowed_proxy_targets.get(requested_authzid)
        if granted is None:
            return (RESULT_AUTHORIZATION_DENIED,
                    'requested authzid is not in the proxy ACL', None)

        if self.scenario == 'different_identity':
            # Bind succeeds but the granted identity differs from what was asked.
            # A careful client must detect this via WhoAmI rather than assume it.
            granted = 'dn:cn=connector-service,ou=service-accounts,dc=example,dc=test'
        return (RESULT_SUCCESS, 'proxy authorized', granted)


def _ldap_result(result_code, matched_dn, diagnostic):
    return (ber.enumerated(result_code)
            + ber.octet_string(matched_dn)
            + ber.octet_string(diagnostic))


def _bind_response(message_id, result_code, diagnostic):
    body = _ldap_result(result_code, '', diagnostic)
    return ber.frame(message_id, ber.application_tag(1, body, constructed=True))


def _extended_response(message_id, result_code, diagnostic, oid, value):
    body = _ldap_result(result_code, '', diagnostic)
    if oid is not None:
        body += ber.context_tag(10, ber.octet_string(oid))
    if value is not None:
        # responseValue [11] carries the raw value octets as its content, not a
        # nested OCTET STRING TLV (RFC 4511 ExtendedResponse).
        body += ber.context_tag(11, value if isinstance(value, bytes)
                                else value.encode('utf-8'))
    return ber.frame(message_id, ber.application_tag(24, body, constructed=True))


def _search_done(message_id, result_code, diagnostic):
    return ber.frame(message_id, ber.application_tag(5,
                     _ldap_result(result_code, '', diagnostic), constructed=True))


def _partial_attribute(attr_type, values):
    vals = b''.join(ber.octet_string(v) for v in values)
    return ber.seq(ber.octet_string(attr_type) + ber.tlv(0x31, vals))


def _search_result_entry(message_id, object_dn, attributes):
    attr_list = b''.join(_partial_attribute(name, vals) for name, vals in attributes)
    body = ber.octet_string(object_dn) + ber.seq(attr_list)
    return ber.frame(message_id, ber.application_tag(4, body, constructed=True))


def _read_ldap_message(tls_conn):
    """Read one BER length-framed LDAP message across the TLS socket."""
    header = _recv_exactly(tls_conn, 2)
    if header[0] != 0x30:
        raise ValueError('expected SEQUENCE tag, got %02x' % header[0])
    first_len = header[1]
    if first_len < 0x80:
        size = first_len
        rest = b''
    else:
        nbytes = first_len & 0x7F
        rest = _recv_exactly(tls_conn, nbytes)
        size = int.from_bytes(rest, 'big')
    payload = _recv_exactly(tls_conn, size)
    return bytes(header) + rest + payload


def _recv_exactly(sock, n):
    chunks = []
    remaining = n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError('peer closed mid-message')
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def _subject_dn(peercert):
    if not peercert:
        return None
    parts = []
    for rdn in peercert.get('subject', ()):
        parts.append('='.join(rdn[0]))
    return '/'.join(parts)


class ProtocolDouble:
    def __init__(self, scenario, pki_dir):
        self.scenario = scenario
        self.pki_dir = pki_dir
        self.directory = ScriptedDirectory(scenario)
        self.events = []
        self.searches_attempted = 0
        self._client_end = None
        self._server_end = None
        self._thread = None
        self.granted_identity = None
        self.bound = False

    def start(self):
        self._client_end, self._server_end = socket.socketpair()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self._client_end

    def _wrap_server_socket(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.pki_dir + '/server.crt', self.pki_dir + '/server.key')
        ctx.load_verify_locations(self.pki_dir + '/ca.crt')
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx.wrap_socket(self._server_end, server_side=True)

    def _serve(self):
        try:
            tls_conn = self._wrap_server_socket()
        except ssl.SSLError as exc:
            self.events.append(('tls_handshake_failed', str(exc)))
            return
        try:
            self._loop(tls_conn)
        except (ConnectionError, OSError) as exc:
            self.events.append(('transport_closed', str(exc)))
        finally:
            try:
                tls_conn.close()
            except OSError:
                pass

    def _loop(self, tls_conn):
        peercert = tls_conn.getpeercert()
        tls_subject = _subject_dn(peercert)
        self.events.append(('tls_client_certificate_subject', tls_subject))
        while True:
            try:
                wire = _read_ldap_message(tls_conn)
            except (ConnectionError, OSError):
                return
            message_id, op, _ = ber.parse_message(wire)
            if op.number == OP_UNBIND_REQUEST:
                self.events.append(('unbind', message_id))
                return
            if op.number == OP_BIND_REQUEST:
                self._handle_bind(tls_conn, message_id, op, tls_subject)
            elif op.number == OP_EXTENDED_REQUEST:
                self._handle_extended(tls_conn, message_id, op)
            elif op.number == OP_SEARCH_REQUEST:
                self._handle_search(tls_conn, message_id, op)
            else:
                tls_conn.sendall(_bind_response(message_id, RESULT_PROTOCOL_ERROR,
                                                'unsupported operation in double'))

    def _handle_bind(self, tls_conn, message_id, op, tls_subject):
        version, bind_name, auth_choice = op.children()
        if auth_choice.cls != ber.CLASS_CONTEXT or auth_choice.number != 3:
            tls_conn.sendall(_bind_response(message_id, RESULT_AUTH_METHOD_NOT_SUPPORTED,
                                            'only SASL EXTERNAL is supported by this double'))
            return
        sasl_parts = auth_choice.children()
        mechanism = sasl_parts[0].text()
        has_credentials = len(sasl_parts) > 1
        requested_authzid = sasl_parts[1].text() if has_credentials else ''
        self.events.append(('bind_request', {
            'version': version.integer_value(),
            'bind_name_dn': bind_name.text(),
            'mechanism': mechanism,
            'requested_authzid': requested_authzid,
            'credentials_present': has_credentials,
        }))
        if mechanism != 'EXTERNAL':
            tls_conn.sendall(_bind_response(message_id, RESULT_AUTH_METHOD_NOT_SUPPORTED,
                                            'mechanism %s not supported' % mechanism))
            return
        code, diagnostic, granted = self.directory.external_bind(
            tls_subject, requested_authzid, has_credentials)
        self.events.append(('bind_response', {
            'result_code': code, 'diagnostic': diagnostic, 'granted': granted}))
        tls_conn.sendall(_bind_response(message_id, code, diagnostic))
        if code == RESULT_SUCCESS:
            self.bound = True
            self.granted_identity = granted

    def _handle_extended(self, tls_conn, message_id, op):
        name_elem = op.child(0)
        oid = name_elem.text() if name_elem else ''
        self.events.append(('extended_request', {'oid': oid}))
        if oid != WHOAMI_OID:
            tls_conn.sendall(_extended_response(message_id, RESULT_UNWILLING_TO_PERFORM,
                                                'extension not supported', None, None))
            return
        if not self.bound:
            tls_conn.sendall(_extended_response(message_id, RESULT_INSUFFICIENT_ACCESS_RIGHTS,
                                                'not bound', oid, b''))
            return
        value = self.granted_identity.encode('utf-8')
        self.events.append(('whoami_response', {'authzid': self.granted_identity}))
        tls_conn.sendall(_extended_response(message_id, RESULT_SUCCESS, '', oid, value))

    def _handle_search(self, tls_conn, message_id, op):
        self.searches_attempted += 1
        self.events.append(('search_request', {'bound': self.bound}))
        if not self.bound:
            tls_conn.sendall(_search_done(message_id, RESULT_INSUFFICIENT_ACCESS_RIGHTS,
                                          'refusing user query before authorization'))
            return
        # The entry is returned under the server-confirmed granted identity, never
        # derived from the certificate subject. The double stores no full directory.
        granted_dn = self.granted_identity[3:] if self.granted_identity.startswith('dn:') else self.granted_identity
        attributes = [
            ('objectClass', ['top', 'person']),
            ('cn', [granted_dn.split(',')[0].replace('cn=', '')]),
            ('authorizedAs', [self.granted_identity]),
        ]
        tls_conn.sendall(_search_result_entry(message_id, granted_dn, attributes))
        self.events.append(('search_entry_returned', {'dn': granted_dn}))
        tls_conn.sendall(_search_done(message_id, RESULT_SUCCESS, ''))

    def join(self, timeout=5):
        self._thread.join(timeout)
