"""Redirect ldap3's outbound socket to the in-process protocol double.

ldap3's SyncStrategy calls ``socket.socket(...)`` then ``connect((host, port))``.
The sandbox forbids binding/listening on TCP, so the shim hands the client the
socketpair endpoint created by ProtocolDouble instead of a real network socket.
The full ldap3 transport, TLS handshake and BER codec still run unchanged; only
the address family endpoint is substituted.
"""

import socket


class FakeSocketFactory:
    def __init__(self, client_endpoint):
        self._client_endpoint = client_endpoint
        self._handed_out = False

    def __call__(self, *args, **kwargs):
        if not self._handed_out:
            # Hand back the genuine socketpair endpoint (a real SOCK_STREAM fd,
            # so ssl.SSLContext.wrap_socket accepts it), with connect/bind neutered
            # because the pair is already connected in-process.
            self._handed_out = True
            return _ConnectedPairSocket(self._client_endpoint)
        return socket.socket(*args, **kwargs)


class _ConnectedPairSocket(socket.socket):
    """A real socket whose network-establishment calls are no-ops."""

    def __init__(self, endpoint):
        self._endpoint = endpoint
        # Re-parent the live socketpair fd instead of allocating a new one.
        super().__init__(fileno=endpoint.detach())

    def bind(self, address):
        return None

    def connect(self, address):
        return None

    def connect_ex(self, address):
        return 0

    def setsockopt(self, *args):
        return None


class SocketInterceptor:
    def __init__(self, client_endpoint):
        self._factory = FakeSocketFactory(client_endpoint)
        self._original_socket = None
        self._original_getaddrinfo = None

    def _fake_getaddrinfo(self, host, port, *args, **kwargs):
        # Provide a placeholder candidate so ldap3's address resolution succeeds;
        # the connect() call on our adapter is a no-op backed by the socketpair.
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                 '', ('127.0.0.1', port or 636))]

    def __enter__(self):
        self._original_socket = socket.socket
        self._original_getaddrinfo = socket.getaddrinfo
        socket.socket = self._factory
        socket.getaddrinfo = self._fake_getaddrinfo
        return self

    def __exit__(self, exc_type, exc, tb):
        socket.socket = self._original_socket
        socket.getaddrinfo = self._original_getaddrinfo
        return False
