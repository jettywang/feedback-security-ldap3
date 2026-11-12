"""
"""

# Created on 2026.11.12
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
# GNU Lesser General Public License for more dectails.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

import unittest
from threading import Event

from ldap3 import Server, Connection, SYNC, ASYNC, AUTO_BIND_NONE, NONE, DIGEST_MD5
from ldap3.core.exceptions import LDAPMessageSizeLimitError
from ldap3.protocol.sasl.digestMd5 import md5_hmac

FRAGMENT_SIZES = [1, 2, 3, 5, 7, 13, 64, 4096]


def _ber_length(size):
    if size < 128:
        return bytes([size])
    octets = size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(octets)]) + octets


def _tlv(tag, content):
    return bytes([tag]) + _ber_length(len(content)) + content


def _ldap_result(application_tag, message_id, result_code=0):
    return _tlv(0x30, _tlv(0x02, bytes([message_id])) + _tlv(application_tag, _tlv(0x0A, bytes([result_code])) + _tlv(0x04, b'') + _tlv(0x04, b'')))


def bind_response(message_id):
    return _ldap_result(0x61, message_id)


def search_done(message_id):
    return _ldap_result(0x65, message_id)


def search_entry(message_id, dn='cn=user1,ou=test,o=lab', attributes=None):
    if attributes is None:
        attributes = {'sn': [b'user1_sn']}
    encoded_attributes = b''
    for attr_type, values in attributes.items():
        encoded_values = b''.join(_tlv(0x04, value) for value in values)
        encoded_attributes += _tlv(0x30, _tlv(0x04, attr_type.encode('utf-8')) + _tlv(0x31, encoded_values))
    entry = _tlv(0x04, dn.encode('utf-8')) + _tlv(0x30, encoded_attributes)
    return _tlv(0x30, _tlv(0x02, bytes([message_id])) + _tlv(0x64, entry))


SASL_KIS = b'0123456789abcdef'


def sasl_packet(message, sec_num):
    """Wrap an LDAP message in a DIGEST-MD5 signed SASL buffer (integrity only)"""
    sec_num_bytes = sec_num.to_bytes(4, 'big')
    signature = bytes.fromhex(md5_hmac(SASL_KIS, sec_num_bytes + message)[0:20])
    buffer = message + signature + b'\x00\x01' + sec_num_bytes
    return len(buffer).to_bytes(4, 'big') + buffer


class PeakRecordingSocket(object):
    """Fake socket that serves a scripted byte stream in fixed-size fragments and
    records the peak of the connection pending (not-yet-complete) receive buffer."""

    def __init__(self, payload, fragment_size, block_at_end=False):
        self.payload = payload
        self.fragment_size = fragment_size
        self.offset = 0
        self.peak_pending = 0
        self.closed = False
        self.block_at_end = block_at_end
        self._release = Event()

    def recv(self, size):
        if self.offset < len(self.payload):
            chunk_size = min(size, self.fragment_size, len(self.payload) - self.offset)
            chunk = self.payload[self.offset:self.offset + chunk_size]
            self.offset += chunk_size
            return chunk
        if self.block_at_end and not self.closed:
            self._release.wait(10)  # emulate an open idle socket until closed
        return b''

    def sendall(self, data):
        pass

    def shutdown(self, *args):
        pass

    def setsockopt(self, *args):
        pass

    def settimeout(self, *args):
        pass

    def close(self):
        self.closed = True
        self._release.set()

    def hook_peak_recording(self, strategy):
        original_check = strategy._check_pending_buffer_size

        def recording_check(pending_size):
            if pending_size > self.peak_pending:
                self.peak_pending = pending_size
            return original_check(pending_size)

        strategy._check_pending_buffer_size = recording_check


def make_sync_connection(payload, fragment_size, max_message_size=None, max_pending_buffer=None):
    server = Server('fake_sync_limits_server', get_info=NONE)
    connection = Connection(server, client_strategy=SYNC, auto_bind=AUTO_BIND_NONE,
                            max_message_size=max_message_size, max_pending_buffer=max_pending_buffer)
    sock = PeakRecordingSocket(payload, fragment_size)
    connection.socket = sock
    connection.closed = False
    connection.listening = True
    connection.strategy._outstanding = dict()
    sock.hook_peak_recording(connection.strategy)
    return connection, sock


def make_async_connection(payload, fragment_size, outstanding=None, max_message_size=None, max_pending_buffer=None, sasl_kis=False):
    server = Server('fake_async_limits_server', get_info=NONE)
    connection = Connection(server, client_strategy=ASYNC, auto_bind=AUTO_BIND_NONE,
                            max_message_size=max_message_size, max_pending_buffer=max_pending_buffer)
    sock = PeakRecordingSocket(payload, fragment_size, block_at_end=True)
    connection.socket = sock
    connection.closed = False
    if sasl_kis:  # must be set before the receiver thread is started
        connection._digest_md5_kis = SASL_KIS
        connection.sasl_mechanism = DIGEST_MD5
    connection.strategy._responses = dict()
    connection.strategy._requests = dict()
    connection.strategy._outstanding = dict(outstanding) if outstanding else dict()
    for message_id in connection.strategy._outstanding:
        connection.strategy._add_event_for_message(message_id)
    sock.hook_peak_recording(connection.strategy)
    connection.strategy._start_listen()
    return connection, sock


def stop_async_connection(connection):
    try:
        connection.strategy.close()
    except Exception:
        pass
    if connection.strategy.receiver is not None:
        connection.strategy.receiver.join(5)


def register_search(connection, message_id):
    connection.strategy._outstanding[message_id] = {'type': 'searchRequest', 'attributes': ['sn']}


def register_bind(connection, message_id):
    connection.strategy._outstanding[message_id] = {'type': 'bindRequest'}


class Test(unittest.TestCase):

    def test_sync_valid_messages_all_fragmentations_peak_bounded(self):
        # same well-formed stream chopped in many fragmentations: delivery is identical and peak buffer stays within the configured limit
        big_entry = search_entry(2, attributes={'sn': [b'x' * 200]})
        payload = big_entry + search_entry(2, dn='cn=user2,ou=test,o=lab') + search_done(2)
        max_pending = len(big_entry) + 10
        for fragment_size in FRAGMENT_SIZES:
            connection, sock = make_sync_connection(payload, fragment_size, max_message_size=1024, max_pending_buffer=max_pending)
            register_search(connection, 2)
            response, result = connection.get_response(2)
            self.assertEqual([r['type'] for r in response], ['searchResEntry', 'searchResEntry'])
            self.assertEqual(response[0]['raw_attributes']['sn'], [b'x' * 200])
            self.assertEqual(response[1]['dn'], 'cn=user2,ou=test,o=lab')
            self.assertEqual(result['type'], 'searchResDone')
            self.assertEqual(result['result'], 0)
            self.assertLessEqual(sock.peak_pending, max_pending, 'fragment size %d' % fragment_size)

    def test_sync_multiple_responses_in_single_read_block(self):
        # several responses for the same message id delivered in a single read block
        payload = search_entry(2) + search_entry(2, dn='cn=user2,ou=test,o=lab') + search_done(2)
        connection, sock = make_sync_connection(payload, len(payload), max_message_size=1024, max_pending_buffer=64)
        register_search(connection, 2)
        response, result = connection.get_response(2)
        self.assertEqual([r['dn'] for r in response], ['cn=user1,ou=test,o=lab', 'cn=user2,ou=test,o=lab'])
        self.assertEqual(result['result'], 0)

    def test_sync_message_exactly_at_limit_is_accepted(self):
        message = search_entry(2, attributes={'sn': [b'x' * 200]})
        payload = message + search_done(2)
        connection, _ = make_sync_connection(payload, 7, max_message_size=len(message))
        register_search(connection, 2)
        response, result = connection.get_response(2)
        self.assertEqual(response[0]['raw_attributes']['sn'], [b'x' * 200])
        self.assertEqual(result['result'], 0)

    def test_sync_message_one_byte_over_limit_is_rejected(self):
        message = search_entry(2, attributes={'sn': [b'x' * 200]})
        payload = message + search_done(2)
        connection, _ = make_sync_connection(payload, 7, max_message_size=len(message) - 1)
        register_search(connection, 2)
        with self.assertRaises(LDAPMessageSizeLimitError):
            connection.get_response(2)
        self.assertTrue(connection.closed)

    def test_sync_declared_huge_length_rejected_before_bytes_arrive(self):
        # declared length of 10 MB trickled one byte at a time: rejected as soon as the length header is complete
        payload = b'\x30\x83\x98\x96\x80' + b'\x02\x01\x02' + b'A' * 100
        connection, sock = make_sync_connection(payload, 1, max_message_size=1024)
        register_search(connection, 2)
        with self.assertRaises(LDAPMessageSizeLimitError):
            connection.get_response(2)
        self.assertLessEqual(sock.offset, 6)
        self.assertTrue(connection.closed)

    def test_sync_slow_drip_bounded_by_pending_buffer_limit(self):
        # declared size is legal but the incomplete buffer may not grow beyond max_pending_buffer
        message = search_entry(2, attributes={'sn': [b'x' * 200]})
        connection, sock = make_sync_connection(message + search_done(2), 8, max_message_size=None, max_pending_buffer=64)
        register_search(connection, 2)
        with self.assertRaises(LDAPMessageSizeLimitError):
            connection.get_response(2)
        self.assertGreater(sock.peak_pending, 64)
        self.assertLessEqual(sock.peak_pending, 64 + 8)  # buffer never grows more than one fragment past the limit
        self.assertTrue(connection.closed)

    def test_sync_overlong_length_encoding_rejected(self):
        # BER long form with 5 length octets is rejected even when no limits are configured
        payload = b'\x30\x85\x00\x00\x00\x00\x0a' + b'\x02\x01\x02' + b'B' * 20
        connection, _ = make_sync_connection(payload, 3)
        register_search(connection, 2)
        with self.assertRaises(LDAPMessageSizeLimitError):
            connection.get_response(2)
        self.assertTrue(connection.closed)

    def test_sync_over_limit_connection_produces_no_post_auth_results(self):
        # a valid bind response followed by an over-limit search entry: bind succeeds, then the
        # connection is terminated and no usable post-authentication query result is produced
        big_entry = search_entry(2, attributes={'sn': [b'x' * 2000]})
        payload = bind_response(1) + big_entry + search_done(2)
        connection, _ = make_sync_connection(payload, 7, max_message_size=1024)
        register_bind(connection, 1)
        register_search(connection, 2)
        _, result_1 = connection.get_response(1)
        self.assertEqual(result_1['result'], 0)  # authentication succeeded before the violation
        with self.assertRaises(LDAPMessageSizeLimitError):
            connection.get_response(2)
        self.assertTrue(connection.closed)
        self.assertFalse(connection.listening)
        self.assertIsNone(connection.response)
        with self.assertRaises(Exception):
            connection.get_response(2)  # the violated connection cannot deliver further results

    def test_sync_limit_violation_does_not_pollute_other_connections(self):
        big_entry = search_entry(2, attributes={'sn': [b'x' * 2000]})
        connection_1, _ = make_sync_connection(big_entry + search_done(2), 7, max_message_size=1024)
        register_search(connection_1, 2)
        connection_2, _ = make_sync_connection(search_entry(2) + search_done(2), 7, max_message_size=1024)
        register_search(connection_2, 2)
        with self.assertRaises(LDAPMessageSizeLimitError):
            connection_1.get_response(2)
        response, result = connection_2.get_response(2)
        self.assertEqual(response[0]['dn'], 'cn=user1,ou=test,o=lab')
        self.assertEqual(result['result'], 0)
        self.assertFalse(connection_2.closed)

    def test_sync_sasl_valid_messages_all_fragmentations(self):
        # DIGEST-MD5 integrity layer: the 4-byte SASL buffer length prefix and the payload
        # are reassembled correctly under every fragmentation
        message_1 = sasl_packet(search_entry(2), 1)
        message_2 = sasl_packet(search_done(2), 2)
        payload = message_1 + message_2
        for fragment_size in FRAGMENT_SIZES:
            connection, sock = make_sync_connection(payload, fragment_size, max_message_size=1024, max_pending_buffer=128)
            connection._digest_md5_kis = SASL_KIS
            connection.sasl_mechanism = DIGEST_MD5
            register_search(connection, 2)
            response, result = connection.get_response(2)
            self.assertEqual([r['type'] for r in response], ['searchResEntry'])
            self.assertEqual(response[0]['dn'], 'cn=user1,ou=test,o=lab')
            self.assertEqual(result['result'], 0)
            self.assertLessEqual(sock.peak_pending, 128, 'fragment size %d' % fragment_size)

    def test_sync_sasl_declared_huge_length_rejected_before_bytes_arrive(self):
        declared_length = 10 * 1024 * 1024
        payload = declared_length.to_bytes(4, 'big') + b'C' * 32
        connection, sock = make_sync_connection(payload, 1, max_message_size=1024)
        connection._digest_md5_kis = SASL_KIS
        connection.sasl_mechanism = DIGEST_MD5
        register_search(connection, 2)
        with self.assertRaises(LDAPMessageSizeLimitError):
            connection.get_response(2)
        self.assertLessEqual(sock.offset, 5)  # rejected as soon as the 4-byte prefix is complete
        self.assertTrue(connection.closed)

    def test_sync_sasl_slow_drip_bounded_by_pending_buffer_limit(self):
        message = sasl_packet(search_entry(2, attributes={'sn': [b'x' * 200]}), 1) + sasl_packet(search_done(2), 2)
        connection, sock = make_sync_connection(message, 8, max_message_size=None, max_pending_buffer=64)
        connection._digest_md5_kis = SASL_KIS
        connection.sasl_mechanism = DIGEST_MD5
        register_search(connection, 2)
        with self.assertRaises(LDAPMessageSizeLimitError):
            connection.get_response(2)
        self.assertGreater(sock.peak_pending, 64)
        self.assertLessEqual(sock.peak_pending, 64 + 8)
        self.assertTrue(connection.closed)

    def test_async_valid_messages_delivered_to_original_message_id(self):
        payload = search_entry(2) + bind_response(1) + search_done(2)  # interleaved message ids in a single stream
        outstanding = {1: {'type': 'bindRequest'}, 2: {'type': 'searchRequest', 'attributes': ['sn']}}
        connection, sock = make_async_connection(payload, len(payload), outstanding=outstanding, max_message_size=1024, max_pending_buffer=64)
        try:
            _, result_1 = connection.get_response(1, timeout=5)
            response_2, result_2 = connection.get_response(2, timeout=5)
            self.assertEqual(result_1['type'], 'bindResponse')
            self.assertEqual(result_1['result'], 0)
            self.assertEqual([r['type'] for r in response_2], ['searchResEntry'])
            self.assertEqual(response_2[0]['dn'], 'cn=user1,ou=test,o=lab')
            self.assertEqual(result_2['result'], 0)
        finally:
            stop_async_connection(connection)

    def test_async_valid_messages_all_fragmentations_peak_bounded(self):
        payload = bind_response(1) + search_entry(2, attributes={'sn': [b'x' * 200]}) + search_done(2)
        largest_message = len(search_entry(2, attributes={'sn': [b'x' * 200]}))
        max_pending = largest_message + 10
        for fragment_size in FRAGMENT_SIZES:
            outstanding = {1: {'type': 'bindRequest'}, 2: {'type': 'searchRequest', 'attributes': ['sn']}}
            connection, sock = make_async_connection(payload, fragment_size, outstanding=outstanding, max_message_size=1024, max_pending_buffer=max_pending)
            try:
                _, result_1 = connection.get_response(1, timeout=5)
                response_2, result_2 = connection.get_response(2, timeout=5)
                self.assertEqual(result_1['result'], 0)
                self.assertEqual(response_2[0]['raw_attributes']['sn'], [b'x' * 200])
                self.assertEqual(result_2['result'], 0)
                self.assertLessEqual(sock.peak_pending, max_pending, 'fragment size %d' % fragment_size)
            finally:
                stop_async_connection(connection)

    def test_async_over_limit_same_rejection_as_sync(self):
        big_entry = search_entry(2, attributes={'sn': [b'x' * 2000]})
        payload = bind_response(1) + big_entry + search_done(2)
        outstanding = {1: {'type': 'bindRequest'}, 2: {'type': 'searchRequest', 'attributes': ['sn']}}
        connection, _ = make_async_connection(payload, 7, outstanding=outstanding, max_message_size=1024)
        try:
            connection.strategy.receiver.join(5)  # the receiver thread terminates the connection on the limit violation
            self.assertTrue(connection.closed)
            with self.assertRaises(LDAPMessageSizeLimitError):  # same rejection reason as the synchronous strategy
                connection.get_response(1, timeout=5)
            with self.assertRaises(LDAPMessageSizeLimitError):
                connection.get_response(2, timeout=5)
        finally:
            stop_async_connection(connection)

    def test_async_slow_drip_bounded_by_pending_buffer_limit(self):
        message = search_entry(2, attributes={'sn': [b'x' * 200]})
        connection, sock = make_async_connection(message + search_done(2), 8, outstanding={2: {'type': 'searchRequest', 'attributes': ['sn']}},
                                                 max_message_size=None, max_pending_buffer=64)
        try:
            connection.strategy.receiver.join(5)
            self.assertGreater(sock.peak_pending, 64)
            self.assertLessEqual(sock.peak_pending, 64 + 8)
            with self.assertRaises(LDAPMessageSizeLimitError):
                connection.get_response(2, timeout=5)
        finally:
            stop_async_connection(connection)

    def test_async_limit_violation_does_not_pollute_other_connections(self):
        big_entry = search_entry(2, attributes={'sn': [b'x' * 2000]})
        connection_1, _ = make_async_connection(big_entry + search_done(2), 7, outstanding={2: {'type': 'searchRequest', 'attributes': ['sn']}}, max_message_size=1024)
        connection_2, _ = make_async_connection(search_entry(2) + search_done(2), 7, outstanding={2: {'type': 'searchRequest', 'attributes': ['sn']}}, max_message_size=1024)
        try:
            connection_1.strategy.receiver.join(5)
            with self.assertRaises(LDAPMessageSizeLimitError):
                connection_1.get_response(2, timeout=5)
            response, result = connection_2.get_response(2, timeout=5)
            self.assertEqual(response[0]['dn'], 'cn=user1,ou=test,o=lab')
            self.assertEqual(result['result'], 0)
            self.assertFalse(connection_2.closed)
        finally:
            stop_async_connection(connection_1)
            stop_async_connection(connection_2)

    def test_async_sasl_valid_messages(self):
        payload = sasl_packet(search_entry(2), 1) + sasl_packet(search_done(2), 2)
        for fragment_size in FRAGMENT_SIZES:
            connection, sock = make_async_connection(payload, fragment_size, outstanding={2: {'type': 'searchRequest', 'attributes': ['sn']}},
                                                     max_message_size=1024, max_pending_buffer=128, sasl_kis=True)
            try:
                response, result = connection.get_response(2, timeout=5)
                self.assertEqual([r['type'] for r in response], ['searchResEntry'])
                self.assertEqual(response[0]['dn'], 'cn=user1,ou=test,o=lab')
                self.assertEqual(result['result'], 0)
                self.assertLessEqual(sock.peak_pending, 128, 'fragment size %d' % fragment_size)
            finally:
                stop_async_connection(connection)

    def test_async_sasl_declared_huge_length_rejected(self):
        declared_length = 10 * 1024 * 1024
        payload = declared_length.to_bytes(4, 'big') + b'C' * 32
        connection, sock = make_async_connection(payload, 1, outstanding={2: {'type': 'searchRequest', 'attributes': ['sn']}}, max_message_size=1024, sasl_kis=True)
        try:
            connection.strategy.receiver.join(5)
            self.assertLessEqual(sock.offset, 5)
            with self.assertRaises(LDAPMessageSizeLimitError):
                connection.get_response(2, timeout=5)
        finally:
            stop_async_connection(connection)


if __name__ == '__main__':
    unittest.main()
