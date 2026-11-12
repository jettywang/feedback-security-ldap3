"""
Tests for the DIGEST-MD5 SASL security layer framing (RFC 2831).

The security layer is exercised over an in-memory transport: a sender
protects BER-like messages and the receiver is fed the resulting bytes in
arbitrary chunks.  The tests prove that short reads and coalesced frames do
not affect signature verification or message ownership, and that any
framing, signature or sequence failure terminates the security session
without delivering data taken from a bad frame.
"""

import unittest
from hashlib import md5

from ldap3.core.exceptions import LDAPSignatureVerificationFailedError, LDAPSecurityLayerFrameError, LDAPSecurityLayerSequenceError
from ldap3.protocol.sasl.securityLayer import DigestMd5SecurityLayer, LENGTH_PREFIX_SIZE
from ldap3.utils.config import set_config_parameter, get_config_parameter


def ber_message(content):
    """Wrap content in a valid short-form BER SEQUENCE."""
    return b'\x30' + bytes([len(content)]) + content


FIRST_MESSAGE = ber_message(b'\x02\x01\x01\x65\x06\x04\x00\x04\x00')
SECOND_MESSAGE = ber_message(b'\x02\x01\x02\x65\x07\x04\x05hello')
THIRD_MESSAGE = ber_message(b'\x02\x01\x03\x65\x05\x04\x03end')


class FakeStrategy(object):
    def __init__(self, connection):
        self.connection = connection
        self.closed = False

    def close(self):
        self.closed = True
        self.connection.closed = True


class FakeConnection(object):
    """Minimal connection holding the negotiated DIGEST-MD5 session material."""

    def __init__(self, kis, kic):
        self._digest_md5_kis = kis
        self._digest_md5_kic = kic
        self._digest_md5_kcs_cipher = None
        self._digest_md5_kcc_cipher = None
        self._digest_md5_sec_num = 0
        self.last_error = None
        self.closed = False
        self.strategy = FakeStrategy(self)


def make_layer_pair():
    # The test covers a single protection direction, so sender and receiver
    # share the same signing key (in a real session the server uses kis to
    # sign and the client verifies with that same key).
    signing_key = md5(b'digest-md5 shared signing key').digest()
    sender_connection = FakeConnection(signing_key, signing_key)
    receiver_connection = FakeConnection(signing_key, signing_key)
    sender = DigestMd5SecurityLayer(sender_connection)
    receiver = DigestMd5SecurityLayer(receiver_connection)
    return sender, receiver, sender_connection, receiver_connection


def feed_in_chunks(receiver, blob, chunk_sizes):
    """Feed blob to the receiver using the given sequence of read sizes."""
    delivered = []
    offset = 0
    sizes = list(chunk_sizes)
    while offset < len(blob):
        if not sizes:
            sizes = list(chunk_sizes)
        size = sizes.pop(0)
        chunk = blob[offset:offset + size]
        offset += size
        delivered.extend(receiver.receive(chunk))
    return delivered


class TestDigestMd5SecurityLayer(unittest.TestCase):
    def setUp(self):
        self.max_frame_size = get_config_parameter('SASL_MAX_FRAME_SIZE')

    def tearDown(self):
        set_config_parameter('SASL_MAX_FRAME_SIZE', self.max_frame_size)

    def test_whole_frames_deliver_both_messages(self):
        sender, receiver, _, _ = make_layer_pair()
        first = FIRST_MESSAGE
        second = SECOND_MESSAGE
        stream = sender.protect(first) + sender.protect(second)

        self.assertEqual(receiver.receive(stream), [first, second])

    def test_split_between_length_header_and_body(self):
        sender, receiver, _, _ = make_layer_pair()
        first = FIRST_MESSAGE
        second = SECOND_MESSAGE
        stream = sender.protect(first) + sender.protect(second)

        for cut in range(1, LENGTH_PREFIX_SIZE + 1):
            _, receiver, _, receiver_connection = make_layer_pair()
            delivered = receiver.receive(stream[:cut])
            self.assertEqual(delivered, [])
            delivered += receiver.receive(stream[cut:])
            self.assertEqual(delivered, [first, second])
            self.assertFalse(receiver_connection.closed)

    def test_split_between_body_and_signature(self):
        sender, receiver, _, _ = make_layer_pair()
        first = FIRST_MESSAGE
        second = SECOND_MESSAGE
        frames = [sender.protect(first), sender.protect(second)]
        stream = b''.join(frames)

        # Cut inside the first frame, right before its signature.
        cut = LENGTH_PREFIX_SIZE + len(first)
        delivered = feed_in_chunks(receiver, stream, [cut, 1, 2, 3, 5, 7, 11, 13])
        self.assertEqual(delivered, [first, second])

    def test_split_between_signature_and_sequence_number(self):
        sender, receiver, _, _ = make_layer_pair()
        first = FIRST_MESSAGE
        second = SECOND_MESSAGE
        first_frame = sender.protect(first)
        second_frame = sender.protect(second)

        # Cut between signature and the 0x0001 marker of the first frame.
        frame_length = int.from_bytes(first_frame[:4], 'big')
        cut = LENGTH_PREFIX_SIZE + frame_length - 6
        stream = first_frame + second_frame
        delivered = feed_in_chunks(receiver, stream, [cut, 3, 4, 1, 2, 8, 16])
        self.assertEqual(delivered, [first, second])

    def test_arbitrary_one_byte_reads_match_block_read(self):
        sender, receiver, _, _ = make_layer_pair()
        first = FIRST_MESSAGE
        second = SECOND_MESSAGE
        stream = sender.protect(first) + sender.protect(second)

        delivered = feed_in_chunks(receiver, stream, [1])
        self.assertEqual(delivered, [first, second])

    def test_coalesced_and_partial_frames(self):
        sender, receiver, _, _ = make_layer_pair()
        first = FIRST_MESSAGE
        second = SECOND_MESSAGE
        third = THIRD_MESSAGE
        frames = [sender.protect(first), sender.protect(second), sender.protect(third)]
        stream = b''.join(frames)

        first_cut = len(frames[0]) + 3  # second frame header is split
        delivered = receiver.receive(stream[:first_cut])
        self.assertEqual(delivered, [first])
        delivered += receiver.receive(stream[first_cut:])
        self.assertEqual(delivered, [first, second, third])

    def test_tampered_signature_delivers_nothing_and_terminates(self):
        sender, receiver, _, receiver_connection = make_layer_pair()
        first = FIRST_MESSAGE
        second = SECOND_MESSAGE
        first_frame = bytearray(sender.protect(first))
        second_frame = sender.protect(second)

        # Flip a byte inside the signature region of the first frame.
        tamper_offset = LENGTH_PREFIX_SIZE + len(first) + 3
        first_frame[tamper_offset] ^= 0xFF
        stream = bytes(first_frame) + second_frame

        with self.assertRaises(LDAPSignatureVerificationFailedError):
            feed_in_chunks(receiver, stream, [7, 5, 9, 13])
        self.assertTrue(receiver._closed)
        self.assertTrue(receiver_connection.closed)
        with self.assertRaises(LDAPSecurityLayerFrameError):
            receiver.receive(second_frame)

    def test_tampered_body_delivers_nothing_and_terminates(self):
        sender, receiver, _, receiver_connection = make_layer_pair()
        first = FIRST_MESSAGE
        second = SECOND_MESSAGE
        first_frame = bytearray(sender.protect(first))
        second_frame = sender.protect(second)

        first_frame[LENGTH_PREFIX_SIZE + 2] ^= 0x01  # flip a body byte
        stream = bytes(first_frame) + second_frame

        with self.assertRaises(LDAPSignatureVerificationFailedError):
            receiver.receive(stream)
        self.assertTrue(receiver._closed)
        self.assertTrue(receiver_connection.closed)

    def test_replayed_frame_is_rejected_and_delivers_nothing(self):
        sender, receiver, _, _ = make_layer_pair()
        first = FIRST_MESSAGE
        second = SECOND_MESSAGE
        first_frame = sender.protect(first)
        second_frame = sender.protect(second)

        self.assertEqual(receiver.receive(first_frame + second_frame), [first, second])
        with self.assertRaises(LDAPSecurityLayerSequenceError):
            receiver.receive(first_frame)
        self.assertTrue(receiver._closed)

    def test_duplicate_sequence_in_stream_terminates_session(self):
        sender, receiver, _, receiver_connection = make_layer_pair()
        first = FIRST_MESSAGE
        first_frame = sender.protect(first)

        # The second copy of frame 0 arrives while sequence 1 is expected.
        stream = first_frame + first_frame
        with self.assertRaises(LDAPSecurityLayerSequenceError):
            receiver.receive(stream)
        self.assertTrue(receiver._closed)
        self.assertTrue(receiver_connection.closed)

    def test_out_of_order_sequence_terminates_session(self):
        sender, receiver, _, _ = make_layer_pair()
        first = FIRST_MESSAGE
        second = SECOND_MESSAGE
        sender.protect(first)
        second_frame = sender.protect(second)

        # Sequence 1 arrives before sequence 0.
        with self.assertRaises(LDAPSecurityLayerSequenceError):
            receiver.receive(second_frame)
        self.assertTrue(receiver._closed)

    def test_oversized_frame_terminates_session(self):
        sender, receiver, _, _ = make_layer_pair()
        first = FIRST_MESSAGE
        frame = bytearray(sender.protect(first))
        set_config_parameter('SASL_MAX_FRAME_SIZE', len(frame) - 1)

        with self.assertRaises(LDAPSecurityLayerFrameError):
            receiver.receive(bytes(frame))
        self.assertTrue(receiver._closed)

    def test_invalid_max_frame_size_configuration_rejected(self):
        sender, receiver, _, _ = make_layer_pair()
        set_config_parameter('SASL_MAX_FRAME_SIZE', 4)  # cannot even hold a minimal frame

        # The misconfiguration is refused before any frame is accepted.
        with self.assertRaises(LDAPSecurityLayerFrameError):
            receiver.receive(sender.protect(FIRST_MESSAGE))

    def test_truncated_length_header_waits_then_verifies(self):
        sender, receiver, _, _ = make_layer_pair()
        first = FIRST_MESSAGE
        frame = sender.protect(first)

        self.assertEqual(receiver.receive(frame[:2]), [])
        self.assertFalse(receiver._closed)
        self.assertEqual(receiver.receive(frame[2:]), [first])

    def test_declared_length_smaller_than_minimum_terminates_session(self):
        sender, receiver, _, _ = make_layer_pair()
        first = FIRST_MESSAGE
        frame = bytearray(sender.protect(first))
        frame[:4] = (5).to_bytes(4, 'big')  # smaller than signature + marker + seq

        with self.assertRaises(LDAPSecurityLayerFrameError):
            receiver.receive(bytes(frame))
        self.assertTrue(receiver._closed)

    def test_invalid_padding_marker_terminates_session(self):
        sender, receiver, _, _ = make_layer_pair()
        first = FIRST_MESSAGE
        frame = bytearray(sender.protect(first))
        frame_length = int.from_bytes(frame[:4], 'big')
        marker_offset = LENGTH_PREFIX_SIZE + frame_length - 6
        frame[marker_offset] = 0x02

        with self.assertRaises(LDAPSecurityLayerFrameError):
            receiver.receive(bytes(frame))
        self.assertTrue(receiver._closed)

    def test_send_sequence_exhaustion_terminates_session(self):
        kis = md5(b'kis').digest()
        kic = md5(b'kic').digest()
        connection = FakeConnection(kis, kic)
        sender = DigestMd5SecurityLayer(connection)
        connection._digest_md5_sec_num = 0xFFFFFFFF

        # The last legal sequence number still produces a frame.
        last_frame = sender.protect(b'\x30\x03\x01\x02')
        self.assertEqual(connection._digest_md5_sec_num, 0x100000000)
        self.assertEqual(int.from_bytes(last_frame[-4:], 'big'), 0xFFFFFFFF)

        # The next send has no sequence number left and must terminate.
        with self.assertRaises(LDAPSecurityLayerSequenceError):
            sender.protect(b'\x30\x03\x01\x02')
        self.assertTrue(sender._closed)

    def test_receive_sequence_exhaustion_after_last_valid_frame(self):
        sender, receiver, _, receiver_connection = make_layer_pair()
        first = FIRST_MESSAGE
        second = SECOND_MESSAGE

        # Build frames carrying the final two sequence numbers directly with
        # the sender, so signatures match the rewritten sequence numbers.
        sender_connection = sender.connection
        sender_connection._digest_md5_sec_num = 0xFFFFFFFE
        first_frame = sender.protect(first)
        second_frame = sender.protect(second)
        self.assertEqual(int.from_bytes(first_frame[-4:], 'big'), 0xFFFFFFFE)
        self.assertEqual(int.from_bytes(second_frame[-4:], 'big'), 0xFFFFFFFF)

        receiver._next_receive_sequence = 0xFFFFFFFE
        self.assertEqual(receiver.receive(first_frame), [first])
        # The frame carrying the final sequence number is still valid and is
        # delivered; any further receive then fails because the space is spent.
        self.assertEqual(receiver.receive(second_frame), [second])
        self.assertTrue(receiver._exhausted)
        self.assertFalse(receiver._closed)
        with self.assertRaises(LDAPSecurityLayerSequenceError):
            receiver.receive(b'')
        self.assertTrue(receiver._closed)
        with self.assertRaises(LDAPSecurityLayerFrameError):
            receiver.receive(second_frame)


if __name__ == '__main__':
    unittest.main()
