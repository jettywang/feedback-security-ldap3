"""
DIGEST-MD5 SASL security layer framing (RFC 2831).

After a DIGEST-MD5 bind completes with the "auth-int" (integrity) or
"auth-conf" (confidentiality) quality of protection, every subsequent LDAP
message is carried inside a length-prefixed security layer frame:

    length (4 octets, network byte order)
        length of everything that follows in the frame
    payload (length - 6 octets)
        the BER-encoded LDAP message followed by its 10 octet signature,
        RC4 encrypted when confidentiality is negotiated
    padding marker (2 octets, always 0x0001)
    sequence number (4 octets, network byte order)

The module keeps the receive side stateful so that short reads, frames that
share a single TCP segment and frames split at arbitrary offsets are all
reassembled exactly once.  A bad signature, a duplicate or out-of-order
sequence number, an exhausted sequence number space or an oversized frame
closes the security session: no data taken from a rejected frame is ever
returned as an authenticated LDAP message.
"""

from hmac import compare_digest

from ...utils.config import get_config_parameter
from ...core.exceptions import LDAPSecurityLayerFrameError, LDAPSecurityLayerSequenceError, LDAPSignatureVerificationFailedError
from .digestMd5 import md5_hmac

# Fixed values defined by the DIGEST-MD5 security layer framing (RFC 2831).
LENGTH_PREFIX_SIZE = 4
SEQUENCE_NUMBER_SIZE = 4
PADDING_MARKER_SIZE = 2
PADDING_MARKER = b'\x00\x01'
SIGNATURE_SIZE = 10
# A frame always holds at least a signature, the padding marker and a
# sequence number, even when the wrapped LDAP message is empty.
MIN_FRAME_PAYLOAD_SIZE = SIGNATURE_SIZE + PADDING_MARKER_SIZE + SEQUENCE_NUMBER_SIZE
MAX_SEQUENCE_NUMBER = 0xFFFFFFFF


class DigestMd5SecurityLayer(object):
    """Stateful send/receive machinery for one DIGEST-MD5 security session."""

    def __init__(self, connection):
        self.connection = connection
        self._receive_buffer = b''
        self._frame_length = None
        # The sequence number of the first frame is 0 (RFC 2831).
        self._next_receive_sequence = 0
        self._closed = False
        self._exhausted = False

    @staticmethod
    def _max_frame_size():
        max_frame_size = get_config_parameter('SASL_MAX_FRAME_SIZE')
        if not isinstance(max_frame_size, int) or max_frame_size < LENGTH_PREFIX_SIZE + MIN_FRAME_PAYLOAD_SIZE:
            raise LDAPSecurityLayerFrameError('invalid SASL_MAX_FRAME_SIZE configuration: %r' % max_frame_size)
        return max_frame_size

    def _fail(self, exception):
        """Permanently tear down the security session and raise the error."""
        self._closed = True
        self._receive_buffer = b''
        self._frame_length = None
        self.connection.last_error = str(exception)
        try:
            self.connection.strategy.close()
        except Exception:  # closing must never hide the original security error
            pass
        raise exception

    def protect(self, encoded_message):
        """Wrap a BER-encoded LDAP message in a security layer frame."""
        if self._closed:
            raise LDAPSecurityLayerFrameError('DIGEST-MD5 security session is closed, cannot protect new messages')

        sec_num = self.connection._digest_md5_sec_num
        if sec_num > MAX_SEQUENCE_NUMBER:
            self._fail(LDAPSecurityLayerSequenceError('DIGEST-MD5 send sequence number space exhausted, security session terminated'))

        kic = self.connection._digest_md5_kic
        signature = bytes.fromhex(md5_hmac(kic, sec_num.to_bytes(SEQUENCE_NUMBER_SIZE, 'big') + encoded_message)[0:20])
        payload = encoded_message + signature
        if self.connection._digest_md5_kcc_cipher:
            # RC4 is a stream cipher, so len(ciphertext) == len(plaintext).
            payload = self.connection._digest_md5_kcc_cipher.encrypt(payload)

        frame = (len(payload) + PADDING_MARKER_SIZE + SEQUENCE_NUMBER_SIZE).to_bytes(LENGTH_PREFIX_SIZE, 'big') + \
            payload + PADDING_MARKER + sec_num.to_bytes(SEQUENCE_NUMBER_SIZE, 'big')

        if sec_num == MAX_SEQUENCE_NUMBER:
            # The last legal sequence number has been consumed: no further
            # protected frame can be sent on this session.
            self.connection._digest_md5_sec_num = MAX_SEQUENCE_NUMBER + 1
        else:
            self.connection._digest_md5_sec_num = sec_num + 1
        return frame

    def receive(self, data):
        """Feed raw socket bytes and return every LDAP message that fully verifies.

        Data may contain partial frames, several concatenated frames or any
        mixture of the two.  Returns a list of BER-encoded LDAP messages;
        any framing, signature or sequence failure terminates the security
        session before unauthenticated bytes can be delivered.
        """
        if self._closed:
            raise LDAPSecurityLayerFrameError('DIGEST-MD5 security session is closed, cannot receive new messages')
        if self._exhausted:
            self._fail(LDAPSecurityLayerSequenceError('DIGEST-MD5 receive sequence number space exhausted, security session terminated'))
        if data:
            self._receive_buffer += data

        messages = []
        max_frame_size = self._max_frame_size()
        while True:
            if self._frame_length is None:
                if len(self._receive_buffer) < LENGTH_PREFIX_SIZE:
                    break
                frame_length = int.from_bytes(self._receive_buffer[:LENGTH_PREFIX_SIZE], 'big')
                if frame_length < MIN_FRAME_PAYLOAD_SIZE:
                    self._fail(LDAPSecurityLayerFrameError('DIGEST-MD5 frame length %d is smaller than the minimum frame payload %d' %
                                                           (frame_length, MIN_FRAME_PAYLOAD_SIZE)))
                if frame_length + LENGTH_PREFIX_SIZE > max_frame_size:
                    self._fail(LDAPSecurityLayerFrameError('DIGEST-MD5 frame length %d exceeds the configured maximum frame size %d' %
                                                           (frame_length + LENGTH_PREFIX_SIZE, max_frame_size)))
                self._frame_length = frame_length

            if len(self._receive_buffer) < LENGTH_PREFIX_SIZE + self._frame_length:
                # Wait for the remaining octets of this frame; buffering the
                # prefix makes the result independent of the recv() chunking.
                break

            frame = self._receive_buffer[LENGTH_PREFIX_SIZE:LENGTH_PREFIX_SIZE + self._frame_length]
            self._receive_buffer = self._receive_buffer[LENGTH_PREFIX_SIZE + self._frame_length:]
            frame_length = self._frame_length
            self._frame_length = None
            messages.append(self._verify_frame(frame, frame_length))

        return messages

    def _verify_frame(self, frame, frame_length):
        # Frame layout: payload + 0x0001 + sequence number.
        marker_offset = frame_length - SEQUENCE_NUMBER_SIZE - PADDING_MARKER_SIZE
        padding_marker = frame[marker_offset:marker_offset + PADDING_MARKER_SIZE]
        if padding_marker != PADDING_MARKER:
            self._fail(LDAPSecurityLayerFrameError('invalid DIGEST-MD5 padding marker %s, expected 0001' % padding_marker.hex()))

        sec_num_bytes = frame[frame_length - SEQUENCE_NUMBER_SIZE:]
        sec_num = int.from_bytes(sec_num_bytes, 'big')
        if sec_num != self._next_receive_sequence:
            if sec_num < self._next_receive_sequence:
                reason = 'duplicate or out-of-order'
            else:
                reason = 'out-of-order (sequence gap)'
            self._fail(LDAPSecurityLayerSequenceError('DIGEST-MD5 %s frame sequence number %d, expected %d; security session terminated' %
                                                      (reason, sec_num, self._next_receive_sequence)))

        protected_payload = frame[:marker_offset]
        if self.connection._digest_md5_kcs_cipher:
            protected_payload = self.connection._digest_md5_kcs_cipher.decrypt(protected_payload)

        if len(protected_payload) < SIGNATURE_SIZE:
            self._fail(LDAPSecurityLayerFrameError('DIGEST-MD5 frame payload is too short to contain a signature'))

        encoded_message = protected_payload[:-SIGNATURE_SIZE]
        signature = protected_payload[-SIGNATURE_SIZE:]
        calculated_signature = bytes.fromhex(md5_hmac(self.connection._digest_md5_kis, sec_num_bytes + encoded_message)[0:20])
        if not compare_digest(signature, calculated_signature):
            self._fail(LDAPSignatureVerificationFailedError('Signature verification failed for the received LDAP message number ' +
                                                            str(sec_num) + '. Expected signature ' + calculated_signature.hex() +
                                                            ' but got ' + signature.hex() + '.'))

        # Advance the replay window only after the frame is fully verified,
        # so a bad frame keeps the session on the expected sequence number.
        self._next_receive_sequence = sec_num + 1
        if self._next_receive_sequence > MAX_SEQUENCE_NUMBER:
            # The accepted frame consumed the final legal sequence number.
            # Mark the session exhausted; it is delivered this once, but any
            # further receive is refused instead of wrapping the counter.
            self._exhausted = True
        return encoded_message
