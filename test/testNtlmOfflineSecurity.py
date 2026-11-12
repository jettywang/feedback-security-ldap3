"""
"""

# Offline security regression tests for ldap3 NTLMv2 authentication.
#
# These tests feed crafted, untrusted NTLM CHALLENGE_MESSAGE byte strings
# through the real call chain used by Connection.do_ntlm_bind():
#
#     bind_operation(version, 'SICILY_NEGOTIATE_NTLM', ntlm_client)
#     bind_operation(version, 'SICILY_RESPONSE_NTLM', ntlm_client, challenge)
#         -> NtlmClient.parse_challenge_message(challenge)
#         -> NtlmClient.create_authenticate_message()
#             -> NtlmClient.compute_nt_response()
#
# No part of the NTLM client is mocked; only the entropy source (urandom)
# and the clock (time) are patched so the generated key fields can be
# checked against fixed vectors / independent computations.
#
# Fixed test credentials from [MS-NLMP] 4.2.4 ("User" / "Domain" /
# "Password") are used throughout. No real password appears in this file
# and nothing is logged.
#
# Each malformed challenge is classified as either:
#   REJECTED  - no AUTHENTICATE_MESSAGE is emitted (bind_operation returns
#               None or raises before a response exists), or
#   TOLERATED - the protocol implementation accepts the input within
#               protocol tolerance and still emits a response (documented
#               per test).

import struct
import unittest
from hashlib import md5, sha256
from hmac import new as hmac_new
from os.path import dirname, join

from Cryptodome.Hash import MD4

import ldap3.utils.ntlm as ntlm_module
from ldap3.operation.bind import bind_operation
from ldap3.utils.ntlm import (
    NtlmClient,
    NTLM_SIGNATURE,
    AV_CHANNEL_BINDINGS,
    AV_DNS_DOMAIN_NAME,
    AV_END_OF_LIST,
    FLAG_NEGOTIATE_128,
    FLAG_NEGOTIATE_ALWAYS_SIGN,
    FLAG_NEGOTIATE_EXTENDED_SESSIONSECURITY,
    FLAG_NEGOTIATE_NTLM,
    FLAG_NEGOTIATE_OEM,
    FLAG_NEGOTIATE_TARGET_INFO,
    FLAG_NEGOTIATE_UNICODE,
    FLAG_REQUEST_TARGET,
)
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Fixed test material (no real credentials)
# ---------------------------------------------------------------------------

TEST_USER = 'User'
TEST_DOMAIN = 'Domain'
TEST_PASSWORD = 'Password'  # fixed test credential from [MS-NLMP] 4.2.4

SERVER_CHALLENGE = bytes.fromhex('0123456789abcdef')
CLIENT_CHALLENGE = b'\xaa' * 8
FIXED_TIME = -11644473600  # makes the NTLM timestamp field exactly 0
FIXED_TIMESTAMP = b'\x00' * 8

# NTOWFv2('User','Domain','Password') - independently verified from the
# well-known NT hash of 'Password' (a4f49c406510bdcab6824ee7c30fd852).
EXPECTED_NTOWF_V2 = bytes.fromhex('0c868a403bfd7a93a3001ef22ef02e3f')

# TargetInfo AV pairs from [MS-NLMP] 4.2.4.1.3 (NetBIOS domain/computer,
# DNS domain/computer, EOL).
GOOD_TARGET_INFO = bytes.fromhex(
    '02000c0044006f006d00610069006e00'
    '01000c00530065007200760065007200'
    '0400140064006f006d00610069006e002e0063006f006d00'
    '030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d00'
    '00000000')

# NtProofStr independently computed (HMAC-MD5 chain over the MS-NLMP 4.2.4
# materials with zero timestamp and client challenge aa*8) for the known
# good challenge below.
EXPECTED_NT_PROOF_GOOD = bytes.fromhex('9f7b422d9b447198df80bd8434fb2af7')

GOOD_FLAGS = ((1 << FLAG_NEGOTIATE_UNICODE)
              | (1 << FLAG_NEGOTIATE_OEM)
              | (1 << FLAG_REQUEST_TARGET)
              | (1 << FLAG_NEGOTIATE_NTLM)
              | (1 << FLAG_NEGOTIATE_ALWAYS_SIGN)
              | (1 << FLAG_NEGOTIATE_EXTENDED_SESSIONSECURITY)
              | (1 << FLAG_NEGOTIATE_TARGET_INFO)
              | (1 << FLAG_NEGOTIATE_128))

TARGET_NAME = TEST_DOMAIN.encode('utf-16-le')
WINDOWS_VERSION = bytes.fromhex('0601000000000f00')

CERT_DIR = dirname(__file__)
CERT_A_PATH = join(CERT_DIR, '1024b-rsa-example-cert.der')
CERT_B_PATH = join(CERT_DIR, '512b-rsa-example-cert.der')


def build_challenge(target_name=TARGET_NAME,
                    target_info=GOOD_TARGET_INFO,
                    flags=GOOD_FLAGS,
                    server_challenge=SERVER_CHALLENGE,
                    message_type=2,
                    signature=NTLM_SIGNATURE,
                    target_name_len=None,
                    target_name_offset=None,
                    target_info_len=None,
                    target_info_offset=None,
                    trailing=b''):
    """Builds a raw CHALLENGE_MESSAGE; length/offset fields can be lied about."""
    payload = target_name + target_info + trailing
    tn_len = len(target_name) if target_name_len is None else target_name_len
    tn_off = 56 if target_name_offset is None else target_name_offset
    ti_len = len(target_info) if target_info_len is None else target_info_len
    ti_off = 56 + len(target_name) if target_info_offset is None else target_info_offset
    message = signature
    message += struct.pack('<I', message_type)
    message += struct.pack('<HHI', tn_len, tn_len, tn_off)
    message += struct.pack('<I', flags)
    message += server_challenge
    message += b'\x00' * 8  # reserved
    message += struct.pack('<HHI', ti_len, ti_len, ti_off)
    message += WINDOWS_VERSION
    message += payload
    return message


# The known-good challenge, kept as a fixed positive example.
GOOD_CHALLENGE = build_challenge()


def make_client():
    client = NtlmClient(TEST_DOMAIN, TEST_USER, TEST_PASSWORD)
    # first leg of the real chain: SICILY_NEGOTIATE_NTLM
    bind_operation(3, 'SICILY_NEGOTIATE_NTLM', client)
    return client


def run_response_leg(client, challenge):
    """Second leg of the real chain: returns the raw AUTHENTICATE_MESSAGE
    bytes, or None when bind_operation refuses to build a request."""
    request = bind_operation(3, 'SICILY_RESPONSE_NTLM', client, challenge)
    if request is None:
        return None
    response = request['authentication'].getComponentByName('sicilyResponse')
    if response is None:
        return None
    return bytes(response.asOctets())


def extract_nt_challenge_response(authenticate_message):
    """Independently parses the NtChallengeResponse security buffer."""
    assert authenticate_message[0:8] == NTLM_SIGNATURE
    assert struct.unpack('<I', authenticate_message[8:12])[0] == 3
    length, _, offset = struct.unpack('<HHI', authenticate_message[20:28])
    return authenticate_message[offset:offset + length]


def parse_av_pairs(raw):
    """Independent AV_PAIR walker used to verify response contents."""
    avs = []
    pos = 0
    while pos + 4 <= len(raw):
        av_type, av_len = struct.unpack('<HH', raw[pos:pos + 4])
        avs.append((av_type, raw[pos + 4:pos + 4 + av_len]))
        pos += 4 + av_len
        if av_type == AV_END_OF_LIST:
            break
    return avs


def independent_nt_proof(password, user, domain, server_challenge,
                         client_challenge, timestamp, target_info_raw):
    """Computes the NTLMv2 NtProofStr from raw materials only (no ldap3
    NTLM code), used to cross-check the client output."""
    nt_hash = MD4.new(password.encode('utf-16-le')).digest()
    response_key = hmac_new(nt_hash, (user.upper() + domain).encode('utf-16-le'), md5).digest()
    temp = (b'\x01\x01' + b'\x00' * 6 + timestamp + client_challenge
            + b'\x00' * 4 + target_info_raw + b'\x00' * 4)
    proof = hmac_new(response_key, server_challenge + temp, md5).digest()
    return proof, temp


def tls_server_end_point_binding(cert_der):
    """RFC 5929 section 4.1 'tls-server-end-point' channel binding turned
    into the MsvAvChannelBindings value, mirroring Connection.do_ntlm_bind
    (gss_channel_bindings_struct -> MD5). Both bundled test certificates
    use sha1WithRSAEncryption, so RFC 5929 mandates SHA-256 here."""
    cert_hash = sha256(cert_der).digest()
    application_data = b'tls-server-end-point:' + cert_hash
    cb_struct = (b'\x00' * 8  # initiator address
                 + b'\x00' * 8  # acceptor address
                 + len(application_data).to_bytes(4, 'little')
                 + application_data)
    return md5(cb_struct).digest()


def read_cert(path):
    with open(path, 'rb') as cert_file:
        return cert_file.read()


def fixed_entropy():
    return patch.multiple(ntlm_module,
                          urandom=lambda n: CLIENT_CHALLENGE[:n],
                          time=lambda: FIXED_TIME)


# ---------------------------------------------------------------------------
# Positive case: known-good challenge, key fields verified independently
# ---------------------------------------------------------------------------

class TestNtlmKnownGoodChallenge(unittest.TestCase):

    def test_ntowf_v2_matches_fixed_vector(self):
        client = make_client()
        self.assertEqual(client.ntowf_v2(), EXPECTED_NTOWF_V2)

    def test_authenticate_message_key_fields(self):
        with fixed_entropy():
            client = make_client()
            auth = run_response_leg(client, GOOD_CHALLENGE)
        self.assertIsNotNone(auth)
        self.assertEqual(auth[0:8], NTLM_SIGNATURE)
        self.assertEqual(struct.unpack('<I', auth[8:12])[0], 3)
        # LM response is empty when the server supplied target info
        lm_len, _, _ = struct.unpack('<HHI', auth[12:20])
        self.assertEqual(lm_len, 0)
        # negotiated flags are echoed
        self.assertEqual(struct.unpack('<I', auth[60:64])[0], GOOD_FLAGS)
        # MIC placeholder is 16 zero bytes
        self.assertEqual(auth[72:88], b'\x00' * 16)
        # domain and user travel in negotiated Unicode
        dom_len, _, dom_off = struct.unpack('<HHI', auth[28:36])
        usr_len, _, usr_off = struct.unpack('<HHI', auth[36:44])
        self.assertEqual(auth[dom_off:dom_off + dom_len], TEST_DOMAIN.encode('utf-16-le'))
        self.assertEqual(auth[usr_off:usr_off + usr_len], TEST_USER.encode('utf-16-le'))

    def test_nt_proof_matches_fixed_vector_and_independent_computation(self):
        with fixed_entropy():
            client = make_client()
            auth = run_response_leg(client, GOOD_CHALLENGE)
        nt_response = extract_nt_challenge_response(auth)
        proof, temp = nt_response[:16], nt_response[16:]
        # fixed vector
        self.assertEqual(proof, EXPECTED_NT_PROOF_GOOD)
        # independent recomputation from raw materials
        expected_proof, expected_temp = independent_nt_proof(
            TEST_PASSWORD, TEST_USER, TEST_DOMAIN, SERVER_CHALLENGE,
            CLIENT_CHALLENGE, FIXED_TIMESTAMP, GOOD_TARGET_INFO)
        self.assertEqual(proof, expected_proof)
        self.assertEqual(temp, expected_temp)
        # temp structure: version 0101, zero timestamp, fixed client
        # challenge, server target info echoed verbatim
        self.assertEqual(temp[0:2], b'\x01\x01')
        self.assertEqual(temp[8:16], FIXED_TIMESTAMP)
        self.assertEqual(temp[16:24], CLIENT_CHALLENGE)
        self.assertEqual(temp[28:-4], GOOD_TARGET_INFO)


# ---------------------------------------------------------------------------
# Security buffer (offset/length) boundary violations
# ---------------------------------------------------------------------------

class TestNtlmSecurityBufferBounds(unittest.TestCase):

    def test_target_name_offset_out_of_bounds_tolerated(self):
        # TOLERATED: Python slicing clamps the out-of-bounds security
        # buffer to an empty string; a response is still emitted.
        challenge = build_challenge(target_name_offset=4096, target_name_len=8)
        with fixed_entropy():
            client = make_client()
            auth = run_response_leg(client, challenge)
        self.assertIsNotNone(auth)
        self.assertEqual(client.server_target_name, '')

    def test_target_name_length_overrun_tolerated_with_truncation(self):
        # TOLERATED: a declared length far beyond the message is clamped by
        # slicing; the (even-length) truncated name is accepted.
        challenge = build_challenge(target_name_len=0xFFFE)
        with fixed_entropy():
            client = make_client()
            auth = run_response_leg(client, challenge)
        self.assertIsNotNone(auth)
        self.assertEqual(client.server_target_name,
                         (TARGET_NAME + GOOD_TARGET_INFO).decode('utf-16-le'))

    def test_target_info_offset_out_of_bounds_tolerated(self):
        # TOLERATED: out-of-bounds target info buffer yields an empty AV
        # list; the response goes out without any server target info.
        challenge = build_challenge(target_info_offset=8192, target_info_len=16)
        with fixed_entropy():
            client = make_client()
            auth = run_response_leg(client, challenge)
        self.assertIsNotNone(auth)
        self.assertEqual(client.server_target_info, [])
        self.assertEqual(client.server_target_info_raw, b'')
        nt_response = extract_nt_challenge_response(auth)
        self.assertEqual(nt_response[16:][28:-4], b'')  # no AVs inside temp

    def test_target_info_length_overrun_rejected(self):
        # REJECTED: declared target info length runs past the message end
        # and the clamped bytes end mid-AV_PAIR; the AV walker raises
        # struct.error before any response is produced.
        truncated_info = struct.pack('<HH', 3, 10) + b'\x41\x00\x42\x00'
        challenge = build_challenge(target_info=truncated_info,
                                    target_info_len=len(truncated_info) + 32)
        with fixed_entropy():
            client = make_client()
            with self.assertRaises(struct.error):
                run_response_leg(client, challenge)


# ---------------------------------------------------------------------------
# AV_PAIR truncation, overrun and duplication
# ---------------------------------------------------------------------------

class TestNtlmAvPairHandling(unittest.TestCase):

    def test_truncated_av_pair_rejected(self):
        # REJECTED: AV header announces 10 value bytes, only 4 are present
        # and no EOL follows; struct.error is raised before the response.
        info = struct.pack('<HH', AV_DNS_DOMAIN_NAME, 10) + b'\x61\x00\x62\x00'
        challenge = build_challenge(target_info=info)
        with fixed_entropy():
            client = make_client()
            with self.assertRaises(struct.error):
                run_response_leg(client, challenge)

    def test_av_length_overrun_rejected(self):
        # REJECTED: av_len of 0xFFFF consumes the rest of the buffer and
        # the walker falls off the end looking for the next header.
        info = struct.pack('<HH', AV_DNS_DOMAIN_NAME, 0xFFFF) + b'\x61\x00'
        challenge = build_challenge(target_info=info)
        with fixed_entropy():
            client = make_client()
            with self.assertRaises(struct.error):
                run_response_leg(client, challenge)

    def test_missing_end_of_list_rejected(self):
        # REJECTED: well-formed AV pairs without the terminating EOL make
        # the walker run past the buffer end (struct.error).
        info = struct.pack('<HH', AV_DNS_DOMAIN_NAME, 4) + b'\x61\x00\x00\x00'
        challenge = build_challenge(target_info=info)
        with fixed_entropy():
            client = make_client()
            with self.assertRaises(struct.error):
                run_response_leg(client, challenge)

    def test_unknown_av_type_rejected(self):
        # REJECTED: an AV id outside the MS-NLMP set raises ValueError
        # before any response is emitted.
        info = struct.pack('<HH', 0x0BAD, 2) + b'\x00\x00' + b'\x00' * 4
        challenge = build_challenge(target_info=info)
        with fixed_entropy():
            client = make_client()
            with self.assertRaises(ValueError):
                run_response_leg(client, challenge)

    def test_duplicate_av_pairs_last_wins_but_both_echoed(self):
        # TOLERATED: duplicate AV ids are not rejected. The last value wins
        # in the parsed attribute, and both copies are echoed verbatim into
        # the NtChallengeResponse temp (server target info is reflected
        # unmodified, as MS-NLMP allows).
        first = struct.pack('<HH', AV_DNS_DOMAIN_NAME, 8) + 'one.'.encode('utf-16-le')
        second = struct.pack('<HH', AV_DNS_DOMAIN_NAME, 8) + 'two.'.encode('utf-16-le')
        info = first + second + b'\x00' * 4
        challenge = build_challenge(target_info=info)
        with fixed_entropy():
            client = make_client()
            auth = run_response_leg(client, challenge)
        self.assertIsNotNone(auth)
        self.assertEqual(client.server_av_dns_domain_name, 'two.')
        nt_response = extract_nt_challenge_response(auth)
        echoed = parse_av_pairs(nt_response[16:][28:-4])
        dns_values = [v for t, v in echoed if t == AV_DNS_DOMAIN_NAME]
        self.assertEqual(dns_values, ['one.'.encode('utf-16-le'), 'two.'.encode('utf-16-le')])

    def test_zero_length_av_value_tolerated(self):
        # TOLERATED: a zero-length AV value decodes to an empty string and
        # the response is still emitted.
        info = struct.pack('<HH', AV_DNS_DOMAIN_NAME, 0) + b'\x00' * 4
        challenge = build_challenge(target_info=info)
        with fixed_entropy():
            client = make_client()
            auth = run_response_leg(client, challenge)
        self.assertIsNotNone(auth)
        self.assertEqual(client.server_av_dns_domain_name, '')


# ---------------------------------------------------------------------------
# Unicode length errors
# ---------------------------------------------------------------------------

class TestNtlmUnicodeLengthErrors(unittest.TestCase):

    def test_odd_length_unicode_target_name_rejected(self):
        # REJECTED: with NEGOTIATE_UNICODE set, an odd-length target name
        # cannot be UTF-16; decoding fails before the response.
        odd_name = b'\x44\x00\x4f\x00\x47'  # 'DO' + stray byte
        challenge = build_challenge(target_name=odd_name)
        with fixed_entropy():
            client = make_client()
            with self.assertRaises(UnicodeDecodeError):
                run_response_leg(client, challenge)

    def test_odd_length_unicode_av_value_rejected(self):
        # REJECTED: an odd-length UTF-16 AV value fails decoding during
        # challenge parsing, before any response exists.
        info = (struct.pack('<HH', AV_DNS_DOMAIN_NAME, 3) + b'\x61\x00\x62'
                + b'\x00' * 4)
        challenge = build_challenge(target_info=info)
        with fixed_entropy():
            client = make_client()
            with self.assertRaises(UnicodeDecodeError):
                run_response_leg(client, challenge)


# ---------------------------------------------------------------------------
# Structurally invalid messages and clean rejection
# ---------------------------------------------------------------------------

class TestNtlmMalformedMessageRejection(unittest.TestCase):

    def test_short_message_cleanly_rejected(self):
        # REJECTED (clean): messages shorter than the 56-byte header make
        # parse_challenge_message return False; with a fresh client the
        # missing negotiated 128-bit flag stops create_authenticate_message
        # and bind_operation emits no request at all.
        with fixed_entropy():
            client = make_client()
            self.assertFalse(client.parse_challenge_message(GOOD_CHALLENGE[:40]))
            self.assertIsNone(run_response_leg(client, GOOD_CHALLENGE[:40]))

    def test_bad_signature_cleanly_rejected(self):
        # REJECTED (clean): wrong NTLMSSP signature -> parse returns False,
        # no AUTHENTICATE_MESSAGE is built.
        challenge = build_challenge(signature=b'NTLMXXX\x00')
        with fixed_entropy():
            client = make_client()
            self.assertIsNone(run_response_leg(client, challenge))

    def test_wrong_message_type_cleanly_rejected(self):
        # REJECTED (clean): message type other than 2 is refused.
        challenge = build_challenge(message_type=3)
        with fixed_entropy():
            client = make_client()
            self.assertIsNone(run_response_leg(client, challenge))

    def test_target_info_negotiated_but_absent_raises(self):
        # REJECTED (unhandled): the challenge negotiates TARGET_INFO but
        # carries a zero-length buffer; server_target_info_raw stays None
        # and compute_nt_response blows up with TypeError instead of a
        # clean refusal. Documented as a robustness gap: still no response.
        flags = GOOD_FLAGS
        challenge = build_challenge(target_info=b'', target_info_len=0, flags=flags)
        with fixed_entropy():
            client = make_client()
            with self.assertRaises(TypeError):
                run_response_leg(client, challenge)


# ---------------------------------------------------------------------------
# Residual state of reused challenge objects
# ---------------------------------------------------------------------------

class TestNtlmChallengeResidualState(unittest.TestCase):

    def test_failed_parse_leaves_previous_challenge_material(self):
        # RESIDUAL STATE: after a good challenge is parsed, a rejected
        # second challenge (parse returns False) does NOT clear the client.
        # create_authenticate_message still emits a response cryptographi-
        # cally bound to the FIRST server challenge and target info.
        with fixed_entropy():
            client = make_client()
            good_auth = run_response_leg(client, GOOD_CHALLENGE)
            good_proof = extract_nt_challenge_response(good_auth)[:16]
            # second, malformed challenge is refused by the parser...
            self.assertFalse(client.parse_challenge_message(b'too short'))
            # ...but the stale state still produces a full response
            stale_auth = client.create_authenticate_message()
        stale_proof = extract_nt_challenge_response(stale_auth)[:16]
        self.assertEqual(stale_proof, good_proof)
        self.assertEqual(client.server_challenge, SERVER_CHALLENGE)

    def test_challenge_without_target_info_inherits_stale_av_pairs(self):
        # RESIDUAL STATE: a second, syntactically valid challenge that does
        # not negotiate TARGET_INFO leaves server_target_info_raw from the
        # previous challenge in place; the new response mixes the NEW
        # server challenge with the OLD target info.
        flags_no_ti = GOOD_FLAGS & ~(1 << FLAG_NEGOTIATE_TARGET_INFO)
        second_challenge = build_challenge(target_info=b'',
                                           target_info_len=0,
                                           flags=flags_no_ti,
                                           server_challenge=b'\x11' * 8)
        with fixed_entropy():
            client = make_client()
            run_response_leg(client, GOOD_CHALLENGE)
            mixed_auth = run_response_leg(client, second_challenge)
        self.assertIsNotNone(mixed_auth)
        nt_response = extract_nt_challenge_response(mixed_auth)
        # old AV pairs are still echoed...
        self.assertEqual(nt_response[16:][28:-4], GOOD_TARGET_INFO)
        # ...and the proof matches an independent computation over the
        # NEW server challenge plus the STALE target info
        expected_proof, _ = independent_nt_proof(
            TEST_PASSWORD, TEST_USER, TEST_DOMAIN, b'\x11' * 8,
            CLIENT_CHALLENGE, FIXED_TIMESTAMP, GOOD_TARGET_INFO)
        self.assertEqual(nt_response[:16], expected_proof)


# ---------------------------------------------------------------------------
# TLS channel binding (RFC 5929 tls-server-end-point)
# ---------------------------------------------------------------------------

class TestNtlmTlsChannelBinding(unittest.TestCase):

    def setUp(self):
        self.cb_a = tls_server_end_point_binding(read_cert(CERT_A_PATH))
        self.cb_b = tls_server_end_point_binding(read_cert(CERT_B_PATH))
        self.assertNotEqual(self.cb_a, self.cb_b)  # distinct certificates

    @staticmethod
    def expected_bound_target_info(*bindings):
        raw = GOOD_TARGET_INFO[:-4]  # strip EOL
        for binding in bindings:
            raw += struct.pack('<HH', AV_CHANNEL_BINDINGS, len(binding)) + binding
        return raw + b'\x00' * 4  # new EOL

    def bound_proof(self, client):
        with fixed_entropy():
            auth = run_response_leg(client, GOOD_CHALLENGE)
        self.assertIsNotNone(auth)
        return extract_nt_challenge_response(auth)

    def make_bound_client(self, binding):
        client = make_client()
        client.tls_channel_binding = True
        client.client_av_channel_bindings = binding
        return client

    def test_channel_binding_av_echoed_and_proof_matches_independent(self):
        client = self.make_bound_client(self.cb_a)
        nt_response = self.bound_proof(client)
        expected_raw = self.expected_bound_target_info(self.cb_a)
        # the client mutates server_target_info_raw in place, appending
        # MsvAvChannelBindings before the EOL
        self.assertEqual(client.server_target_info_raw, expected_raw)
        expected_proof, _ = independent_nt_proof(
            TEST_PASSWORD, TEST_USER, TEST_DOMAIN, SERVER_CHALLENGE,
            CLIENT_CHALLENGE, FIXED_TIMESTAMP, expected_raw)
        self.assertEqual(nt_response[:16], expected_proof)
        echoed = parse_av_pairs(nt_response[16:][28:-4])
        self.assertIn((AV_CHANNEL_BINDINGS, self.cb_a), echoed)

    def test_certificate_change_changes_proof(self):
        # Same challenge, same credentials, same entropy: only the TLS
        # binding material differs, so the authentication proof MUST differ.
        proof_a = self.bound_proof(self.make_bound_client(self.cb_a))[:16]
        proof_b = self.bound_proof(self.make_bound_client(self.cb_b))[:16]
        self.assertNotEqual(proof_a, proof_b)
        expected_proof_b, _ = independent_nt_proof(
            TEST_PASSWORD, TEST_USER, TEST_DOMAIN, SERVER_CHALLENGE,
            CLIENT_CHALLENGE, FIXED_TIMESTAMP,
            self.expected_bound_target_info(self.cb_b))
        self.assertEqual(proof_b, expected_proof_b)

    def test_no_channel_binding_baseline(self):
        # Without TLS channel binding no MsvAvChannelBindings AV appears.
        with fixed_entropy():
            client = make_client()
            auth = run_response_leg(client, GOOD_CHALLENGE)
        nt_response = extract_nt_challenge_response(auth)
        echoed = parse_av_pairs(nt_response[16:][28:-4])
        self.assertNotIn(AV_CHANNEL_BINDINGS, [t for t, _ in echoed])

    def test_cert_change_on_reused_client_accumulates_stale_binding(self):
        # RESIDUAL STATE: compute_nt_response permanently appends the
        # channel binding AV to server_target_info_raw. Rebinding the same
        # client object to a new certificate stacks a SECOND
        # MsvAvChannelBindings AV; the resulting proof differs from what a
        # fresh client bound to the new certificate produces.
        client = self.make_bound_client(self.cb_a)
        with fixed_entropy():
            run_response_leg(client, GOOD_CHALLENGE)
            # certificate changed on the same client object; regenerating
            # without re-parsing a challenge reuses the mutated state
            client.client_av_channel_bindings = self.cb_b
            reused_auth = client.create_authenticate_message()
        reused_response = extract_nt_challenge_response(reused_auth)
        echoed = parse_av_pairs(reused_response[16:][28:-4])
        bindings = [v for t, v in echoed if t == AV_CHANNEL_BINDINGS]
        # stale cb_a is still there, cb_b is appended after it
        self.assertEqual(bindings, [self.cb_a, self.cb_b])
        expected_stale_proof, _ = independent_nt_proof(
            TEST_PASSWORD, TEST_USER, TEST_DOMAIN, SERVER_CHALLENGE,
            CLIENT_CHALLENGE, FIXED_TIMESTAMP,
            self.expected_bound_target_info(self.cb_a, self.cb_b))
        self.assertEqual(reused_response[:16], expected_stale_proof)
        fresh_proof_b, _ = independent_nt_proof(
            TEST_PASSWORD, TEST_USER, TEST_DOMAIN, SERVER_CHALLENGE,
            CLIENT_CHALLENGE, FIXED_TIMESTAMP,
            self.expected_bound_target_info(self.cb_b))
        self.assertNotEqual(reused_response[:16], fresh_proof_b)


if __name__ == '__main__':
    unittest.main()
