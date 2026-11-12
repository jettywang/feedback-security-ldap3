"""
Deterministic tests for the isolation guarantees of the asynchronous strategy
when a request is cancelled with an LDAP Abandon.

An AbandonRequest has no server acknowledgement, so "the Abandon was sent"
cannot be taken as "the server stopped sending responses". These tests drive
the real AsyncStrategy receiver thread with a scripted, fully controllable
fake socket and prove that:

* entries already buffered before the cancel are discarded,
* late searchResEntry/searchResDone messages arriving after the cancel can
  never wake the abandoned caller nor leak into a later request,
* a connection close clears every piece of abandoned state,
* a quarantined message id cannot be handed out again on the same socket,
  while a reopened socket (a new LDAP session) may safely use it again,
* quarantine retention is bounded,
* a normal, non-cancelled search still collects every entry and its final
  searchResDone status.
"""

import unittest

from ldap3 import Server, Connection, ASYNC, ANONYMOUS, AUTO_BIND_NONE, SUBTREE, ALL, set_config_parameter
from ldap3.core.exceptions import LDAPOperationAbandonedError, LDAPMessageIDReuseError
from ldap3.protocol.rfc4511 import (LDAPMessage, MessageID, ProtocolOp, SearchResultEntry,
                                    SearchResultDone, LDAPDN, PartialAttributeList, ResultCode,
                                    LDAPString)
from ldap3.utils.asn1 import encode


def search_entry_message(message_id, dn):
    entry = SearchResultEntry()
    entry.setComponentByName('object', LDAPDN(dn))
    entry.setComponentByName('attributes', PartialAttributeList())
    message = LDAPMessage()
    message['messageID'] = MessageID(message_id)
    message['protocolOp'] = ProtocolOp().setComponentByName('searchResEntry', entry)
    return encode(message)


def search_done_message(message_id, result_code=0):
    done = SearchResultDone()
    done.setComponentByName('resultCode', ResultCode(result_code))
    done.setComponentByName('matchedDN', LDAPDN(''))
    done.setComponentByName('diagnosticMessage', LDAPString(''))
    message = LDAPMessage()
    message['messageID'] = MessageID(message_id)
    message['protocolOp'] = ProtocolOp().setComponentByName('searchResDone', done)
    return encode(message)


class ScriptedSocket(object):
    """In-memory replacement for a TCP socket.

    The test decides exactly which LDAP messages the receiver thread is allowed
    to see and when, via ``release``/``release_all``: no timing guesses, no
    sleeps are needed to interleave old responses between a cancel and a new
    request. Sent bytes (including the AbandonRequest) are captured for
    assertions.

    Every queued chunk is handed out exactly once, mirroring a blocking TCP
    socket: ``recv`` blocks while the queue is empty and the socket is open and
    only returns ``b''`` after ``close``. That keeps the real receiver thread
    alive for the whole test without any timing-based polling.
    """

    def __init__(self):
        import queue
        self.sent = []
        self._chunks = queue.Queue()
        self.closed = False

    def sendall(self, data):
        self.sent.append(bytes(data))

    def send(self, data):
        self.sent.append(bytes(data))
        return len(data)

    def recv(self, size):
        chunk = self._chunks.get()
        if chunk is None:
            # sentinel pushed by close(): real sockets return b'' afterwards
            self._chunks.put(None)
            return b''
        return chunk

    def release(self, message_bytes):
        self._chunks.put(bytes(message_bytes))

    def release_all(self, messages):
        for message_bytes in messages:
            self._chunks.put(bytes(message_bytes))

    def shutdown(self, how):
        pass

    def close(self):
        if not self.closed:
            self.closed = True
            self._chunks.put(None)

    def setsockopt(self, *args):
        pass

    def fileno(self):
        return -1

    def wait_until_received(self, expected_messages, timeout=5):
        import time
        end = time.monotonic() + timeout
        while time.monotonic() < end and len(self.sent) < expected_messages:
            time.sleep(0.005)
        if len(self.sent) < expected_messages:
            raise AssertionError('expected %d sent messages, got %d' % (expected_messages, len(self.sent)))


def make_connection(fake_socket, fast_decoder=False):
    server = Server('fake-server.example')
    connection = Connection(server, authentication=ANONYMOUS, auto_bind=AUTO_BIND_NONE,
                            client_strategy=ASYNC, fast_decoder=fast_decoder, receive_timeout=None)
    # bypass the real TCP connect: the strategy opens the receiver thread on it
    connection.socket = fake_socket
    connection.closed = False
    connection.listening = False
    connection.strategy._outstanding = dict()
    connection.strategy._responses = dict()
    connection.strategy._requests = dict()
    connection.strategy._reset_message_isolation_state()
    connection.strategy._start_listen()
    return connection


class TestAsyncAbandonIsolation(unittest.TestCase):
    def setUp(self):
        self.fake_socket = ScriptedSocket()
        self.connection = make_connection(self.fake_socket)
        self.strategy = self.connection.strategy

    def tearDown(self):
        try:
            self.connection.unbind()
        except Exception:
            pass
        if self.connection.listening:
            self.connection.strategy.close()

    def _send_search(self):
        return self.connection.search(search_base='ou=test,o=lab',
                                      search_filter='(objectClass=*)',
                                      search_scope=SUBTREE,
                                      attributes=ALL)

    def test_entries_buffered_before_cancel_are_discarded(self):
        message_id = self._send_search()
        self.fake_socket.wait_until_received(1)

        # server already produced an entry before the caller cancels
        self.fake_socket.release(search_entry_message(message_id, 'cn=before-cancel,ou=test,o=lab'))
        self.assertTrue(self._wait_until(lambda: message_id in self.strategy._responses))
        self.assertEqual(1, len(self.strategy._responses[message_id]))

        self.assertTrue(self.connection.abandon(message_id))
        # two messages on the wire: searchRequest then abandonRequest
        self.fake_socket.wait_until_received(2)

        # the pre-cancel buffered entry must be gone and nothing can wake the caller
        self.assertNotIn(message_id, self.strategy._responses)
        self.assertNotIn(message_id, self.strategy._events)
        self.assertIn(message_id, self.strategy._abandoned_messages)
        with self.assertRaises(LDAPOperationAbandonedError):
            self.connection.get_response(message_id, timeout=0.1)

    def test_late_entry_and_done_after_cancel_never_reach_any_caller(self):
        abandoned_id = self._send_search()
        second_id = self._send_search()
        self.fake_socket.wait_until_received(2)
        self.assertNotEqual(abandoned_id, second_id)

        self.assertTrue(self.connection.abandon(abandoned_id))
        self.fake_socket.wait_until_received(3)

        # the "server" keeps answering the abandoned search: entry then done,
        # interleaved with the fresh search's own entry and done
        self.fake_socket.release_all([
            search_entry_message(abandoned_id, 'cn=stale,ou=test,o=lab'),
            search_done_message(abandoned_id),
            search_entry_message(second_id, 'cn=fresh,ou=test,o=lab'),
            search_done_message(second_id),
        ])

        response, result = self.connection.get_response(second_id, timeout=5)
        self.assertEqual(1, len(response))
        self.assertEqual('cn=fresh,ou=test,o=lab', response[0]['dn'])
        self.assertEqual('searchResEntry', response[0]['type'])
        self.assertEqual('searchResDone', result['type'])
        self.assertEqual(0, result['result'])

        # no stale trace anywhere, and the abandoned caller cannot be re-woken
        self.assertNotIn(abandoned_id, self.strategy._responses)
        self.assertNotIn(second_id, self.strategy._responses)
        self.assertNotIn(abandoned_id, self.strategy.active_abandoned_messages())  # done was terminal
        with self.assertRaises(LDAPOperationAbandonedError):
            self.connection.get_response(abandoned_id, timeout=0.1)

    def test_abandoned_caller_is_not_woken_by_late_traffic(self):
        message_id = self._send_search()
        self.fake_socket.wait_until_received(1)
        self.assertTrue(self.connection.abandon(message_id))
        self.fake_socket.wait_until_received(2)

        # a flood of late entries must never create an event for the cancelled id
        for index in range(5):
            self.fake_socket.release(search_entry_message(message_id, 'cn=late-%d,ou=test,o=lab' % index))
        self.assertTrue(self._wait_until_quiescent())
        self.assertNotIn(message_id, self.strategy._events)
        self.assertNotIn(message_id, self.strategy._responses)
        with self.assertRaises(LDAPOperationAbandonedError):
            self.connection.get_response(message_id, timeout=0.1)

    def test_connection_close_clears_abandoned_state(self):
        message_id = self._send_search()
        self.fake_socket.wait_until_received(1)
        self.assertTrue(self.connection.abandon(message_id))
        self.fake_socket.wait_until_received(2)
        self.fake_socket.release(search_entry_message(message_id, 'cn=late,ou=test,o=lab'))
        self.assertTrue(self._wait_until_quiescent())
        self.assertIn(message_id, self.strategy._abandoned_messages)

        self.connection.strategy.close()
        self.assertEqual(0, len(self.strategy._abandoned_messages))
        self.assertEqual(0, len(self.strategy._events))

    def test_quarantined_message_id_is_refused_on_same_socket(self):
        abandoned_id = self._send_search()
        self.fake_socket.wait_until_received(1)
        self.assertTrue(self.connection.abandon(abandoned_id))
        self.fake_socket.wait_until_received(2)

        # force the shared Server counter to hand the quarantined id out again
        from ldap3.core.server import Server
        Server._message_counter = abandoned_id - 1

        with self.assertRaises(LDAPMessageIDReuseError):
            self._send_search()
        # the rejected attempt must not have written anything to the wire
        self.fake_socket.wait_until_received(2)
        self.assertEqual(2, len(self.fake_socket.sent))

    def test_reopened_socket_may_reuse_the_message_id_safely(self):
        abandoned_id = self._send_search()
        self.fake_socket.wait_until_received(1)
        self.assertTrue(self.connection.abandon(abandoned_id))
        self.fake_socket.wait_until_received(2)
        self.assertIn(abandoned_id, self.strategy._abandoned_messages)

        # closing the socket ends the LDAP session. A brand new connection gets
        # a new TCP socket and a fresh, empty message-id bookkeeping, which is
        # the only safe boundary for reusing an abandoned id: no fixed sleep,
        # no guess about the network having drained.
        self.connection.strategy.close()
        new_socket = ScriptedSocket()
        new_connection = make_connection(new_socket)
        self.connection = new_connection
        self.strategy = new_connection.strategy
        self.fake_socket = new_socket

        from ldap3.core.server import Server
        Server._message_counter = abandoned_id - 1
        reused_id = self._send_search()
        self.assertEqual(abandoned_id, reused_id)
        new_socket.wait_until_received(1)

        new_socket.release_all([
            search_entry_message(reused_id, 'cn=new-session,ou=test,o=lab'),
            search_done_message(reused_id),
        ])
        response, result = self.connection.get_response(reused_id, timeout=5)
        self.assertEqual(['cn=new-session,ou=test,o=lab'], [entry['dn'] for entry in response])
        self.assertEqual(0, result['result'])

    def test_quarantine_retention_is_bounded(self):
        original_limit = self._quarantine_limit()
        set_config_parameter('ABANDONED_MESSAGE_RETENTION', 3)
        try:
            abandoned_ids = []
            for _ in range(5):
                message_id = self._send_search()
                self.fake_socket.wait_until_received(len(abandoned_ids) * 2 + 1)
                self.assertTrue(self.connection.abandon(message_id))
                self.fake_socket.wait_until_received(len(abandoned_ids) * 2 + 2)
                abandoned_ids.append(message_id)

            active = self.strategy.active_abandoned_messages()
            self.assertEqual(3, len(active))
            # oldest ids were demoted to tombstones, newest ones stay active
            self.assertEqual(abandoned_ids[-3:], active)
            self.assertEqual(abandoned_ids[:2], self.strategy.abandoned_tombstones())
            # tombstones still block reuse on the open socket
            from ldap3.core.server import Server
            for blocked_id in abandoned_ids:
                Server._message_counter = blocked_id - 1
                with self.assertRaises(LDAPMessageIDReuseError):
                    self._send_search()
        finally:
            set_config_parameter('ABANDONED_MESSAGE_RETENTION', original_limit)

    def test_evicted_id_still_refused_until_a_new_socket_session(self):
        original_limit = self._quarantine_limit()
        set_config_parameter('ABANDONED_MESSAGE_RETENTION', 1)
        try:
            first_id = self._send_search()
            self.fake_socket.wait_until_received(1)
            self.assertTrue(self.connection.abandon(first_id))
            self.fake_socket.wait_until_received(2)

            second_id = self._send_search()
            self.fake_socket.wait_until_received(3)
            self.assertTrue(self.connection.abandon(second_id))
            self.fake_socket.wait_until_received(4)
            # first_id was demoted to a tombstone by the bounded retention ...
            self.assertNotIn(first_id, self.strategy.active_abandoned_messages())
            self.assertIn(first_id, self.strategy.abandoned_tombstones())
            self.assertIn(second_id, self.strategy.active_abandoned_messages())

            # ... but the demotion must not make the id reusable on the still-open
            # socket; the only safe boundary is a new socket session
            from ldap3.core.server import Server
            Server._message_counter = first_id - 1
            with self.assertRaises(LDAPMessageIDReuseError):
                self._send_search()
        finally:
            set_config_parameter('ABANDONED_MESSAGE_RETENTION', original_limit)

    def test_normal_search_collects_every_entry_and_final_status(self):
        message_id = self._send_search()
        self.fake_socket.wait_until_received(1)
        self.fake_socket.release_all([
            search_entry_message(message_id, 'cn=one,ou=test,o=lab'),
            search_entry_message(message_id, 'cn=two,ou=test,o=lab'),
            search_entry_message(message_id, 'cn=three,ou=test,o=lab'),
            search_done_message(message_id),
        ])

        response, result = self.connection.get_response(message_id, timeout=5)
        self.assertEqual(['cn=one,ou=test,o=lab', 'cn=two,ou=test,o=lab', 'cn=three,ou=test,o=lab'],
                         [entry['dn'] for entry in response])
        self.assertEqual('searchResDone', result['type'])
        self.assertEqual(0, result['result'])
        self.assertNotIn(message_id, self.strategy._responses)
        self.assertNotIn(message_id, self.strategy._abandoned_messages)

    def test_late_traffic_is_isolated_with_fast_decoder(self):
        fast_socket = ScriptedSocket()
        fast_connection = make_connection(fast_socket, fast_decoder=True)
        self.connection = fast_connection
        self.strategy = fast_connection.strategy
        self.fake_socket = fast_socket

        abandoned_id = self._send_search()
        second_id = self._send_search()
        fast_socket.wait_until_received(2)
        self.assertTrue(self.connection.abandon(abandoned_id))
        fast_socket.wait_until_received(3)

        fast_socket.release_all([
            search_entry_message(abandoned_id, 'cn=stale,ou=test,o=lab'),
            search_done_message(abandoned_id),
            search_entry_message(second_id, 'cn=fresh,ou=test,o=lab'),
            search_done_message(second_id),
        ])

        response, result = self.connection.get_response(second_id, timeout=5)
        self.assertEqual(['cn=fresh,ou=test,o=lab'], [entry['dn'] for entry in response])
        self.assertEqual(0, result['result'])
        self.assertNotIn(abandoned_id, self.strategy._responses)
        with self.assertRaises(LDAPOperationAbandonedError):
            self.connection.get_response(abandoned_id, timeout=0.1)

    def test_abandon_request_itself_is_sent_but_has_no_quarantine(self):
        message_id = self._send_search()
        self.fake_socket.wait_until_received(1)
        self.assertTrue(self.connection.abandon(message_id))
        self.fake_socket.wait_until_received(2)

        from ldap3.utils.asn1 import decoder
        first = decoder.decode(self.fake_socket.sent[0], asn1Spec=LDAPMessage())[0]
        second = decoder.decode(self.fake_socket.sent[1], asn1Spec=LDAPMessage())[0]
        self.assertEqual(message_id, int(first['messageID']))
        self.assertNotEqual(message_id, int(second['messageID']))  # the AbandonRequest has its own envelope id
        abandon_payload = second['protocolOp'].getComponentByName('abandonRequest')
        self.assertEqual(message_id, int(abandon_payload))  # ...and names the cancelled target
        self.assertEqual([message_id], self.strategy.active_abandoned_messages())

    def _wait_until(self, predicate, timeout=5):
        import time
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate():
                return True
            time.sleep(0.005)
        return predicate()

    def _wait_until_quiescent(self, quiet_period=0.2, timeout=5):
        import time
        end = time.monotonic() + timeout
        last_size = None
        stable_since = None
        while time.monotonic() < end:
            size = (len(self.strategy._responses), len(self.strategy._events), len(self.strategy._abandoned_messages))
            now = time.monotonic()
            if size == last_size:
                if stable_since is None:
                    stable_since = now
                elif now - stable_since >= quiet_period:
                    return True
            else:
                stable_since = None
                last_size = size
            time.sleep(0.01)
        return False

    @staticmethod
    def _quarantine_limit():
        from ldap3 import get_config_parameter
        return get_config_parameter('ABANDONED_MESSAGE_RETENTION')
