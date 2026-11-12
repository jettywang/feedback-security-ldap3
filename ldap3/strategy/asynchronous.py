"""
"""

# Created on 2013.07.15
#
# Author: Giovanni Cannata
#
# Copyright 2013 - 2025 Giovanni Cannata
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

from collections import OrderedDict
from threading import Thread, Lock, Event
import socket

from .. import get_config_parameter, DIGEST_MD5, ENCRYPT
from ..core.exceptions import LDAPSSLConfigurationError, LDAPStartTLSError, LDAPOperationResult, LDAPSignatureVerificationFailedError, LDAPConfigurationError, LDAPMessageIDReuseError, LDAPOperationAbandonedError
from ..strategy.base import BaseStrategy, RESPONSE_COMPLETE
from ..protocol.rfc4511 import LDAPMessage
from ..utils.log import log, log_enabled, format_ldap_message, ERROR, NETWORK, EXTENDED, PROTOCOL
from ..utils.asn1 import decoder, decode_message_fast
from ..protocol.sasl.digestMd5 import md5_hmac


# noinspection PyProtectedMember
class AsyncStrategy(BaseStrategy):
    """
    This strategy is asynchronous. You send the request and get the messageId of the request sent
    Receiving data from socket is managed in a separated thread in a blocking mode
    Requests return an int value to indicate the messageId of the requested Operation
    You get the response with get_response, it has a timeout to wait for response to appear
    Connection.response will contain the whole LDAP response for the messageId requested in a dict form
    Connection.request will contain the result LDAP message in a dict form
    Response appear in strategy._responses dictionary
    """

    # noinspection PyProtectedMember
    class ReceiverSocketThread(Thread):
        """
        The thread that actually manage the receiver socket
        """

        def __init__(self, ldap_connection):
            Thread.__init__(self)
            self.connection = ldap_connection
            self.socket_size = get_config_parameter('SOCKET_SIZE')

        def run(self):
            """
            Waits for data on socket, computes the length of the message and waits for enough bytes to decode the message
            Message are appended to strategy._responses
            """
            unprocessed = b''
            get_more_data = True
            listen = True
            data = b''
            sasl_total_bytes_recieved = 0
            sasl_received_data = b''  # used to verify the signature, typo GC
            sasl_next_packet = b''
            sasl_buffer_length = -1
            # sasl_signature = b''  # not needed here GC
            # sasl_sec_num = b'' # used to verify the signature, not needed here GC

            while listen:
                if get_more_data:
                    try:
                        data = self.connection.socket.recv(self.socket_size)
                    except (OSError, socket.error, AttributeError):
                        if self.connection.receive_timeout:  # a receive timeout has been detected - keep kistening on the socket
                            continue
                    except Exception as e:
                        if log_enabled(ERROR):
                            log(ERROR, '<%s> for <%s>', str(e), self.connection)
                        raise  # unexpected exception - re-raise
                    if len(data) > 0:
                        # If we are using DIGEST-MD5 and LDAP signing is set : verify & remove the signature from the message
                        if self.connection._digest_md5_kcs_cipher or self.connection.session_security == ENCRYPT:
                            raise LDAPConfigurationError("Confidentiality layers are only available for synchronous strategies")
                        if self.connection.sasl_mechanism == DIGEST_MD5 and self.connection._digest_md5_kis and not self.connection.sasl_in_progress:
                            data = sasl_next_packet + data

                            if sasl_received_data == b'' or sasl_next_packet:
                                # Remove the sizeOf(encoded_message + signature + 0x0001 + secNum) from data.
                                sasl_buffer_length = int.from_bytes(data[0:4], "big")
                                data = data[4:]
                            sasl_next_packet = b''
                            sasl_total_bytes_recieved += len(data)
                            sasl_received_data += data

                            if sasl_total_bytes_recieved >= sasl_buffer_length:
                                # When the LDAP response is splitted accross multiple TCP packets, the SASL buffer length is equal to the MTU of each packet..Which is usually not equal to self.socket_size
                                # This means that the end of one SASL packet/beginning of one other....could be located in the middle of data
                                # We are using "sasl_received_data" instead of "data" & "unprocessed" for this reason
                                sasl_next_packet = sasl_received_data[sasl_buffer_length:]  # the last "data" variable may contain another sasl packet. We'll process it at the next iteration.

                                # structure of messages when LDAP signing is enabled : sizeOf(encoded_message + signature + 0x0001 + secNum) + encoded_message + signature + 0x0001 + secNum
                                sasl_sec_num = sasl_received_data[sasl_buffer_length - 4:sasl_buffer_length]
                                sasl_received_data = sasl_received_data[:sasl_buffer_length-6] # Removing secNum and the message type number to fit also encryption
                                sasl_buffer_length = len(sasl_received_data) # We can do that because len(ciphertext) == len(plaintext) for RC4
                                sasl_signature = sasl_received_data[sasl_buffer_length - 10:]
                                sasl_received_data = sasl_received_data[:sasl_buffer_length - 10]  # retrieve encoded_message
                                kis = self.connection._digest_md5_kis  # renamed to lowercase GC
                                calculated_signature = bytes.fromhex(md5_hmac(kis, sasl_sec_num + sasl_received_data)[0:20])
                                if sasl_signature != calculated_signature:
                                    raise LDAPSignatureVerificationFailedError("Signature verification failed for the recieved LDAP message number " + str(int.from_bytes(sasl_sec_num, 'big')) + ". Expected signature " + calculated_signature.hex() + " but got " + sasl_signature.hex() + ".")
                                sasl_total_bytes_recieved = 0
                                unprocessed += sasl_received_data
                                sasl_received_data = b''
                        else:
                            unprocessed += data
                        data = b''
                    else:
                        listen = False
                length = BaseStrategy.compute_ldap_message_size(unprocessed)
                if length == -1 or len(unprocessed) < length:
                    get_more_data = True
                elif len(unprocessed) >= length:  # add message to message list
                    if self.connection.usage:
                        self.connection._usage.update_received_message(length)
                        if log_enabled(NETWORK):
                            log(NETWORK, 'received %d bytes via <%s>', length, self.connection)
                    if self.connection.fast_decoder:
                        ldap_resp = decode_message_fast(unprocessed[:length])
                        dict_response = self.connection.strategy.decode_response_fast(ldap_resp)
                    else:
                        ldap_resp = decoder.decode(unprocessed[:length], asn1Spec=LDAPMessage())[0]
                        dict_response = self.connection.strategy.decode_response(ldap_resp)
                    message_id = int(ldap_resp['messageID'])
                    if log_enabled(NETWORK):
                        log(NETWORK, 'received 1 ldap message via <%s>', self.connection)
                    if log_enabled(EXTENDED):
                        log(EXTENDED, 'ldap message received via <%s>:%s', self.connection, format_ldap_message(ldap_resp, '<<'))
                    if dict_response['type'] == 'extendedResp' and (dict_response['responseName'] == '1.3.6.1.4.1.1466.20037' or hasattr(self.connection, '_awaiting_for_async_start_tls')):
                        if dict_response['result'] == 0:  # StartTls in progress
                            if self.connection.server.tls:
                                self.connection.server.tls._start_tls(self.connection)
                            else:
                                self.connection.last_error = 'no Tls object defined in Server'
                                if log_enabled(ERROR):
                                    log(ERROR, '<%s> for <%s>', self.connection.last_error, self.connection)
                                raise LDAPSSLConfigurationError(self.connection.last_error)
                        else:
                            self.connection.last_error = 'asynchronous StartTls failed'
                            if log_enabled(ERROR):
                                log(ERROR, '<%s> for <%s>', self.connection.last_error, self.connection)
                            raise LDAPStartTLSError(self.connection.last_error)
                        del self.connection._awaiting_for_async_start_tls
                    if message_id != 0:  # 0 is reserved for 'Unsolicited Notification' from server as per RFC4511 (paragraph 4.4)
                        with self.connection.strategy.async_lock:
                            if self.connection.strategy._was_abandoned(message_id):
                                # the caller abandoned this request and already moved on: never let a late
                                # entry, reference or terminal result re-enter _responses or wake an event.
                                # An active quarantine is demoted to a tombstone by the terminal message,
                                # which also proves the server is done with the id; tombstone traffic is
                                # simply dropped.
                                terminal = dict_response['type'] not in ['searchResEntry', 'searchResRef', 'intermediateResponse']
                                if terminal and self.connection.strategy._is_abandoned(message_id):
                                    self.connection.strategy._release_abandoned_message(message_id)
                                if log_enabled(PROTOCOL):
                                    log(PROTOCOL, 'discarded late response of type <%s> for abandoned message id <%d> via <%s>', dict_response['type'], message_id, self.connection)
                            else:
                                if message_id in self.connection.strategy._responses:
                                    self.connection.strategy._responses[message_id].append(dict_response)
                                else:
                                    self.connection.strategy._responses[message_id] = [dict_response]
                                if dict_response['type'] not in ['searchResEntry', 'searchResRef', 'intermediateResponse']:
                                    self.connection.strategy._responses[message_id].append(RESPONSE_COMPLETE)
                                    self.connection.strategy.set_event_for_message(message_id)

                        with self.connection.strategy.async_lock:
                            is_abandoned = self.connection.strategy._was_abandoned(message_id)
                        if not is_abandoned and self.connection.strategy.can_stream:  # for AsyncStreamStrategy, used for PersistentSearch
                            self.connection.strategy.accumulate_stream(message_id, dict_response)
                        unprocessed = unprocessed[length:]
                        get_more_data = False if unprocessed else True
                        listen = True if self.connection.listening or unprocessed else False
                    else:  # Unsolicited Notification
                        if dict_response['responseName'] == '1.3.6.1.4.1.1466.20036':  # Notice of Disconnection as per RFC4511 (paragraph 4.4.1)
                            listen = False
                        else:
                            self.connection.last_error = 'unknown unsolicited notification from server'
                            if log_enabled(ERROR):
                                log(ERROR, '<%s> for <%s>', self.connection.last_error, self.connection)
                            raise LDAPStartTLSError(self.connection.last_error)
            self.connection.strategy.close()

    def __init__(self, ldap_connection):
        BaseStrategy.__init__(self, ldap_connection)
        self.sync = False
        self.no_real_dsa = False
        self.pooled = False
        self._responses = None
        self._requests = None
        self.can_stream = False
        self.receiver = None
        self.async_lock = Lock()
        self.event_lock = Lock()
        self._events = {}
        # message ids of requests that received an Abandon: an Abandon has no
        # server acknowledgement, so late entries/results for these ids must be
        # dropped and the ids themselves must not be reused on this socket.
        # Insertion ordered so the oldest quarantine entry can be evicted first;
        # the number of retained ids is bounded by ABANDONED_MESSAGE_RETENTION.
        # Values are:
        #   None -> active quarantine, late traffic is dropped and the id is
        #           refused at allocation time
        #   True -> tombstone, the bounded retention limit evicted the active
        #           entry; late traffic can no longer be matched (and is simply
        #           not stored), but the id still cannot be reused on this socket
        # Both kinds disappear with the socket (close/open start a new session).
        self._abandoned_messages = OrderedDict()

    def open(self, reset_usage=True, read_server_info=True):
        """
        Open connection and start listen on the socket in a different thread
        """
        with self.connection.connection_lock:
            self._responses = dict()
            self._requests = dict()
            self._reset_message_isolation_state()
            BaseStrategy.open(self, reset_usage, read_server_info)

        if read_server_info:
            try:
                self.connection.refresh_server_info()
            except LDAPOperationResult:  # catch errors from server if raise_exception = True
                self.connection.server._dsa_info = None
                self.connection.server._schema_info = None

    def _reset_message_isolation_state(self):
        """
        Clear every per-socket message bookkeeping structure.

        A new socket starts a fresh LDAP session with its own message id space,
        so quarantined ids and pending events from the previous socket cannot
        protect or contaminate the new one.
        """
        with self.async_lock:
            self._abandoned_messages = OrderedDict()
            self._events = dict()

    def _quarantine_limit(self):
        limit = get_config_parameter('ABANDONED_MESSAGE_RETENTION')
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 1024
        return limit if limit > 0 else 1024

    def _reserve_message_id(self, message_id):
        """
        Bookkeeping for a message id about to be sent on the socket.

        Refuses to hand out an id whose previous request was abandoned and is
        still quarantined: the Abandon has no response, so stale messages with
        that id could still be in flight and would be indistinguishable from
        the new request's responses.
        """
        with self.async_lock:
            if message_id in self._abandoned_messages:
                if log_enabled(ERROR):
                    log(ERROR, 'message id <%d> is quarantined as abandoned on <%s>, rebind the connection before reusing it', message_id, self.connection)
                raise LDAPMessageIDReuseError('message id %d is quarantined because the previous request was abandoned; '
                                              'reopen/rebind the connection to start a new session before sending further requests' % message_id)

    def abandon_message(self, message_id):
        """
        Move a locally cancelled request into the abandoned quarantine.

        Any response already buffered for the id is discarded and the waiting
        event, if any, is removed without being set: the abandoned caller gets
        no wake-up from late server traffic. The number of *active* quarantines
        (entries that still match and discard late traffic) is bounded by
        ABANDONED_MESSAGE_RETENTION: once the quota is full the oldest active
        entries are demoted to tombstones, which are cheap single dict entries.
        Both an active quarantine and a tombstone refuse the id at allocation
        time for the whole life of the socket, so an id can only be reused on a
        fresh LDAP session (close/reopen), never after a fixed delay or a
        guessed network drain.
        """
        with self.async_lock:
            self._abandoned_messages[message_id] = None
            self._responses.pop(message_id, None)
            self._events.pop(message_id, None)
            limit = self._quarantine_limit()
            active_ids = [mid for mid, state in self._abandoned_messages.items() if state is None]
            for evicted_message_id in active_ids[:max(0, len(active_ids) - limit)]:
                self._abandoned_messages[evicted_message_id] = True
                if log_enabled(PROTOCOL):
                    log(PROTOCOL, 'abandoned message id <%d> demoted to a reuse tombstone on <%s>', evicted_message_id, self.connection)

    def _is_abandoned(self, message_id):
        """Active quarantine: the id was abandoned and its terminal server
        message has not been seen and discarded yet (value is None)."""
        return message_id in self._abandoned_messages and self._abandoned_messages[message_id] is None

    def _was_abandoned(self, message_id):
        """True for both active quarantines and tombstones: the caller gave up
        on this id at some point on the current socket, so no response must ever
        be returned for it."""
        return message_id in self._abandoned_messages

    def active_abandoned_messages(self):
        """Message ids whose late traffic is still actively matched and discarded."""
        with self.async_lock:
            return [message_id for message_id, state in self._abandoned_messages.items() if state is None]

    def abandoned_tombstones(self):
        """Message ids demoted by the bounded retention limit or by their terminal
        response; reuse stays blocked until the socket is recreated."""
        with self.async_lock:
            return [message_id for message_id, state in self._abandoned_messages.items() if state is True]

    def _release_abandoned_message(self, message_id):
        """
        Demote an active quarantine entry to a tombstone once the terminal
        message of the abandoned request has been seen and discarded.

        Late traffic no longer needs active matching, but the id must stay
        non-returnable to the abandoned caller and non-reusable on this socket
        until a fresh socket session clears the bookkeeping.
        """
        if message_id not in self._abandoned_messages:
            return False
        self._abandoned_messages[message_id] = True
        return True

    def close(self):
        """
        Close connection and stop socket thread
        """
        with self.connection.connection_lock:
            BaseStrategy.close(self)
            # the socket is gone: every quarantined id belongs to this dead
            # session and a reopen gets a fresh message id space, so no stale
            # response can ever arrive anymore
            self._reset_message_isolation_state()

    def _add_event_for_message(self, message_id):
        with self.event_lock:
            # Should have the check here because the receiver thread may has created it
            if message_id not in self._events:
                self._events[message_id] = Event()

    def set_event_for_message(self, message_id):
        with self.event_lock:
            # The receiver thread may receive the response before the sender set the event for the message_id,
            # so we have to check if the event exists
            if message_id not in self._events:
                self._events[message_id] = Event()
            self._events[message_id].set()

    def _get_event_for_message(self, message_id):
        with self.event_lock:
            if message_id not in self._events:
                raise RuntimeError('Event for message[{}] should have been created before accessing'.format(message_id))
            return self._events[message_id]

    def post_send_search(self, message_id):
        """
        Clears connection.response and returns messageId
        """
        self.connection.response = None
        self.connection.request = None
        self.connection.result = None
        self._add_event_for_message(message_id)
        return message_id

    def post_send_single_response(self, message_id):
        """
        Clears connection.response and returns messageId.
        """
        self.connection.response = None
        self.connection.request = None
        self.connection.result = None
        self._add_event_for_message(message_id)
        return message_id

    def _start_listen(self):
        """
        Start thread in daemon mode
        """
        if not self.connection.listening:
            self.receiver = AsyncStrategy.ReceiverSocketThread(self.connection)
            self.connection.listening = True
            self.receiver.daemon = True
            self.receiver.start()

    def _get_response(self, message_id, timeout):
        """
        Performs the capture of LDAP response for this strategy
        The response is only complete after the event been set

        A request that received an Abandon is never woken up again: its event
        was removed when it entered the quarantine, so calling get_response()
        for it fails immediately with LDAPOperationAbandonedError instead of
        blocking until timeout. Late server traffic for the id is discarded by
        the receiver thread.
        """
        with self.async_lock:
            if self._was_abandoned(message_id):
                raise LDAPOperationAbandonedError('operation with message id %d was abandoned, no response can be returned' % message_id)
        try:
            event = self._get_event_for_message(message_id)
        except RuntimeError:
            # an abandon can land between the check above and the event lookup;
            # abandon_message removes the event, so treat a missing event as a
            # cancelled request rather than an internal assertion failure
            with self.async_lock:
                if self._was_abandoned(message_id):
                    raise LDAPOperationAbandonedError('operation with message id %d was abandoned, no response can be returned' % message_id)
            raise
        flag = event.wait(timeout)
        if not flag:
            # timeout
            return None

        # In this stage we could ensure the response is already there
        with self.event_lock:
            self._events.pop(message_id, None)
        with self.async_lock:
            if self._was_abandoned(message_id):
                # abandoned while waiting: whatever was buffered belongs to the
                # cancelled request and must not be handed to this caller
                self._responses.pop(message_id, None)
                raise LDAPOperationAbandonedError('operation with message id %d was abandoned, no response can be returned' % message_id)
            return self._responses.pop(message_id)

    def receiving(self):
        raise NotImplementedError

    def get_stream(self):
        raise NotImplementedError

    def set_stream(self, value):
        raise NotImplementedError
