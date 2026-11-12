"""
"""

# Created on 2014.03.23
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

from datetime import datetime
from os import linesep
from threading import Thread, Lock, RLock
from time import sleep

from .. import RESTARTABLE, get_config_parameter, AUTO_BIND_DEFAULT, AUTO_BIND_NONE, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_AFTER_BIND, AUTO_BIND_TLS_BEFORE_BIND
from .base import BaseStrategy
from ..core.usage import ConnectionUsage
from ..core.exceptions import LDAPConnectionPoolNameIsMandatoryError, LDAPConnectionPoolNotStartedError, LDAPOperationResult, LDAPException, \
    LDAPExceptionError, LDAPResponseTimeoutError, LDAPIdentitySwitchError
from ..utils.log import log, log_enabled, ERROR, BASIC
from ..protocol.rfc4511 import LDAP_MAX_INT

TERMINATE_REUSABLE = 'TERMINATE_REUSABLE_CONNECTION'

BOGUS_BIND = -1
BOGUS_UNBIND = -2
BOGUS_EXTENDED = -3
BOGUS_ABANDON = -4

try:
    from queue import Queue, Empty
except ImportError:  # Python 2
    # noinspection PyUnresolvedReferences
    from Queue import Queue, Empty


# noinspection PyProtectedMember
class ReusableStrategy(BaseStrategy):
    """
    A pool of reusable SyncWaitRestartable connections with lazy behaviour and limited lifetime.
    The connection using this strategy presents itself as a normal connection, but internally the strategy has a pool of
    connections that can be used as needed. Each connection lives in its own thread and has a busy/available status.
    The strategy performs the requested operation on the first available connection.
    The pool of connections is instantiated at strategy initialization.
    Strategy has two customizable properties, the total number of connections in the pool and the lifetime of each connection.
    When lifetime is expired the connection is closed and will be open again when needed.
    """
    pools = dict()

    def receiving(self):
        raise NotImplementedError

    def _start_listen(self):
        raise NotImplementedError

    def _get_response(self, message_id, timeout):
        raise NotImplementedError

    def get_stream(self):
        raise NotImplementedError

    def set_stream(self, value):
        raise NotImplementedError

    # noinspection PyProtectedMember
    class ConnectionPool(object):
        """
        Container for the Connection Threads
        """
        def __new__(cls, connection):
            if connection.pool_name in ReusableStrategy.pools:  # returns existing connection pool
                pool = ReusableStrategy.pools[connection.pool_name]
                if not pool.started:  # if pool is not started remove it from the pools singleton and create a new onw
                    del ReusableStrategy.pools[connection.pool_name]
                    return object.__new__(cls)
                if connection.pool_keepalive and pool.keepalive != connection.pool_keepalive:  # change lifetime
                    pool.keepalive = connection.pool_keepalive
                if connection.pool_lifetime and pool.lifetime != connection.pool_lifetime:  # change keepalive
                    pool.lifetime = connection.pool_lifetime
                if connection.pool_size and pool.pool_size != connection.pool_size:  # if pool size has changed terminate and recreate the connections
                    pool.terminate_pool()
                    pool.pool_size = connection.pool_size
                return pool
            else:
                return object.__new__(cls)

        def __init__(self, connection):
            if not hasattr(self, 'workers'):
                self.name = connection.pool_name
                self.master_connection = connection
                self.workers = []
                self.pool_size = connection.pool_size or get_config_parameter('REUSABLE_THREADED_POOL_SIZE')
                self.lifetime = connection.pool_lifetime or get_config_parameter('REUSABLE_THREADED_LIFETIME')
                self.keepalive = connection.pool_keepalive
                self.request_queue = Queue()
                self.open_pool = False
                self.bind_pool = False
                self.tls_pool = False
                self._incoming = dict()
                self.counter = 0
                self.terminated_usage = ConnectionUsage() if connection._usage else None
                self.terminated = False
                self.pool_lock = RLock()  # reentrant: linearizes submission, version commit and response publication
                self.switch_lock = RLock()  # serializes identity switches; reentrant for validate_bind -> switch_identity
                self.identity_version = 1  # version of the identity that has been confirmed on every worker
                self.identity_state = 'ready'  # ready | switching | failed | terminated
                self.committed_identity = self._identity_from_connection(connection)  # identity confirmed for identity_version
                self.pending_identity = None  # identity being confirmed while identity_state == 'switching'
                self.pending_version = None  # identity version assigned to requests submitted during a switch
                self.deferred_requests = []  # requests submitted during a switch, dispatched only after confirmation
                self.terminal_rejections = dict()  # rejected message ids, kept across close/unbind cleanup
                self.last_error = None
                ReusableStrategy.pools[self.name] = self
                self.started = False
                if log_enabled(BASIC):
                    log(BASIC, 'instantiated ConnectionPool: <%r>', self)

        def __str__(self):
            s = 'POOL: ' + str(self.name) + ' - status: ' + ('started' if self.started else 'terminated')
            s += ' - responses in queue: ' + str(len(self._incoming))
            s += ' - pool size: ' + str(self.pool_size)
            s += ' - lifetime: ' + str(self.lifetime)
            s += ' - keepalive: ' + str(self.keepalive)
            s += ' - open: ' + str(self.open_pool)
            s += ' - bind: ' + str(self.bind_pool)
            s += ' - tls: ' + str(self.tls_pool) + linesep
            s += 'MASTER CONN: ' + str(self.master_connection) + linesep
            s += 'WORKERS:'
            if self.workers:
                for i, worker in enumerate(self.workers):
                    s += linesep + str(i).rjust(5) + ': ' + str(worker)
            else:
                s += linesep + '    no active workers in pool'

            return s

        def __repr__(self):
            return self.__str__()

        def get_info_from_server(self):
            for worker in self.workers:
                with worker.worker_lock:
                    if not worker.connection.server.schema or not worker.connection.server.info:
                        worker.get_info_from_server = True
                    else:
                        worker.get_info_from_server = False

        def rebind_pool(self, connection=None, controls=None):
            # The identity is taken from the connection that requested the
            # switch.  Other Connection objects sharing this pool keep their
            # own credentials; their requests are rejected until their own
            # identity is confirmed by a successful switch, so a result can
            # never be delivered to a caller under a different identity.
            identity_connection = connection if connection is not None else self.master_connection
            return self.switch_identity(self._identity_from_connection(identity_connection), controls)

        def start_pool(self):
            if not self.started:
                self.identity_state = 'ready'
                self.create_pool()
                for worker in self.workers:
                    with worker.worker_lock:
                        worker.thread.start()
                self.started = True
                self.terminated = False
                if log_enabled(BASIC):
                    log(BASIC, 'worker started for pool <%s>', self)
                return True
            return False

        def create_pool(self):
            if log_enabled(BASIC):
                log(BASIC, 'created pool <%s>', self)
            self.workers = [ReusableStrategy.PooledConnectionWorker(self.master_connection, self.request_queue) for _ in range(self.pool_size)]

        def _identity_from_connection(self, connection):
            """Immutable snapshot of everything that determines the directory identity.

            The version is bumped only after this identity has been confirmed by
            every worker and reported as successful to callers.
            """
            return (connection.user,
                    connection.password,
                    connection.authentication,
                    connection.sasl_mechanism,
                    connection.sasl_credentials)

        def _apply_identity_to_connection(self, connection, identity):
            (connection.user, connection.password, connection.authentication,
             connection.sasl_mechanism, connection.sasl_credentials) = identity

        def switch_identity(self, identity, controls=None):
            """Atomically move the pool from its confirmed identity to a new one.

            Contract:
            * Requests already queued keep the identity version they were
              submitted with and are executed before the switch takes effect.
            * Requests sent while the switch is in progress keep their own
              identity snapshot and are held; they are executed only after the
              new identity is confirmed, and only if the connection that
              submitted them is the one being confirmed.  On a failed switch
              they are answered with LDAPIdentitySwitchError instead of being
              executed with the old or new credentials.
            * No worker credentials are changed before the pool is idle.  A
              confirmation bind happens on a single, dedicated worker; only
              after it succeeds are the remaining workers rebound.  A worker
              whose rebind fails is left out of service and the pool is
              marked failed; the new identity is never reported as committed.
            * The committed identity (and its version) is only updated after
              every worker has confirmed the new identity.
            """
            with self.switch_lock:
                if not self.started:
                    raise LDAPConnectionPoolNotStartedError('connection pool not started')
                if self.identity_state == 'terminated':
                    raise LDAPConnectionPoolNotStartedError('connection pool terminated')
                with self.pool_lock:
                    self.identity_state = 'switching'
                    self.pending_identity = identity
                    self.pending_version = self.identity_version + 1
                    self.last_error = None

                # Wait for operations already submitted to be drained. New
                # submissions see identity_state == 'switching' and are
                # deferred/rejected, so this cannot wait forever.
                self._drain_request_queue()

                try:
                    rebound = self._rebind_all_workers(identity, controls)
                except Exception as e:
                    self._mark_switch_failed(LDAPIdentitySwitchError('identity switch failed: ' + str(e)))
                    return False
                if not rebound:
                    self._mark_switch_failed(LDAPIdentitySwitchError('identity switch failed: ' + str(self.last_error or 'unknown error')))
                    return False

                # All workers confirmed the new identity. Commit the identity
                # and the version under pool_lock so submission cannot
                # observe the new version before the commit or vice versa.
                with self.pool_lock:
                    self.committed_identity = identity
                    self.identity_version = self.pending_version
                    self.pending_identity = None
                    self.pending_version = None
                    self.identity_state = 'ready'
                    self.bind_pool = True
                    self._dispatch_deferred_requests()
                return True

        def _mark_switch_failed(self, exception):
            # Mark the quarantine and answer every deferred request under one
            # lock: no later submission can observe a 'switching' pool after
            # this point and no deferred request can be dispatched afterwards.
            with self.pool_lock:
                self.identity_state = 'failed'
                self.pending_identity = None
                self.pending_version = None
                self.last_error = self.last_error or str(exception)
                self._fail_deferred_requests(exception)

        def _drain_request_queue(self):
            # request_queue.join() alone is not enough because a request may
            # have been fetched by a worker but not yet task_done(). Wait for
            # both the queue and all busy workers.
            self.request_queue.join()
            while True:
                with self.pool_lock:
                    busy_workers = [worker for worker in self.workers if worker.busy]
                if not busy_workers:
                    break
                sleep(0.01)

        def validate_identity_on_worker(self, identity, controls=None):
            """Confirm credentials on one worker without changing pool identity.

            Used by bind() when the requested identity is already the committed
            one: the pool must still prove the credentials against the server
            before reporting a successful bind.
            """
            worker = self._select_confirmation_worker()
            if worker is None:
                return False
            with worker.worker_lock:
                worker.busy = True
                try:
                    if not worker.connection.closed:
                        try:
                            worker.connection.unbind()
                        except LDAPExceptionError:
                            pass
                    self._apply_identity_to_connection(worker.connection, identity)
                    worker.connection.open(read_server_info=False)
                    old_lazy = worker.connection.lazy
                    worker.connection.lazy = False
                    try:
                        if self.tls_pool and not worker.connection.tls_started:
                            worker.connection.start_tls(read_server_info=False)
                        result = worker.connection.bind(read_server_info=False, controls=controls)
                    finally:
                        worker.connection.lazy = old_lazy
                    return result is not False
                finally:
                    worker.busy = False

        def _rebind_all_workers(self, identity, controls=None):
            # Confirm the new identity on one worker first. Other workers
            # continue to execute (already drained) work with the old identity
            # until confirmation succeeds. If confirmation fails, no worker
            # has changed identity, so queued/deferred requests cannot leak
            # across identities.
            confirmation_worker = self._select_confirmation_worker()
            if confirmation_worker is None:
                return False
            try:
                if not self._rebind_worker(confirmation_worker, identity, controls):
                    return False
            except LDAPException as e:
                self.last_error = str(e)
                return False

            failed_workers = []
            for worker in self.workers:
                if worker is confirmation_worker:
                    continue
                try:
                    if not self._rebind_worker(worker, identity, controls):
                        failed_workers.append(worker)
                except LDAPException as e:
                    self.last_error = str(e)
                    failed_workers.append(worker)
            if failed_workers:
                # The identity is not confirmed pool-wide; workers that were
                # not rebound still hold the old identity, but the pool is
                # quarantined (identity_state == 'failed') so no request can
                # be dispatched until a later switch succeeds.
                return False
            return True

        def _select_confirmation_worker(self):
            # Prefer a worker that is not currently handling a request; its
            # worker_lock serializes with any request the worker may take.
            for worker in self.workers:
                if not worker.busy:
                    return worker
            return None

        def _rebind_worker(self, worker, identity, controls=None):
            worker_id = id(worker)
            with worker.worker_lock:
                worker.busy = True
                try:
                    self._on_switch_step('before_unbind', worker_id)
                    if not worker.connection.closed:
                        try:
                            worker.connection.unbind()
                        except LDAPExceptionError:
                            pass
                    self._on_switch_step('before_bind', worker_id)
                    self._apply_identity_to_connection(worker.connection, identity)
                    worker.connection.open(read_server_info=False)
                    old_lazy = worker.connection.lazy
                    worker.connection.lazy = False
                    try:
                        if self.tls_pool and not worker.connection.tls_started:
                            worker.connection.start_tls(read_server_info=False)
                        result = worker.connection.bind(read_server_info=False, controls=controls)
                    finally:
                        worker.connection.lazy = old_lazy
                    self._on_switch_step('after_bind', worker_id)
                    if result is False:
                        self.last_error = worker.connection.last_error or 'bind failed'
                        return False
                    return True
                finally:
                    worker.busy = False

        def _on_switch_step(self, step, worker_id):
            # Test hook: deterministic pause points inside the identity switch.
            # A test can block here to inject requests and observe the contract.
            pass

        def _fail_deferred_requests(self, exception):
            with self.pool_lock:
                deferred, self.deferred_requests = self.deferred_requests, []
                for counter, message_type, request, controls, version in deferred:
                    self.terminal_rejections[counter] = (exception, None, None)

        def _dispatch_deferred_requests(self):
            # Called while switch_lock is held.  Each deferred request was
            # validated against the identity being confirmed at submission
            # time, so it is queued together with the version that has just
            # been committed.  No new submission can interleave: submit_request
            # takes pool_lock and observes identity_state == 'switching' until
            # the caller of switch_identity commits.
            with self.pool_lock:
                deferred, self.deferred_requests = self.deferred_requests, []
                for counter, message_type, request, controls, version in deferred:
                    self.request_queue.put((counter, message_type, request, controls, version))

        def submit_request(self, connection, message_type, request, controls):
            """Allocate a counter and atomically bind the request to an identity.

            The identity check, counter allocation and enqueue/defer/reject
            decision are made under one lock so a switch cannot commit
            between them.
            """
            with self.pool_lock:
                if not self.started:
                    raise LDAPConnectionPoolNotStartedError('connection pool not started')
                if self.identity_state == 'terminated':
                    raise LDAPConnectionPoolNotStartedError('connection pool terminated')
                self.counter += 1
                if self.counter > LDAP_MAX_INT:
                    self.counter = 1
                counter = self.counter

                identity = self._identity_from_connection(connection)
                if self.identity_state == 'failed':
                    self._reject(counter, 'connection pool identity switch failed; request not executed')
                elif self.identity_state == 'switching':
                    if identity == self.pending_identity:
                        # Submitted by a connection whose identity equals the
                        # identity being confirmed: safe to run only after it
                        # has been confirmed on every worker.
                        self.deferred_requests.append((counter, message_type, request, controls, self.pending_version))
                    else:
                        self._reject(counter, 'request identity is not the identity being confirmed; request not executed')
                elif identity != self.committed_identity:
                    self._reject(counter, 'request identity is not the committed identity; request not executed')
                else:
                    self.request_queue.put((counter, message_type, request, controls, self.identity_version))
                return counter

        def _reject(self, counter, message):
            # Publish the failure under the caller's own message id; get_response
            # raises it for that request only.  Keep it in a terminal-rejection
            # map so close()/unbind() cleanup cannot lose it before the caller
            # retrieves it.
            self.terminal_rejections[counter] = (LDAPIdentitySwitchError(message), None, None)

        def terminate_pool(self):
            if not self.terminated:
                if log_enabled(BASIC):
                    log(BASIC, 'terminating pool <%s>', self)
                with self.switch_lock:
                    with self.pool_lock:
                        self.identity_state = 'terminated'
                        self.started = False
                    self.request_queue.join()  # waits for all queue pending operations
                    for _ in range(len([worker for worker in self.workers if worker.thread.is_alive()])):  # put a TERMINATE signal on the queue for each active thread
                        self.request_queue.put((TERMINATE_REUSABLE, None, None, None, None))
                    self.request_queue.join()  # waits for all queue terminate operations
                    self.terminated = True
                    self._fail_deferred_requests(LDAPConnectionPoolNotStartedError('connection pool terminated'))
                    if log_enabled(BASIC):
                        log(BASIC, 'pool terminated for <%s>', self)

    class PooledConnectionThread(Thread):
        """
        The thread that holds the Reusable connection and receive operation request via the queue
        Result are sent back in the pool._incoming list when ready
        """
        def __init__(self, worker, master_connection):
            Thread.__init__(self)
            self.daemon = True
            self.worker = worker
            self.master_connection = master_connection
            if log_enabled(BASIC):
                log(BASIC, 'instantiated PooledConnectionThread: <%r>', self)

        # noinspection PyProtectedMember
        def run(self):
            self.worker.running = True
            terminate = False
            pool = self.master_connection.strategy.pool
            while not terminate:
                try:
                    counter, message_type, request, controls, version = pool.request_queue.get(block=True, timeout=self.master_connection.strategy.pool.keepalive)
                except Empty:  # issue an Abandon(0) operation to keep the connection live - Abandon(0) is a harmless operation
                    if not self.worker.connection.closed:
                        self.worker.connection.abandon(0)
                    continue

                with self.worker.worker_lock:
                    self.worker.busy = True
                    try:
                        if counter == TERMINATE_REUSABLE:
                            terminate = True
                            if self.worker.connection.bound:
                                try:
                                    self.worker.connection.unbind()
                                    if log_enabled(BASIC):
                                        log(BASIC, 'thread terminated')
                                except LDAPExceptionError:
                                    pass
                        elif message_type in ('bindRequest', 'unbindRequest', 'abandonRequest'):  # control operations, not tied to a caller request
                            if message_type == 'bindRequest':
                                try:
                                    if self.worker.connection.closed:
                                        self.worker.connection.open(read_server_info=False)
                                    self.worker.connection.bind(controls=controls, read_server_info=False)
                                except (LDAPOperationResult, LDAPExceptionError):
                                    pass
                            elif message_type == 'unbindRequest':
                                try:
                                    self.worker.connection.unbind()
                                except LDAPExceptionError:
                                    pass
                            else:  # abandon cannot be executed with multiple connections
                                pass
                        else:
                            try:
                                if version != pool.identity_version:  # request belongs to a superseded identity, never execute it
                                    with pool.pool_lock:
                                        pool._incoming[counter] = (LDAPIdentitySwitchError('stale identity version; request not executed'), None, None)
                                else:
                                    if self.worker.creation_time is not None and (datetime.now() - self.worker.creation_time).seconds >= self.master_connection.strategy.pool.lifetime:  # destroy and create a new connection
                                        try:
                                            self.worker.connection.unbind()
                                        except LDAPExceptionError:
                                            pass
                                        self.worker.new_connection()
                                        if log_enabled(BASIC):
                                            log(BASIC, 'thread respawn')
                                    if message_type not in ['bindRequest', 'unbindRequest']:
                                        if pool.open_pool and self.worker.connection.closed:
                                            self.worker.connection.open(read_server_info=False)
                                            if pool.tls_pool and not self.worker.connection.tls_started:
                                                self.worker.connection.start_tls(read_server_info=False)
                                            if pool.bind_pool and not self.worker.connection.bound:
                                                self.worker.connection.bind(read_server_info=False)
                                        elif pool.open_pool and not self.worker.connection.closed:  # connection already open, issues a start_tls
                                            if pool.tls_pool and not self.worker.connection.tls_started:
                                                self.worker.connection.start_tls(read_server_info=False)
                                        if self.worker.get_info_from_server and counter:
                                            self.worker.connection.refresh_server_info()
                                            self.worker.get_info_from_server = False
                                        response = None
                                        result = None
                                        if message_type == 'searchRequest':
                                            response = self.worker.connection.post_send_search(self.worker.connection.send(message_type, request, controls))
                                        else:
                                            response = self.worker.connection.post_send_single_response(self.worker.connection.send(message_type, request, controls))
                                        result = self.worker.connection.result
                                        with pool.pool_lock:
                                            pool._incoming[counter] = (response, result, BaseStrategy.decode_request(message_type, request, controls))
                            except LDAPOperationResult as e:  # raise_exceptions has raised an exception. It must be redirected to the original connection thread
                                with pool.pool_lock:
                                    pool._incoming[counter] = (e, None, None)
                            except LDAPException as e:  # a communication error must not kill the response of the original request
                                with pool.pool_lock:
                                    pool._incoming[counter] = (e, None, None)
                            except Exception as e:  # never strand a caller's message id
                                with pool.pool_lock:
                                    pool._incoming[counter] = (LDAPExceptionError(str(e)), None, None)
                    finally:
                        self.worker.busy = False
                        pool.request_queue.task_done()
                        self.worker.task_counter += 1
            if log_enabled(BASIC):
                log(BASIC, 'thread terminated')
            if self.master_connection.usage:
                pool.terminated_usage += self.worker.connection.usage
            self.worker.running = False

    class PooledConnectionWorker(object):
        """
        Container for the restartable connection. it includes a thread and a lock to execute the connection in the pool
        """
        def __init__(self, connection, request_queue):
            self.master_connection = connection
            self.request_queue = request_queue
            self.running = False
            self.busy = False
            self.get_info_from_server = False
            self.connection = None
            self.creation_time = None
            self.task_counter = 0
            self.new_connection()
            self.thread = ReusableStrategy.PooledConnectionThread(self, self.master_connection)
            self.worker_lock = Lock()
            if log_enabled(BASIC):
                log(BASIC, 'instantiated PooledConnectionWorker: <%s>', self)

        def __str__(self):
            s = 'CONN: ' + str(self.connection) + linesep + '       THREAD: '
            s += 'running' if self.running else 'halted'
            s += ' - ' + ('busy' if self.busy else 'available')
            s += ' - ' + ('created at: ' + self.creation_time.isoformat())
            s += ' - time to live: ' + str(self.master_connection.strategy.pool.lifetime - (datetime.now() - self.creation_time).seconds)
            s += ' - requests served: ' + str(self.task_counter)

            return s

        def new_connection(self):
            from ..core.connection import Connection
            # New workers are built from the identity the pool has confirmed,
            # not from the master Connection object (which may be in the middle
            # of an unconfirmed switch).
            pool = getattr(self.master_connection.strategy, 'pool', None)
            if pool is not None:
                identity = pool.committed_identity
            else:
                identity = (self.master_connection.user, self.master_connection.password,
                            self.master_connection.authentication, self.master_connection.sasl_mechanism,
                            self.master_connection.sasl_credentials)
            # noinspection PyProtectedMember
            self.creation_time = datetime.now()
            self.connection = Connection(server=self.master_connection.server_pool if self.master_connection.server_pool else self.master_connection.server,
                                         user=identity[0],
                                         password=identity[1],
                                         auto_bind=AUTO_BIND_NONE,  # do not perform auto_bind because it reads again the schema
                                         version=self.master_connection.version,
                                         authentication=identity[2],
                                         client_strategy=RESTARTABLE,
                                         auto_referrals=self.master_connection.auto_referrals,
                                         auto_range=self.master_connection.auto_range,
                                         sasl_mechanism=identity[3],
                                         sasl_credentials=identity[4],
                                         check_names=self.master_connection.check_names,
                                         collect_usage=self.master_connection._usage,
                                         read_only=self.master_connection.read_only,
                                         raise_exceptions=self.master_connection.raise_exceptions,
                                         lazy=False,
                                         fast_decoder=self.master_connection.fast_decoder,
                                         receive_timeout=self.master_connection.receive_timeout,
                                         return_empty_attributes=self.master_connection.empty_attributes)

            # simulates auto_bind, always with read_server_info=False
            if self.master_connection.auto_bind and self.master_connection.auto_bind not in [AUTO_BIND_NONE, AUTO_BIND_DEFAULT]:
                if log_enabled(BASIC):
                    log(BASIC, 'performing automatic bind for <%s>', self.connection)
                self.connection.open(read_server_info=False)
                if self.master_connection.auto_bind == AUTO_BIND_NO_TLS:
                    self.connection.bind(read_server_info=False)
                elif self.master_connection.auto_bind == AUTO_BIND_TLS_BEFORE_BIND:
                    self.connection.start_tls(read_server_info=False)
                    self.connection.bind(read_server_info=False)
                elif self.master_connection.auto_bind == AUTO_BIND_TLS_AFTER_BIND:
                    self.connection.bind(read_server_info=False)
                    self.connection.start_tls(read_server_info=False)

            if self.master_connection.server_pool:
                self.connection.server_pool = self.master_connection.server_pool
                self.connection.server_pool.initialize(self.connection)

    # ReusableStrategy methods
    def __init__(self, ldap_connection):
        BaseStrategy.__init__(self, ldap_connection)
        self.sync = False
        self.no_real_dsa = False
        self.pooled = True
        self.can_stream = False
        if hasattr(ldap_connection, 'pool_name') and ldap_connection.pool_name:
            self.pool = ReusableStrategy.ConnectionPool(ldap_connection)
        else:
            if log_enabled(ERROR):
                log(ERROR, 'reusable connection must have a pool_name')
            raise LDAPConnectionPoolNameIsMandatoryError('reusable connection must have a pool_name')

    def open(self, reset_usage=True, read_server_info=True):
        # read_server_info not used
        self.pool.open_pool = True
        self.pool.start_pool()
        self.connection.closed = False
        if self.connection.usage:
            if reset_usage or not self.connection._usage.initial_connection_start_time:
                self.connection._usage.start()

    def terminate(self):
        self.pool.terminate_pool()
        self.pool.open_pool = False
        self.connection.bound = False
        self.connection.closed = True
        self.pool.bind_pool = False
        self.pool.tls_pool = False

    def _close_socket(self):
        """
        Doesn't really close the socket
        """
        self.connection.closed = True

        if self.connection.usage:
            self.connection._usage.closed_sockets += 1

    def _stop_listen(self):
        # The pool owns the sockets.  Closing the master connection is a
        # cleanup operation and must not discard queued/failed results: it
        # leaves the pool threads alive and only marks the master closed.
        self.connection.listening = False
        self.connection.closed = True

    def send(self, message_type, request, controls=None):
        if self.pool.started:
            if message_type == 'bindRequest':
                self.pool.bind_pool = True
                counter = BOGUS_BIND
            elif message_type == 'unbindRequest':
                self.pool.bind_pool = False
                counter = BOGUS_UNBIND
            elif message_type == 'abandonRequest':
                counter = BOGUS_ABANDON
            elif message_type == 'extendedReq' and self.connection.starting_tls:
                self.pool.tls_pool = True
                counter = BOGUS_EXTENDED
            else:
                # Ordinary requests are bound to the identity snapshot taken
                # at submission time and are never executed with other
                # credentials; the pool defers or rejects them as appropriate.
                counter = self.pool.submit_request(self.connection, message_type, request, controls)
            return counter
        if log_enabled(ERROR):
            log(ERROR, 'reusable connection pool not started')
        raise LDAPConnectionPoolNotStartedError('reusable connection pool not started')

    def validate_bind(self, controls):
        # Bind validation implements the explicit switch contract: the new
        # identity is confirmed pool-wide before success is reported.  A
        # failed switch leaves the pool quarantined and the caller unbound.
        # The master Connection is only updated on behalf of the caller when
        # it requested the switch; other Connection objects sharing the pool
        # keep their own credentials.
        with self.pool.switch_lock:
            new_identity = self.pool._identity_from_connection(self.connection)
            if new_identity != self.pool.committed_identity or self.pool.identity_state != 'ready':
                rebound = self.pool.switch_identity(new_identity, controls)
                if not rebound:
                    if self.pool.last_error:
                        self.connection.last_error = self.pool.last_error
                    self.connection.bound = False
                    return False
            elif not self.pool.validate_identity_on_worker(new_identity, controls):
                # A failed validation of the already-committed identity does
                # not weaken the pool contract: no identity was changed.
                self.connection.bound = False
                return False
            if self.connection is self.pool.master_connection:
                self.pool._apply_identity_to_connection(self.pool.master_connection, new_identity)
            self.connection.bound = True
            return True

    def get_response(self, counter, timeout=None, get_request=False):
        sleeptime = get_config_parameter('RESPONSE_SLEEPTIME')
        request=None
        if timeout is None:
            timeout = get_config_parameter('RESPONSE_WAITING_TIMEOUT')
        if counter == BOGUS_BIND:  # send a bogus bindResponse
            response = list()
            result = {'description': 'success', 'referrals': None, 'type': 'bindResponse', 'result': 0, 'dn': '', 'message': '<bogus Bind response>', 'saslCreds': None}
        elif counter == BOGUS_UNBIND:  # bogus unbind response
            response = None
            result = None
        elif counter == BOGUS_ABANDON:  # abandon cannot be executed because of multiple connections
            response = list()
            result = {'result': 0, 'referrals': None, 'responseName': '1.3.6.1.4.1.1466.20037', 'type': 'extendedResp', 'description': 'success', 'responseValue': 'None', 'dn': '', 'message': '<bogus StartTls response>'}
        elif counter == BOGUS_EXTENDED:  # bogus startTls extended response
            response = list()
            result = {'result': 0, 'referrals': None, 'responseName': '1.3.6.1.4.1.1466.20037', 'type': 'extendedResp', 'description': 'success', 'responseValue': 'None', 'dn': '', 'message': '<bogus StartTls response>'}
            self.connection.starting_tls = False
        else:
            response = None
            result = None
            while timeout > 0:  # waiting for completed message to appear in _incoming
                try:
                    with self.connection.strategy.pool.pool_lock:
                        response, result, request = self.connection.strategy.pool._incoming.pop(counter)
                        break
                except KeyError:
                    pass
                try:
                    with self.connection.strategy.pool.pool_lock:
                        response, result, request = self.connection.strategy.pool.terminal_rejections.pop(counter)
                        break
                except KeyError:
                    pass
                sleep(sleeptime)
                timeout -= sleeptime

            if timeout <= 0:
                if log_enabled(ERROR):
                    log(ERROR, 'no response from worker threads in Reusable connection')
                raise LDAPResponseTimeoutError('no response from worker threads in Reusable connection')

        if isinstance(response, Exception):
            # Includes LDAPOperationResult from raise_exceptions and
            # LDAPIdentitySwitchError / communication errors produced by the
            # pool.  They are raised for the original request only.
            raise response

        if get_request:
            return response, result, request

        return response, result

    def post_send_single_response(self, counter):
        return counter

    def post_send_search(self, counter):
        return counter
