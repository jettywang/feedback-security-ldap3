"""Identity-switch contract for the REUSABLE connection pool.

These tests run the real ReusableStrategy pool (real worker threads, queue,
locks and switch transaction) against an in-process directory simulator.
No socket is opened: the worker's RESTARTABLE Connection is replaced by a
FakeConnection that talks to a BindResponder, so bind pauses and bind failures
are fully deterministic and can be interleaved with submitted requests.
"""

from datetime import datetime
from threading import Event, Thread, Lock
from time import sleep

import pytest

from ldap3 import Server, Connection, REUSABLE, MOCK_SYNC, AUTO_BIND_NONE
from ldap3.core.exceptions import LDAPIdentitySwitchError, LDAPOperationsErrorResult, LDAPResponseTimeoutError
from ldap3.strategy.base import BaseStrategy
from ldap3.strategy.reusable import ReusableStrategy


class BindResponder(object):
    """Deterministic directory: records binds/searches and can fail or block."""

    def __init__(self):
        self.lock = Lock()
        self.bind_calls = []          # (user, password)
        self.executions = []          # (identity, tag)
        self.fail_bind = set()        # (user, password) pairs that fail
        self.fail_execute = {}        # tag -> exception class instance
        self.block_execute = {}       # tag -> Event that must be set before execution
        self.started = {}             # tag -> Event set when execution starts

    def bind(self, user, password):
        with self.lock:
            self.bind_calls.append((user, password))
            return (user, password) not in self.fail_bind

    def execute(self, identity, tag):
        with self.lock:
            self.executions.append((identity, tag))
            started = self.started.get(tag)
            block = self.block_execute.get(tag)
            failure = self.fail_execute.get(tag)
        if started is not None:
            started.set()
        if block is not None:
            block.wait(10)
        if failure is not None:
            raise failure
        return [{'type': 'searchResEntry', 'executed_by': identity, 'tag': tag}]


class FakeConnection(object):
    """Minimal RESTARTABLE Connection surface used by PooledConnectionThread."""

    def __init__(self, responder, identity):
        self.responder = responder
        self.user, self.password, self.authentication, self.sasl_mechanism, self.sasl_credentials = identity
        self.closed = True
        self.bound = False
        self.tls_started = False
        self.lazy = False
        self.result = None
        self._response = []

    def open(self, read_server_info=False):
        self.closed = False

    def unbind(self):
        self.bound = False
        self.closed = True

    def start_tls(self, read_server_info=False):
        self.tls_started = True
        return True

    def bind(self, read_server_info=False, controls=None):
        self.bound = self.responder.bind(self.user, self.password)
        return self.bound

    def send(self, message_type, request, controls=None):
        self._response = self.responder.execute(self.user, request)
        self.result = {'result': 0, 'description': 'success', 'type': 'searchResDone', 'executed_by': self.user, 'tag': request}
        return 1

    def post_send_search(self, counter):
        return self._response

    def post_send_single_response(self, counter):
        return self._response

    def refresh_server_info(self):
        pass

    def abandon(self, message_id):
        pass

    def __str__(self):
        return 'FakeConnection(user=%r)' % self.user


class Fixture(object):
    def __init__(self, name, users=('A', 'B'), pool_size=2):
        self.responder = BindResponder()
        self.pool_name = name
        self.server = Server('127.0.0.1', get_info=None)
        self.pool_size = pool_size
        self.connections = {}
        self._original_decode_request = BaseStrategy.decode_request
        # Patch on the class dict without turning it into an unbound function:
        # strategy code calls self.decode_request(...), so it must remain a
        # staticmethod-shaped callable after teardown as well.
        BaseStrategy.decode_request = staticmethod(_decode_request_stub)
        _install_worker_patch(self.fake_worker_for_pool)
        self.a = self.make_connection(users[0])
        self.a.open()

    def fake_worker_for_pool(self, worker, pool):
        worker.creation_time = datetime.now()
        if pool is not None:
            identity = pool.committed_identity
        else:
            identity = (worker.master_connection.user, worker.master_connection.password,
                        worker.master_connection.authentication, worker.master_connection.sasl_mechanism,
                        worker.master_connection.sasl_credentials)
        worker.connection = FakeConnection(self.responder, identity)

    def make_connection(self, user, password=None):
        connection = Connection(
            self.server,
            user=user,
            password=password if password is not None else 'pw-' + user,
            client_strategy=REUSABLE,
            auto_bind=AUTO_BIND_NONE,
            pool_name=self.pool_name,
            pool_size=self.pool_size,
            collect_usage=False,
        )
        self.connections[user] = connection
        return connection

    @property
    def pool(self):
        return self.a.strategy.pool

    def submit(self, connection, tag, message_type='searchRequest'):
        return connection.send(message_type, tag, None)

    def fetch(self, connection, counter, timeout=5):
        return connection.get_response(counter, timeout=timeout, get_request=True)

    def submit_and_fetch(self, connection, tag):
        counter = self.submit(connection, tag)
        response, result, request = self.fetch(connection, counter)
        return result

    def install_pause(self, step, once=True):
        entered = Event()
        release = Event()
        state = {'triggered': False, 'worker_ids': []}

        def hook(current_step, worker_id):
            if current_step == step and (not once or not state['triggered']):
                state['triggered'] = True
                state['worker_ids'].append(worker_id)
                entered.set()
                release.wait(10)

        self.pool._on_switch_step = hook
        return entered, release, state

    def switch_in_thread(self, connection, call='rebind'):
        outcome = {}

        def run():
            try:
                method = getattr(connection, call)
                outcome['result'] = method()
            except Exception as e:  # pragma: no cover - surfaced by the tests
                outcome['exception'] = e

        thread = Thread(target=run, daemon=True)
        thread.start()
        return thread, outcome

    def teardown(self):
        for connection in self.connections.values():
            try:
                connection.strategy.terminate()
            except Exception:
                pass
        ReusableStrategy.pools.pop(self.pool_name, None)
        _install_worker_patch(None)
        # assignment of a plain function back onto the class would make it an
        # unbound method; wrap it again so self.decode_request(...) keeps the
        # original staticmethod calling convention.
        BaseStrategy.decode_request = staticmethod(self._original_decode_request)


@pytest.fixture
def make_fixture():
    fixtures = []

    def factory(name='pool'):
        fixture = Fixture(name)
        fixtures.append(fixture)
        return fixture

    yield factory
    for fixture in fixtures:
        fixture.teardown()


_WORKER_PATCH = {'factory': None}


def _decode_request_stub(message_type, component, controls=None):
    return {'type': message_type, 'tag': component, 'controls': controls}


def _install_worker_patch(factory):
    """Install one process-wide worker replacement.

    The pool class stores ``new_connection`` on the class object, so tests
    must not each assign a different callable: the last fixture would win.
    Instead one dispatcher looks up the fixture that owns the pool through a
    per-pool name registry.
    """
    _WORKER_PATCH['factory'] = factory
    ReusableStrategy.PooledConnectionWorker.new_connection = _patched_new_connection


def _patched_new_connection(worker):
    pool = getattr(worker.master_connection.strategy, 'pool', None)
    factory = _WORKER_PATCH['factory']
    if factory is None:
        return _ORIGINAL_NEW_CONNECTION(worker)
    return factory(worker, pool)


_ORIGINAL_NEW_CONNECTION = ReusableStrategy.PooledConnectionWorker.new_connection
_install_worker_patch(None)


def test_queued_old_requests_execute_with_old_identity_across_switch(make_fixture):
    fixture = make_fixture('queued')
    a = fixture.a
    fixture.pool._on_switch_step = lambda step, worker_id: None

    # Block the first A request so the switch has to wait for the queue to drain.
    block = Event()
    started = Event()
    fixture.responder.block_execute['old-1'] = block
    fixture.responder.started['old-1'] = started

    counter1 = fixture.submit(a, 'old-1')
    fetch1 = {}
    thread1 = Thread(target=lambda: fetch1.update(result=fixture.fetch(a, counter1)), daemon=True)
    thread1.start()
    assert started.wait(5)

    counter2 = fixture.submit(a, 'old-2')  # queued while old-1 is in flight
    switch_thread, outcome = fixture.switch_in_thread(fixture.make_connection('B'))
    assert fixture.pool.identity_state == 'switching'
    sleep(0.1)
    assert ('B', 'old-2') not in fixture.responder.executions

    block.set()
    thread1.join(5)
    switch_thread.join(5)

    result1 = fetch1['result'][1]
    result2 = fixture.fetch(a, counter2)[1]
    assert result1['executed_by'] == 'A'
    assert result2['executed_by'] == 'A'
    assert outcome['result'] is True
    assert fixture.pool.committed_identity[0] == 'B'
    assert ('B', 'old-1') not in fixture.responder.executions
    assert ('B', 'old-2') not in fixture.responder.executions


@pytest.mark.parametrize('pause_step', ['before_unbind', 'before_bind', 'after_bind'])
def test_requests_injected_during_switch_are_attributed_by_identity(make_fixture, pause_step):
    fixture = make_fixture('pause-' + pause_step)
    a = fixture.a
    b = fixture.make_connection('B')
    entered, release, state = fixture.install_pause(pause_step)

    switch_thread, outcome = fixture.switch_in_thread(b)
    assert entered.wait(5)

    # A request submitted during the switch carries A's identity, which is not
    # the identity being confirmed: it must be rejected, never run as B.
    a_counter = fixture.submit(a, 'a-during')
    with pytest.raises(LDAPIdentitySwitchError):
        fixture.fetch(a, a_counter)

    # B submitted on the connection requesting the switch is held until the
    # switch commits, then runs as B and is delivered to B's caller.
    b_counter = fixture.submit(b, 'b-during')
    delivered = {}

    def fetch_b():
        delivered['value'] = fixture.fetch(b, b_counter)

    fetch_thread = Thread(target=fetch_b, daemon=True)
    fetch_thread.start()
    sleep(0.1)
    assert ('B', 'b-during') not in fixture.responder.executions

    release.set()
    switch_thread.join(5)
    fetch_thread.join(5)

    assert outcome['result'] is True
    result = delivered['value'][1]
    assert result['executed_by'] == 'B'
    assert ('A', 'a-during') not in fixture.responder.executions
    assert ('B', 'a-during') not in fixture.responder.executions
    assert fixture.pool.identity_state == 'ready'


def test_failed_switch_reports_failure_and_rejects_stale_and_inflight_requests(make_fixture, ):
    fixture = make_fixture('failed')
    a = fixture.a
    b = fixture.make_connection('B')
    fixture.responder.fail_bind.add(('B', 'pw-B'))
    entered, release, state = fixture.install_pause('before_bind')

    switch_thread, outcome = fixture.switch_in_thread(b)
    assert entered.wait(5)

    a_counter = fixture.submit(a, 'a-in-failed-switch')
    b_counter = fixture.submit(b, 'b-in-failed-switch')
    b_error = {}
    b_thread = Thread(target=lambda: b_error.update(error=_consume_error(fixture, b, b_counter)), daemon=True)
    b_thread.start()

    release.set()
    switch_thread.join(5)
    b_thread.join(5)

    assert outcome['result'] is False                 # never reports success
    assert fixture.pool.identity_state == 'failed'
    assert fixture.pool.committed_identity[0] == 'A'  # old identity stays committed
    assert fixture.pool.identity_version == 1
    assert isinstance(b_error['error'], LDAPIdentitySwitchError)
    with pytest.raises(LDAPIdentitySwitchError):
        fixture.fetch(a, a_counter)

    assert ('B', 'a-in-failed-switch') not in fixture.responder.executions
    assert ('B', 'b-in-failed-switch') not in fixture.responder.executions
    assert fixture.pool.last_error


def _consume_error(fixture, connection, counter):
    try:
        fixture.fetch(connection, counter)
        return None
    except Exception as e:
        return e


def test_failed_pool_allows_only_explicit_recovery_and_cleanup(make_fixture):
    fixture = make_fixture('recover')
    a = fixture.a
    b = fixture.make_connection('B')
    fixture.responder.fail_bind.add(('B', 'pw-B'))

    assert b.rebind() is False
    assert fixture.pool.identity_state == 'failed'

    # Ordinary work is refused while quarantined.
    counter = fixture.submit(a, 'blocked')
    with pytest.raises(LDAPIdentitySwitchError):
        fixture.fetch(a, counter)

    # A later explicit successful switch is allowed to recover the pool.
    fixture.responder.fail_bind.remove(('B', 'pw-B'))
    assert b.rebind() is True
    assert fixture.pool.identity_state == 'ready'
    assert fixture.pool.committed_identity[0] == 'B'
    assert fixture.pool.identity_version == 2
    assert fixture.submit_and_fetch(b, 'b-after-recovery')['executed_by'] == 'B'

    # A's requests are still rejected: a result is never delivered to A while
    # the pool is executing as B.
    with pytest.raises(LDAPIdentitySwitchError):
        fixture.submit_and_fetch(a, 'a-under-b')

    # A can only use the pool again through an explicit, confirmed switch back.
    assert a.rebind(user='A', password='pw-A') is True
    assert fixture.pool.committed_identity[0] == 'A'
    assert fixture.submit_and_fetch(a, 'a-after-switch-back')['executed_by'] == 'A'

    # Cleanup remains allowed on a failed/terminated pool.
    fixture.pool.identity_state = 'failed'
    fixture.pool.terminate_pool()
    assert fixture.pool.identity_state == 'terminated'


def test_failed_pool_allows_cleanup_without_discarding_results(make_fixture):
    fixture = make_fixture('cleanup')
    a = fixture.a
    b = fixture.make_connection('B')
    fixture.responder.fail_bind.add(('B', 'pw-B'))
    assert b.rebind() is False
    assert fixture.pool.identity_state == 'failed'

    blocked = fixture.submit(a, 'blocked')
    with pytest.raises(LDAPIdentitySwitchError):
        fixture.fetch(a, blocked)

    # A second rejection published while failed survives close/unbind cleanup
    # and can still be attributed to its own message id afterwards.
    survivor = fixture.submit(a, 'blocked-survivor')
    a.unbind()
    with pytest.raises(LDAPIdentitySwitchError):
        fixture.fetch(a, survivor)

    # terminate is allowed and settles deferred requests, not the queue.
    fixture.pool.terminate_pool()
    assert fixture.pool.identity_state == 'terminated'


def test_rejections_are_delivered_through_get_response(make_fixture):
    # REUSABLE is asynchronous: search/add/compare return a message id and the
    # caller retrieves the result with get_response.  A pool rejection must be
    # raised there, on the original message id only.
    fixture = make_fixture('wrappers')
    a = fixture.a

    fixture.pool.identity_state = 'failed'
    counter = fixture.submit(a, 'wrapped-search')
    with pytest.raises(LDAPIdentitySwitchError):
        fixture.fetch(a, counter)
    with pytest.raises(LDAPResponseTimeoutError):
        # the rejection was consumed exactly once, on its own message id
        fixture.fetch(a, counter, timeout=0.2)

    # Recovery restores ordinary dispatch for the confirmed identity.
    b = fixture.make_connection('B')
    assert b.rebind() is True
    assert fixture.pool.identity_state == 'ready'
    assert fixture.pool.identity_version == 2
    result = fixture.submit_and_fetch(b, 'after-wrapper-recovery')
    assert result['executed_by'] == 'B'


def test_results_and_exceptions_are_returned_to_their_original_request(make_fixture):
    fixture = make_fixture('attribution')
    a = fixture.a
    b = fixture.make_connection('B')
    assert b.rebind() is True

    fixture.responder.fail_execute['boom'] = LDAPOperationsErrorResult(1, 'simulated failure')
    ok_counter = fixture.submit(b, 'ok-1')
    boom_counter = fixture.submit(b, 'boom')

    ok = fixture.fetch(b, ok_counter)[1]
    with pytest.raises(LDAPOperationsErrorResult):
        fixture.fetch(b, boom_counter)

    # The exception is not leaked to the next request on another message id.
    after = fixture.submit_and_fetch(b, 'ok-2')
    assert ok['executed_by'] == 'B' and ok['tag'] == 'ok-1'
    assert after['executed_by'] == 'B' and after['tag'] == 'ok-2'


class MockDirectoryFixture(object):
    """Runs REUSABLE workers over a real MockSyncStrategy directory.

    Credentials are validated by mock_bind and operations really execute
    against the mock DIT, while the worker lifecycle still runs in the pool
    threads.
    """

    def __init__(self, name):
        self.server = Server('mock', get_info=None)
        self.seed = Connection(self.server, user='cn=A,ou=test', password='pwA',
                               client_strategy=MOCK_SYNC, auto_bind=None, check_names=False)
        for dn, attrs in [('cn=A,ou=test', {'userPassword': 'pwA', 'cn': 'A'}),
                          ('cn=B,ou=test', {'userPassword': 'pwB', 'cn': 'B'}),
                          ('cn=C,ou=test', {'userPassword': 'pwC', 'cn': 'C'}),
                          ('ou=test', {'objectClass': ['top', 'organizationalUnit'], 'ou': 'test'})]:
            self.seed.strategy.add_entry(dn, attrs, validate=False)
        self.pool_name = name
        _install_worker_patch(self.mock_worker_for_pool)

    def mock_worker_for_pool(self, worker, pool):
        identity = pool.committed_identity
        worker.creation_time = datetime.now()
        worker.connection = Connection(self.server, user=identity[0], password=identity[1],
                                       client_strategy=MOCK_SYNC, auto_bind=AUTO_BIND_NONE,
                                       check_names=False, lazy=False,
                                       raise_exceptions=worker.master_connection.raise_exceptions)

    def connection(self, user, password):
        return Connection(self.server, user=user, password=password, client_strategy=REUSABLE,
                          auto_bind=AUTO_BIND_NONE, pool_name=self.pool_name, pool_size=2,
                          check_names=False, collect_usage=False)

    def teardown(self):
        ReusableStrategy.pools.pop(self.pool_name, None)
        _install_worker_patch(None)


@pytest.fixture
def make_mock_directory():
    fixtures = []

    def factory(name='mockdir'):
        fixture = MockDirectoryFixture(name)
        fixtures.append(fixture)
        return fixture

    yield factory
    for fixture in fixtures:
        fixture.teardown()


def test_real_mock_directory_switch_is_all_or_nothing(make_mock_directory):
    directory = make_mock_directory('real-switch')
    a = directory.connection('cn=A,ou=test', 'pwA')
    a.open()

    assert a.search('ou=test', '(cn=A)', attributes=['cn'])
    assert [worker.connection.user for worker in a.strategy.pool.workers] == ['cn=A,ou=test'] * 2

    assert a.rebind(user='cn=B,ou=test', password='pwB') is True
    assert [worker.connection.user for worker in a.strategy.pool.workers] == ['cn=B,ou=test'] * 2
    assert a.search('ou=test', '(cn=B)', attributes=['cn'])

    # Failed confirmation: reported as failure, old identity stays committed,
    # and ordinary operations are refused even with raise_exceptions=False.
    assert a.rebind(user='cn=C,ou=test', password='wrong') is False
    assert a.strategy.pool.identity_state == 'failed'
    assert a.strategy.pool.committed_identity[0] == 'cn=B,ou=test'
    assert a.strategy.pool.identity_version == 2
    assert a.last_error == 'invalidCredentials'

    with pytest.raises(LDAPIdentitySwitchError):
        # REUSABLE returns the message id; the rejection is raised when the
        # caller collects that request's response (even with
        # raise_exceptions=False).
        a.get_response(a.search('ou=test', '(cn=B)', attributes=['cn']))
    with pytest.raises(LDAPIdentitySwitchError):
        a.get_response(a.compare('cn=B,ou=test', 'cn', 'B'))

    # Only an explicit confirmed switch recovers the pool.
    assert a.rebind(user='cn=A,ou=test', password='pwA') is True
    assert a.strategy.pool.identity_state == 'ready'
    assert a.strategy.pool.committed_identity[0] == 'cn=A,ou=test'
    assert a.strategy.pool.identity_version == 3
    assert a.search('ou=test', '(cn=A)', attributes=['cn'])
