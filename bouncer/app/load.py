# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
This module is to be imported by the WSGI server. Specifically, it exposes the
`wsgiapp` object which is intended to be consumed by the WSGI server.

Load Bouncer, order matters.

1. Perform initialization defined in bouncer.app.__init__.py
2. Conditionally bootstrap database.
3. Import WSGI application object (triggers app import chain, i.e.
   requires database abstraction as well as config details
   from bouncer.app).
"""


import faulthandler
import logging
import os
import signal
import sys
import threading

import bouncer.logutil  # noqa: F401
import bouncer.app
from bouncer.app import config, db
from bouncer.utils import set_up_app_tempdir


# Load Alembic to register the CockroachDB dialect.
import bouncer.alembic


log = logging.getLogger(__name__)


log.info('Loading app package.')


def _rawout(msg):
    """
    Bypass canonical print/logging here, and instead write bytes directly to
    the underlying stdout file descriptor. This works around Python's IO stack
    reentrancy protection. Do pre and post flushing in order to limit message
    interleaving.
    """
    sys.stdout.buffer.flush()
    sys.stdout.buffer.write(('_rawout: %s\n' % msg).encode('ascii'))
    sys.stdout.buffer.flush()


def terminate_worker_process(called_from_signal_handler=False):
    """Shut down current gunicorn worker process.

    Attempt to gracefully shut down the worker process. The worker process
    shutdown method used here is tied to gunicorn's 'sync' worker model used
    together with threads, and is prepared for being invoked from

        - the main thread
        - a thread other than the main thread
        - a signal handler within the main thread.

    For the case where invocation happens from a thread other than the main
    thread, one of the established graceful approaches to shut down the
    containing process is to raise a KeyboardInterrupt exception in the main
    thread via `_thread.interrupt_main()`. Here, in the special case of a
    gunicorn worker process, it however makes more sense to send a SIGTERM to
    the process, which according to gunicorn documentation triggers a graceful
    worker shutdown.

    For reliably terminating the worker process after a short grace period,
    install a thread-based Timer invoking CPython's `os._exit` which calls the
    system's _exit() function specified at
    http://pubs.opengroup.org/onlinepubs/9699919799/functions/_Exit.html

    This function might be called from within a signal handler and we're doing
    an unusually large amount of work here. Notes on that:
    1) Bypass Python's IO stack via _rawout()
    2) _exit(), getpid(), kill() are safe to be called from within a signal
    handler according to
    http://pubs.opengroup.org/onlinepubs/009695399/functions/xsh_chap02_04.html
    """

    def _kill():
        _rawout('Call os._exit(1)')
        os._exit(1)

    current_thread = threading.current_thread()
    _rawout(
        'terminate_worker_process() in thread `%s`. signal handler: %s' %
        (current_thread.name, called_from_signal_handler))
    is_mainthread = current_thread == threading.main_thread()

    # Non-gracefully and reliably take down worker process after a short grace
    # period, no matter from where this function was invoked (main thread or
    # not main thread, and if main thread: from a signal handler or not from a
    # signal handler).
    _rawout('Install _exit() timer')
    exittimer = threading.Timer(5.0, _kill)
    # Set daemon flag: run timer thread w/o blocking the process from exiting.
    exittimer.daemon = True
    exittimer.start()

    if not is_mainthread:
        # Attempt to gracefully shut down the worker process. Delegate this
        # work to the main thread by sending a signal to my own process
        # (signal handlers are executed in the main thread).
        assert not called_from_signal_handler
        _rawout('Sending SIGTERM to my own process')
        # Flush stdout and stderr before interrupting ourselves with SIGTERM.
        sys.stdout.flush()
        sys.stderr.flush()
        os.kill(os.getpid(), signal.SIGTERM)
        return

    # At this point, we're in the main thread any _may_ be within a signal
    # handler. The _exit() timer has been installed (maybe even multiple
    # times). Attempt to gracefully shut down whatever needs to be gracefully
    # shut down, there is not much time left until we're dead :-).
    try:
        pass
        # TODO(jp): anything we should do here?
    finally:
        if called_from_signal_handler:
            _rawout("Rely on original SIGTERM handler to invoke exit logic")
            return
        # Raise SystemExit (in the main thread that actually leads to
        # interpreter shutdown, as opposed to being called from within a
        # thread other than the main thread).
        sys.exit(1)


def _exit_signal_handler(signalnbr, frame):
    _rawout('Worker %s received signal %s' % (
        os.getpid(), _signals_nbr_name_mapping[signalnbr]))
    terminate_worker_process(called_from_signal_handler=True)
    _rawout('Call original SIGTERM handler')
    _original_sigterm_handler(signalnbr, frame)


def _install_signal_handlers():
    log.info('Installing exit handler for SIGTERM, SIGQUIT.')
    for s in (signal.SIGTERM, signal.SIGQUIT):
        signal.signal(s, _exit_signal_handler)
    log.info('Installing stacktrace dumper for SIGUSR2.')
    faulthandler.register(
        signal.SIGUSR2, file=sys.stderr, all_threads=True, chain=False)


def _initialize_database():
    log.info('Trigger database setup.')
    with bouncer.logutil.temporary_log_level('sqlalchemy.engine', logging.INFO):
        db.conditional_bootstrap()


_initialize_database()


# Set up signal handlers.
_original_sigterm_handler = signal.getsignal(signal.SIGTERM)
_signals_nbr_name_mapping = dict(
    (getattr(signal, n), n)
    for n in dir(signal) if n.startswith('SIG') and '_' not in n)
_install_signal_handlers()


# Set the temporary directory.
_cleanup_app_temp_dir = not config['TESTING']
bouncer.app.tempdir_abspath = set_up_app_tempdir(
    name='dcos-iam',
    cleanup_dir=_cleanup_app_temp_dir,
    )

# Import last, requires previous definitions.
from bouncer.app.wsgiapp import wsgiapp  # noqa: E402,F401
