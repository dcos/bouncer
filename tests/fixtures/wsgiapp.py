# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


import functools
import logging
import os
import shutil
import signal
import subprocess
import time

import pytest
import requests


from tests.misc import generate_RSA_keypair

WSGI_APP_EXIT_TIMEOUT = 5


log = logging.getLogger(__name__)


@pytest.fixture(scope='session')
def wsgi_app(tmpdir_factory, cockroach):
    # Create temporary directory, use config class name in dir name. Note
    # that py.test's base temporary directory management takes care of
    # deleting old contents. Ref: http://doc.pytest.org/en/latest/tmpdir.html
    tmpdir = tmpdir_factory.mktemp('TestConfigBase')
    terminator = wsgi_app_fixture_builder('TestConfigBase', 8101, tmpdir)
    try:
        yield
    finally:
        terminator()


@pytest.fixture(scope='session')
def wsgi_app_with_bootstrap_service_account(tmpdir_factory, cockroach):

    uid = 'superuser_service'
    privkey, pubkey = generate_RSA_keypair()

    env = {
        'SUPERUSER_SERVICE_ACCOUNT_UID': uid,
        'SUPERUSER_SERVICE_ACCOUNT_PUBLIC_KEY': pubkey,
        'SQLALCHEMY_DB_URL': cockroach.sql_alchemy_url_for_db('iam_with_sa'),
    }

    tmpdir = tmpdir_factory.mktemp('TestConfigSvcAcc')
    terminator = wsgi_app_fixture_builder('TestConfigBase', 8105, tmpdir, env)
    try:
        yield uid, pubkey, privkey
    finally:
        terminator()


def terminate_gunicorn(process):
    """Attempt to gracefully shut down Gunicorn.

    `process` is a subprocess object.
    """

    # Attempt to terminate first via SIGTERM (which triggers the graceful
    # shutdown procedure, invoking worker exit handlers).
    # See http://docs.gunicorn.org/en/19.7.1/signals.html
    log.info("Send SIGTERM to Gunicorn master process.")
    process.send_signal(signal.SIGTERM)

    log.info("wait() for Gunicorn master process.")
    try:
        process.wait(WSGI_APP_EXIT_TIMEOUT / 2.0)
    except subprocess.TimeoutExpired:
        # Send SIGQUIT, triggering fast, but friendly, shutdown
        # (not necessarily invoking worker exit handlers).
        log.info("Send SIGQUIT to Gunicorn master process.")
        process.send_signal(signal.SIGQUIT)

        log.info("wait() for Gunicorn master process.")
        try:
            process.wait(WSGI_APP_EXIT_TIMEOUT / 2.0)
        except subprocess.TimeoutExpired:
            log.info("Send SIGKILL to all Gunicorn processes.")
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    else:
        log.info("wait() returned.")
        return

    # Wait again, after os.killpg() above.
    log.info("wait() for Gunicorn master process.")
    process.wait()


def wait_for_wsgi_app_to_serve(bind_address, timeout):

    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            r = requests.get(
                'http://%s/acs/api/v1/users' % bind_address,
                timeout=1
                )
            if r.status_code == 200:
                return True
        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(0.1)

    return False


def wsgi_app_fixture_builder(configclass, port, tmpdir, env=None):
    # Prepare environment for child process.

    gunicorn_env = os.environ.copy()
    gunicorn_env['BOUNCER_CONFIG_CLASS'] = configclass
    gunicorn_env['SECRET_KEY_FILE_PATH'] = str(tmpdir.join('bouncer-secret.key'))

    if env is not None:
        gunicorn_env.update(env)

    log.info('Gunicorn process environment to be injected: %s', gunicorn_env)

    # Note: the log level specified for Gunicorn on the command line does not
    # influence the configuraiton of the Bouncer log handlers. In the context
    # of tests, Bouncer log handlers log on DEBUG level as configured by the
    # TestConfig class.

    # Build absolute path to gunicorn testconfig Python module.
    gunicorn_cfg_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), '..',
        'gunicorn-testconfig.py'
        )

    # The Bouncer web application spawned by the test runner runs side-by-side
    # with the test runner, i.e. in the same "environment" -- either in the same
    # container, or directly on the host. 127.0.0.1 is the intended way for the
    # test runner to reach the web applicaiton.
    bind_address = '127.0.0.1:%s' % port

    # Note(JP): commandline arguments override config file contents:
    # http://docs.gunicorn.org/en/stable/configure.html

    # Note(JP): Using a worker timeout of less than 2 seconds can be too short
    # on a weak or loaded system. Upon test startup, the worker process
    # bootstrap can be quite time-consuming (YAML apispec parsing, keypair
    # generation, datastore bootstrap contribute significantly). If it takes
    # longer than specified by the timeout, the gunicorn master kills the
    # worker and starts a fresh one. This can end up in an endless loop.
    # Enforce to use a single thread, so that profiling works (if activated).
    gunicorn_log_level = 'debug'
    args = [shutil.which("python3"),
            shutil.which('gunicorn'),
            '--config=%s' % gunicorn_cfg_path,
            '--timeout=60',
            '--threads=10',
            '--bind=%s' % bind_address,
            '--log-level={}'.format(gunicorn_log_level),
            'bouncer.app.load:wsgiapp'
            ]

    # Encode configuration class and port in log file name to make sure that
    # concurrenty running instances of Bouncer do not write to the same log
    # files.
    outerr_path = 'gunicorn_%s_%s.outerr' % (configclass, port)
    log.info(
        "Run WSGI app in child process (stdout/err -> %s, listen on %s)",
        outerr_path,
        bind_address
        )
    gproc_stdout = open(outerr_path, 'wb')
    gproc = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        stdout=gproc_stdout,
        env=gunicorn_env,
        universal_newlines=False,
        preexec_fn=os.setsid  # Attach session id (make process group leader)
        )
    try:
        # Close stdout stream on our (parent) end.
        gproc_stdout.close()

        log.info("Wait for Gunicorn to serve the WSGI app")
        # Make timeout a little longer than the worker --timeout specified in
        # the gunicorn run command above.
        if not wait_for_wsgi_app_to_serve(bind_address, timeout=61):

            pytest.fail(
                "Failed to start WSGI web server, exit code "
                "is %s. See %s." % (gproc.returncode, outerr_path)
                )

        log.info('App serves, proceed')

        terminator = functools.partial(terminate_gunicorn, process=gproc)
        return terminator
    except BaseException:
        # If exceptions occur while waiting for gunicorn to start, then the
        # fixture will not terminate gunicorn, so terminate it directly.  The
        # two likely causes of exceptions here are user-initiated Ctrl-C or a
        # Pytest failure where `wait_for_wsgi_app_to_serve` has not detected
        # start-up, but the processes are still running.  The
        # `KeyboardInterrupt` exception does not inherit from the standard
        # Python `Exception` class, and in PyTest 3.2+, neither do Pytest
        # failures. Hence, the unusual catch of `BaseException`.
        if gproc.poll() is None:
            log.info('Attempt to shut down Gunicorn.')
            terminate_gunicorn(gproc)
        raise
