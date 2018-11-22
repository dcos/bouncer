# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
Set up a root logger for all loggers used directly or indirectly by the test
environment. Configure its verbosity based on the --log-level command line
argument (INFO by default).

Set up a logger for the Bouncer hierarchy (Bouncer code directly executed by
py.test). Configure its verbosity based on the --bouncer-log-level command
line argument (disabled by default). Note that this setting does not affect
the log output of the Bouncer WSGI app spawned in a subprocess (whose output
goes to a log file).
"""


import logging


def configure_logger(pytest_config):

    tests_log_level = pytest_config.getoption('tests_log_level')
    bouncer_log_level = pytest_config.getoption('bouncer_log_level')
    rootlogger = logging.getLogger()
    bouncerlogger = logging.getLogger('bouncer')

    # Set up a stderr handler for the root logger, and specify the format.
    fmt = "%(asctime)s.%(msecs)03d %(name)s:%(lineno)s %(levelname)s: %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        datefmt="%y%m%d-%H:%M:%S"
        )

    # Decrease verbosity of 3rd party lib logs executed in the
    # context of the test runner.
    logging.getLogger('requests').setLevel(logging.ERROR)
    logging.getLogger('oic').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.ERROR)
    logging.getLogger('chardet').setLevel(logging.ERROR)

    if tests_log_level != 'disabled':
        level = getattr(logging, tests_log_level.upper())
        rootlogger.setLevel(level)
    else:
        rootlogger.handlers = []
        rootlogger.addHandler(logging.NullHandler())

    if bouncer_log_level != 'disabled':
        level = getattr(logging, bouncer_log_level.upper())
        bouncerlogger.setLevel(level)
    else:
        bouncerlogger.handlers = []
        bouncerlogger.addHandler(logging.NullHandler())
        bouncerlogger.propagate = False
