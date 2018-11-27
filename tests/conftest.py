# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


import sys
import os


def pytest_addoption(parser):
    parser.addoption(
        '--test-log-level',
        type='choice',
        action='store',
        dest='tests_log_level',
        choices=['disabled', 'debug', 'info', 'warning', 'error', 'critical'],
        default='info',
        help='Set verbosity of the testing framework.'
        )
    parser.addoption(
        '--bouncer-log-level',
        type='choice',
        action='store',
        dest='bouncer_log_level',
        choices=['disabled', 'debug', 'info', 'warning', 'error', 'critical'],
        default='disabled',
        help=('Set verbosity of bouncer code executed in the '
              'context of the testing framework.')
        )


def pytest_configure(config):
    from tests.log import configure_logger
    configure_logger(config)


# Pytest itself ensures that the directory _this_ file lives in is part of
# sys.path. The following sys.path modification ensures that the root
# directory of the Bouncer repository is accessible and prioritzied for
# Python's import machinery.
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


# Use the pytest plugin system for loading modules which define fixtures which
# are supposed to be re-used across various test modules. The
# tests.fixtures.extension module is meant for downstream, exclusively.
pytest_plugins = [
    'tests.fixtures.wsgiapp',
    'tests.fixtures.containers',
    'tests.fixtures.extension',
]


# The test runner process triggers many urllib3-based HTTPS connections w/o
# performing cert verification (e.g. when interacting with Dex). Suppress these
# warnings (this takes effect globally).
import urllib3  # noqa: E402
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
