# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
Set up Python's logging infrastructure for the Bouncer web application.

Acquire root logger instance and populate it with handlers, applying a
certain log format. This takes effect for Bouncer code as well as integrated
libraries, such as Kazoo, ldap3.

A package or module within bouncer should obtain and use a logger instance
in the 'bouncer' sub-tree of the logging namespace hierarchy, via e.g.

    log = logging.getLogger('bouncer.xxx')
"""


import logging
import logging.handlers


bouncerconfig = None


def setup(level_stderr='ERROR', level_file='DEBUG', logfilepath='bouncer.log'):
    """Set up root logger for the Bouncer application.

    Args:
        level_stderr: `None` or a valid log level string.
        level_file: `None` or a valid log level string.
        logfilepath: Path to where a log file should be opened
            in append mode. Takes effect only when `level_file`
            defines a logging level.

    Valid log level strings:

        'NOTSET', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'

    Cf. https://docs.python.org/3/library/logging.html#levels

    Setting both levels to `None` will mute the root logger.
    """

    # Reset root logger configuration: remove existing handlers and don't
    # filter on logger level, but on handler level (pass all LogRecords
    # to attached handlers).
    rootlog = logging.getLogger()
    rootlog.handlers = []
    rootlog.setLevel(0)

    # Define formatter, to be applied to all handlers below.
    logfmt = ("[%(asctime)s.%(msecs)03d] [%(process)d:%(threadName)s] "
              "[%(name)s] %(levelname)s: %(message)s")
    datefmt = "%y%m%d-%H:%M:%S"
    formatter = logging.Formatter(fmt=logfmt, datefmt=datefmt)

    # Set up handlers.
    handlers = []
    if level_stderr:
        level = getattr(logging, level_stderr)
        h = logging.StreamHandler()
        h.setLevel(level)
        handlers.append(h)

    if level_file:
        level = getattr(logging, level_file)
        h = logging.handlers.RotatingFileHandler(
            filename=logfilepath,
            mode='a',
            maxBytes=5 * 1024 * 1024,
            backupCount=50,
            encoding='utf-8',
            delay=False
            )
        h.setLevel(level)
        handlers.append(h)

    # For newly defined handlers: set formatter, attach to root logger.
    for h in handlers:
        h.setFormatter(formatter)
        rootlog.addHandler(h)

    if not handlers:
        # Mute root logger (prevent logging.lastResort from taking effect).
        rootlog.addHandler(logging.NullHandler())

    # Conditionally modify the log level for the datastore logger. If that is
    # e.g. set to INFO while the root logger's level is set to DEBUG, then
    # datastore's debug messages will not arrive at the root logger.
    if bouncerconfig is not None:
        level = bouncerconfig.get('LOG_LEVEL_SQLALCHEMY', None)
        if level:
            sa_logger = logging.getLogger('sqlalchemy.engine')
            sa_logger.setLevel(getattr(logging, level))


# Pre-configure logging for configuration builder.
setup(level_stderr='DEBUG', level_file=None)
log = logging.getLogger('bouncer.logging')

# Trigger first application-wide import of the configuration module. This
# invokes the configuration builder.
log.info("Import configuration module from logging module")
from bouncer.config import config as bouncerconfig  # noqa: E402

# Re-configure logging using configuration details.
log.debug("Re-configure logging.")
setup(
    level_stderr=bouncerconfig['LOG_LEVEL_STDERR'],
    level_file=bouncerconfig['LOG_LEVEL_FILE']
    )
