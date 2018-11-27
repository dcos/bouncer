# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


import contextlib
import logging

log = logging.getLogger('bouncer.logutil')


@contextlib.contextmanager
def temporary_log_level(logger_name, tmp_level):
    """
    A context manager that sets the log level of a logger for the duration of the block.

    This only increases the logging level. If the requested logging level is lower than
    the existing logging level, nothing is changed.

    Args:
        logger_name (str): The name of the logger to set the log level of.
        tmp_level (logging level, eg. logging.DEBUG): The temporary log level.
    """
    logger = logging.getLogger(logger_name)
    if logger.isEnabledFor(tmp_level):
        tmp_level_name = logging.getLevelName(tmp_level)
        previous_level = logger.level
        previous_level_name = logging.getLevelName(previous_level)
        logger.setLevel(tmp_level)
        log.debug('Set `{name}` log level {previous_level} -> {tmp_level}'.format(
            name=logger_name,
            previous_level=previous_level_name,
            tmp_level=tmp_level_name,
            ))
        try:
            yield
        finally:
            logger.setLevel(previous_level)
            log.debug('Restored `{name}` log level {tmp_level} -> {previous_level}'.format(
                name=logger_name,
                tmp_level=tmp_level_name,
                previous_level=previous_level_name,
                ))
    else:
        yield
