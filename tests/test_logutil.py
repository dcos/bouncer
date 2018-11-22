import logging

from bouncer.logutil import temporary_log_level


class TestTemporaryLogLevel:

    def test_temp_logging_level_higher(self):
        logger = logging.getLogger('test')
        logger.setLevel(logging.INFO)
        assert logger.getEffectiveLevel() == logging.INFO
        with temporary_log_level('test', logging.WARN):
            assert logger.getEffectiveLevel() == logging.WARN
        assert logger.getEffectiveLevel() == logging.INFO

    def test_temp_logging_level_lower(self):
        logger = logging.getLogger('test')
        logger.setLevel(logging.INFO)
        assert logger.getEffectiveLevel() == logging.INFO
        with temporary_log_level('test', logging.DEBUG):
            assert logger.getEffectiveLevel() == logging.INFO
        assert logger.getEffectiveLevel() == logging.INFO

    def test_temp_logging_level_inherited(self):
        logger = logging.getLogger('test')
        sublogger = logging.getLogger('test.sub')
        logger.setLevel(logging.INFO)
        assert sublogger.getEffectiveLevel() == logging.INFO
        with temporary_log_level('test.sub', logging.WARN):
            assert sublogger.getEffectiveLevel() == logging.WARN
        assert sublogger.getEffectiveLevel() == logging.INFO
        # logger still inherits log level
        logger.setLevel(logging.ERROR)
        assert sublogger.getEffectiveLevel() == logging.ERROR
