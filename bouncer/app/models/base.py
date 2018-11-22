# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

import contextlib
import logging

import sqlalchemy
from sqlalchemy.ext.declarative import declarative_base
import psycopg2.errorcodes

import bouncer.app.exceptions
from .session import dbsession


log = logging.getLogger(__name__)
DeclarativeBase = declarative_base()


class ModelBase:
    """SQLAlchemy-specific abstraction that is common among multiple entities.
    """

    @staticmethod
    def add(o):
        log.info('Insert `%s` into database.', o)
        with reraise_unique_violation():
            dbsession.add(o)
            dbsession.commit()


@contextlib.contextmanager
def reraise_unique_violation():
    try:
        yield
    except sqlalchemy.exc.IntegrityError as exc:
        if 'UNIQUE constraint failed' in str(exc):
            # This works with SQLite.
            raise bouncer.app.exceptions.EntityExists
        elif hasattr(exc.orig, 'pgcode'):
            # This works with CockroachDB.
            if exc.orig.pgcode == psycopg2.errorcodes.UNIQUE_VIOLATION:
                raise bouncer.app.exceptions.EntityExists
        raise
