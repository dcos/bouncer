# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""SQLAlchemy session abstraction and database management.

One major task of this module: expose `dbsession`. From The SQLAlchemy docs:

    "The Session will begin a new transaction if it is used again, subsequent to
    the previous transaction ending; from this it follows that the Session is
    capable of having a lifespan across many transactions, though only one at a
    time. We refer to these two concepts as transaction scope and session scope.
    [...] A common choice is to tear down the Session at the same time the
    transaction ends, meaning the transaction and session scopes are the same.
    [...] A web application is the easiest case because such an application is
    already constructed around a single, consistent scope - this is the request,
    which represents an incoming request from a browser, the processing of that
    request to formulate a response, and finally the delivery of that response
    back to the client. [...] In those situations where the integration
    libraries are not provided or are insufficient, SQLAlchemy includes its own
    “helper” class known as scoped_session."

Create sessionmaker. From the SQLAlchemy docs:

    "Just one time, somewhere in your application’s global scope. It should be
    looked upon as part of your application’s configuration."

SQLAlchemy's `scoped_session` is a wrapper around a Python thread-local
variable. Because each HTTP request is as of now handled in its own thread, a
session is effectively tied to the process of handling an individual HTTP
request. The `dbsession` object can be used anywhere in the code and can be
thought of to yield the same session when staying within the context of a
certain HTTP request, but to yield a different session for each request context.
The most important property to keep in mind is that `dbsession` will
automatically yield the same session when using it multiple times within an HTTP
request-handling code path. From the SQLAlchemy docs:

    "Implicit Method Access: The job of the scoped_session is simple; hold onto
    a Session for all who ask for it. As a means of producing more transparent
    access to this Session, the scoped_session also includes proxy behavior,
    meaning that the registry itself can be treated just like a Session
    directly; when methods are called on this object, they are proxied to the
    underlying Session being maintained by the registry.""

    "This pattern allows disparate sections of the application to call upon a
    global scoped_session, so that all those areas may share the same session
    without the need to pass it explicitly."

Useful video/talk resource:

    - https://youtu.be/5SSC6nU314c
    - Specifically:
      https://www.youtube.com/watch?v=5SSC6nU314c&feature=youtu.be&t=889

Recommended commit/teardown of the session:

    "As the request ends, the Session is torn down as well, usually through the
    usage of event hooks provided by the web framework. The transaction used by
    the Session may also be committed at this point, or alternatively the
    application may opt for an explicit commit pattern, only committing for
    those requests where one is warranted, but still always tearing down the
    Session unconditionally at the end."

After HTTP response generation, session cleanup is initiated via
`bouncer.app.wsgiapp.SQLAlchemySessionMiddleware`.
"""

import logging
import os

import psycopg2
import psycopg2.errorcodes
import sqlalchemy
import sqlalchemy.exc
import sqlalchemy.orm
import sqlalchemy.orm.session
import sqlalchemy.schema
from sqlalchemy.engine.url import make_url
from cockroachdb.sqlalchemy.dialect import savepoint_state

import bouncer.app.exceptions
from bouncer.config import config


log = logging.getLogger(__name__)


# NOTE(jp): instead of the scoped session which is thread-local and therefore
# implicitly request-local, we could in the future use a more simple session
# registry and tie it to the current Falcon request.


log.info(
    'Create database engine. URL: %s -- connect args: %s',
    config['SQLALCHEMY_DB_URL'],
    config['SQLALCHEMY_CONNECT_ARGS']
)


_engine = sqlalchemy.create_engine(
    config['SQLALCHEMY_DB_URL'],
    echo=False,
    connect_args=config['SQLALCHEMY_CONNECT_ARGS']
)

if config['SQLALCHEMY_DB_URL'].startswith('cockroachdb://'):
    _session_factory = sqlalchemy.orm.session.sessionmaker(
        bind=_engine, autocommit=True)
else:
    _session_factory = sqlalchemy.orm.session.sessionmaker(
        bind=_engine, autocommit=False)


dbsession = sqlalchemy.orm.scoped_session(_session_factory)
log.info('Created `dbsession` object: %s', dbsession)


alembic_cfg = None
if os.path.isdir(config['ALEMBIC_DIR_PATH']):
    import alembic
    import alembic.config
    alembic_cfg = alembic.config.Config()
    alembic_cfg.set_main_option('script_location', config['ALEMBIC_DIR_PATH'])
    log.info('Built Alembic configuration: %s', alembic_cfg)
else:
    log.info('Not using Alembic')
    # For now, the Alembic machinery is only used downstream.
    pass


# Late imports, on purpose
log.info('Import database model modules ...')
from .base import DeclarativeBase  # noqa: E402
from .config import ConfigItem  # noqa: E402


class Database:
    """Database abstraction. Provide utilities used in the application."""

    def __init__(self, testing_mode):
        self._testing_mode = testing_mode

    def requires_bootstrap(self):
        return _requires_bootstrap()

    def conditional_bootstrap(self):
        # The database cannot be created inside a transaction so we ensure it's
        # existence before defining and running the retryable callback.
        _create_database_if_not_exists()

        if not _requires_bootstrap():
            log.info('Database appears to be populated, skip bootstrap.')
            if alembic_cfg is not None:
                log.info('Performing migrations.')
                alembic.command.upgrade(alembic_cfg, 'head')
                log.info('Migrations completed.')
            return

        log.info('Database appears to be not populated, trigger bootstrap.')
        def callback():
            log.info('Performing bootstrap procedure.')
            _bootstrap()

        run_transaction(callback)

    def create_database_if_not_exists(self):
        _create_database_if_not_exists()

    def create_empty_tables(self):
        log.info('Create (empty) database tables.')
        _create_db_tables()

    def reset(self, do_bootstrap):
        if not self._testing_mode:
            log.warning('Database reset only allowed in TESTING mode.')
            return

        log.info('Database reset: delete table contents')
        _empty_db_tables()

        if do_bootstrap:
            log.info('Database reset: insert bootstrap contents')
            _bootstrap()
        else:
            dbsession.commit()

    def drop(self):
        if not self._testing_mode:
            log.warning('Database `drop` only allowed in TESTING mode.')
            return
        _drop_database_if_exists()

    def dump(self):
        """Serialize current database contents."""
        if not self._testing_mode:
            log.warning('Database dump only allowed in TESTING mode.')
            return
        raise NotImplementedError

    def load(self, data):
        """Reset database to the state defined by `data`."""
        if not self._testing_mode:
            log.warning('Database load only allowed in TESTING mode.')
            return
        raise NotImplementedError

    def achieve_value_consensus(self, key, value):
        log.info('Achieve consensus among the IAM instances on key `%s`.', key)
        item = ConfigItem(key, value)
        try:
            ConfigItem.add(item)
            log.info('Consensus: I have set the key `%s` for the others.', key)
            return value
        except bouncer.app.exceptions.EntityExists:
            log.info('Consensus: already set, read it.')
            # The `rollback()` was observed to be necessary with CockroachDB.
            # Note(JP): this code path does not seem to be exercised by DC/OS
            # where bootstrap always writes the key file before Bouncer
            # launches.
            dbsession.rollback()

        return dbsession.query(ConfigItem).filter_by(key=key).one().value


def _create_database_if_not_exists():
    """Create the database if it doesn't already exist."""
    # The `sqlalchemy_utils.create_database` function does not understand TLS
    # connection parameters as it operates on the URL alone, so we implement our
    # own.
    if _engine.dialect.name == 'sqlite' and _engine.url.database == ':memory:':
        return

    # For postgresql (and cockroachdb) SQLAlchemy dialect checks availability of
    # features (and version) by running queries against live DB connection. An
    # error is thrown if the database specified in the connection string does
    # not exist. As such, we set the database to the builtin 'system' database
    # so the connection succeeds.
    url = make_url(config['SQLALCHEMY_DB_URL'])
    url.database = 'system'
    temp_engine = sqlalchemy.create_engine(
        url,
        echo=False,
        connect_args=config['SQLALCHEMY_CONNECT_ARGS']
        )
    log.info('Create database if it does not already exist.')
    with temp_engine.connect() as conn:
        conn.execute("create database if not exists {};".format(_engine.url.database))
    temp_engine.dispose()


def _drop_database_if_exists():
    """Drop the database."""
    if _engine.dialect.name == 'sqlite' and _engine.url.database == ':memory:':
        return
    with _engine.connect() as conn:
        conn.execute("drop database if exists {};".format(_engine.url.database))


def _requires_bootstrap():
    """Detect a fresh install.

    Return `True` if the database appears to require a bootstrap procedure. For
    starters, decide that based on the existence of the `users` table.
    """
    log.info('Identify whether the `users` table exists.')
    try:
        r = _engine.dialect.has_table(dbsession.connection(), 'users')
        log.info('`users` table exists: %s', r)
        return not r
    except sqlalchemy.exc.ProgrammingError as exc:
        if hasattr(exc.orig, 'pgcode'):
            # This works with CockroachDB.
            if exc.orig.pgcode == psycopg2.errorcodes.INVALID_CATALOG_NAME:
                log.info('Database `iam` does not exist.')
                return True
        raise


def _create_db_tables():
    """Create all tables required by the current SQLAlchemy model metadata.

    Do not attempt recreate tables already present in the database.
    """
    # We use the current session connection instead of the _engine itself so
    # table creation forms part of the same transaction that populates
    DeclarativeBase.metadata.create_all(dbsession.connection())


def _empty_db_tables():
    """Make sure that all tables are empty.

    A drop_all()/create_all() is a little slower than deleting individual table
    contents, especially when not using an in-memory database, as of the file
    system operations.
    """
    log.info('Delete contents of all DB tables except the alembic_version table')
    # We need to create a new MetaData as `reflect()` mutates the
    # instance it is called on which would add an "alembic_versions"
    # table to DeclarativeBase.metadata if we used it.
    meta = sqlalchemy.schema.MetaData()
    meta.reflect(_engine)
    for table in meta.sorted_tables:
        if table.name == 'alembic_version':
            # Keep the list of migrations that have been run so we dun't rerun
            # migrations in the future.
            continue
        dbsession.execute(table.delete())


def _stamp_schema_revision(rev):
    """Stamp the database schema revision to `rev`.

    This method creates the `alembic_version` table if it doesn't
    already exist and inserts a record into it that sets the schema
    version to `rev`.

    Args:
        rev (str):
            The migration revision to mark the schema as upgraded to,
            or 'head' to mark it as up to date.
    """
    alembic.command.stamp(alembic_cfg, rev)


def _bootstrap():
    """Bootstrap database: create tables, populate with initial data.

    Assume to see an empty database (no relevant tables yet).
    """
    log.info('Create (empty) database tables.')

    from .bootstrap import insert_bootstrap_data

    _create_db_tables()

    insert_bootstrap_data(dbsession, bouncer_config=config)

    log.info('insert_bootstrap_data() is done')

    if alembic_cfg is not None:
        log.info('Perform Alembic `stamp`')
        # Mark the schema revision as up to date.
        _stamp_schema_revision('head')

    dbsession.commit()


def run_transaction(callback):
    return _txn_retry_loop(dbsession, callback)


class _NestedTransaction(object):
    """Wraps begin_nested() to set the savepoint_state thread-local.
    This causes the savepoint statements that are a part of this retry
    loop to be rewritten by the dialect.
    """
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        self.conn.begin_nested()
        # Sessions are lazy and don't execute the savepoint
        # query until you ask for the connection.
        self.conn.connection()
        return self

    def __exit__(self, typ, value, tb):
        # Ignore exceptions used for control flow such as falcon
        # redirects.  We should consider explicitly ignoring falcon
        # redirects and rolling back on all other exceptions
        # instead. Using exceptions for control flow, sigh.
        if typ is not None and issubclass(typ, sqlalchemy.exc.SQLAlchemyError):
            self.conn.rollback()


def _txn_retry_loop(conn, callback):
    """Inner transaction retry loop.
    ``conn`` may be either a Connection or a Session, but they both
    have compatible ``begin()`` and ``begin_nested()`` methods.
    """

    # Using cockroachdb it is never legal to start or end a nested
    # transaction while it is `False` as doing so would cause a `RELEASE
    # SAVEPOINT {name}` or `ROLLBACK TO SAVEPOINT {name}` instruction
    # where `name != 'cockroach_restart`.
    #
    # As cockroach_restart is a thread-local variable it is not enough
    # to set it globally. It must be set by every thread. As such,
    # we set it here, before it gets used by any thread.
    savepoint_state.cockroach_restart = True
    with conn.begin():
        while True:
            try:
                with _NestedTransaction(conn):
                    ret = callback()
                    return ret
            except sqlalchemy.exc.DatabaseError as e:
                if isinstance(e.orig, psycopg2.OperationalError):
                    if e.orig.pgcode == psycopg2.errorcodes.SERIALIZATION_FAILURE:
                        continue
                raise


if not config['SQLALCHEMY_DB_URL'].startswith('cockroachdb://'):
    # Replace `run_transaction()` with a noop for those few instances
    # of `run_transaction()` being called directly instead of via a
    # Falcon resource class wrapper.
    run_transaction = lambda f: f()  # noqa: E731, F811
