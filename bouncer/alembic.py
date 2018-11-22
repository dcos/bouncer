"""
This module is replaced downstream. As of today its main job is to define and
register the `CockroachAlembicDialect`.
"""

import cockroachdb.sqlalchemy.dialect
import sqlalchemy.types as sqltypes
import alembic.ddl.postgresql

# Monkey-patch CockroachDB SQLAchemy dialect to add 'BOOL' -> BOOLEAN
# to the type map. This resolves an issue where the 'BOOL' type
# reflected for `is_remote` is not mapped to a known type.
cockroachdb.sqlalchemy.dialect._type_map['bool'] = sqltypes.BOOLEAN


class CockroachAlembicDialect(
        alembic.ddl.postgresql.PostgresqlImpl,
        cockroachdb.sqlalchemy.dialect.CockroachDBDialect,
        ):
    """
    An Alembic dialect for CockroachDB.

    By inheriting from `alembic.ddl.postgresql.PostgresqlImpl`, which inherits
    from the `DefaultImpl` in the same package, we automatically register the
    dialect with alembic.
    """

    __dialect__ = 'cockroachdb'


def load_initial_schema(op):
    # This logic will be added when the first DB schema migration
    # is added.
    pass
