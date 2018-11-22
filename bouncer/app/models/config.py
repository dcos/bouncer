# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


import logging

import sqlalchemy as sa

from .base import DeclarativeBase, ModelBase
from .session import dbsession


log = logging.getLogger(__name__)


class ConfigKeyNotFound(Exception):
    pass


class ConfigKeyExists(Exception):
    pass


class ConfigItemBase:
    """Config item abstraction free from SQLAlchemy-specific code."""

    def __init__(self, key, value):
        self.key = key
        self.value = value

        # Automatic serialization?

    def __repr__(self):
        return "<ConfigItem(key='%s')>" % (self.key, )


class ConfigItem(ConfigItemBase, ModelBase, DeclarativeBase):

    __tablename__ = 'configs'

    # TODO(jp): should we just declare the `key` to be the primary key?

    id = sa.Column(sa.Integer, primary_key=True)
    key = sa.Column(sa.Unicode, unique=True)
    value = sa.Column(sa.Unicode)

    @classmethod
    def get(cls, key):
        item = dbsession.query(cls).filter_by(key=key).one_or_none()
        return None if item is None else item.value

    @classmethod
    def get_all(cls):
        items = dbsession.query(cls).all()
        return {i.key: i.value for i in items}

    @classmethod
    def set(cls, key, value, update=True, strict_update=False):
        """
        Args:
            update: raise `KeyExists` if set to `False` and key already exists.
            strict_update: raise `KeyNotFound` if set to `True` and key does not
                yet exist.
        """
        item = dbsession.query(cls).filter_by(key=key).one_or_none()

        if item is not None:
            if not update:
                raise ConfigKeyExists

            # Update value for existing key.
            log.info('Update `%s`.', item)
            item.value = value

        else:
            if strict_update:
                raise ConfigKeyNotFound

            # Create fresh key/value pair.
            item = cls(key, value)
            log.info('Insert `%s`.', item)
            dbsession.add(item)

        dbsession.commit()

    @classmethod
    def delete(cls, key):

        item = dbsession.query(ConfigItem).filter_by(key=key).one_or_none()

        if item is None:
            raise ConfigKeyNotFound

        log.info('Delete `%s`.', item)
        dbsession.delete(item)
        dbsession.commit()
