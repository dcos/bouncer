# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


import enum
import logging
import re

import sqlalchemy as sa
from sqlalchemy.orm import load_only

from bouncer.app import urlbuild, errors
from bouncer.app.exceptions import (
    UidValidationError,
    ProviderTypeValidationError,
    ProviderIdValidationError,
    EntityNotFound
)

from .base import DeclarativeBase, ModelBase
from .session import dbsession
from .provider_type import ProviderType


log = logging.getLogger(__name__)


class UserType(enum.Enum):
    """Abstraction for user account types."""
    regular = 1
    service = 2


class UserBase:
    """User abstraction free from SQLAlchemy-specific code."""

    def __init__(
            self, uid, utype, description,
            provider_type, provider_id, passwordhash=None, publickey=None):

        # Default provider_type to `internal` for backwards-compatibility.
        if provider_type is None:
            provider_type = ProviderType.internal

        # Default to is_remote = False for backwards-compatibility.
        if provider_type == ProviderType.internal:
            self.is_remote = False
        else:
            self.is_remote = True

        self._validate_provider_type(provider_type)
        self._validate_provider_id(provider_type, provider_id)
        self._validate_uid(uid)

        self.passwordhash = passwordhash
        self.uid = uid
        self.utype = utype
        self.description = description
        self.provider_type = provider_type
        self.provider_id = provider_id

        if publickey is not None:
            assert passwordhash is None
            # Note(JP): while this is not yet a database field go through the
            # magic property to piggy-back this into the passwordhash field.
            self.pubkey = publickey

    def _validate_uid(self, uid):

        uid_regexp = re.compile(r'[a-zA-Z0-9-_@\.]+$')
        uid_maxlen = 96

        if uid == 'anonymous':
            raise UidValidationError(
                'uid `anonymous` is reserved and cannot be used')

        elif len(uid) > uid_maxlen:
            raise UidValidationError(
                'uid `%s` is too long (> %s)' % (uid, uid_maxlen))

        elif not uid_regexp.match(uid):
            raise UidValidationError('uid `%s` is invalid' % uid)

    def _validate_provider_type(self, provider_type):
        if provider_type not in ProviderType:
            members = ', '.join(m.value for m in ProviderType)
            raise ProviderTypeValidationError(
                'provider_type must be one of: {}'.format(members))

    def _validate_provider_id(self, provider_type, provider_id):
        if provider_type in [ProviderType.saml, ProviderType.oidc]:
            if provider_id is None or provider_id == '':
                raise ProviderIdValidationError(
                    'provider_id must be provided if provider_type is saml or oidc')
        else:
            # Note(JP): Why would we want to allow an empty string provider ID
            # here? Why not be strict and only allow `None`?
            if provider_id is not None and provider_id != '':
                raise ProviderIdValidationError(
                    'provider_id must not be provided unless provider_type is saml or oidc')

    def _build_url(self):
        return urlbuild.user(self.uid)

    @property
    def is_service(self):
        return self.utype is UserType.service

    @property
    def pubkey(self):
        """Hide all the dirtiness behind this.

        Todo(JP): add a database field for the public key, and perform a
        migration.
        """
        # The program must not perform this lookup if this is not a service
        # account.
        assert self.is_service
        p = self.passwordhash
        assert p.startswith(':public:')
        return p[8:]

    @pubkey.setter
    def pubkey(self, pubkey):
        assert self.is_service
        self.passwordhash = ':public:' + pubkey

    def jsonobj(self):
        """Generate dict in compliance with the HTTP API `User` JSON Schema."""
        user_json_obj = {
            'uid': self.uid,
            'description': self.description,
            'url': self._build_url(),
            'is_remote': self.is_remote,
            'is_service': True if self.utype is UserType.service else False,
            'provider_type': self.provider_type.name,
            'provider_id': (self.provider_id or '')
            }

        # Add pubkey property only conditionally.
        if self.utype is UserType.service:
            user_json_obj['public_key'] = self.pubkey

        return user_json_obj

    def __repr__(self):
        return "<User(uid='%s')>" % self.uid


class User(UserBase, ModelBase, DeclarativeBase):
    """Primary user abstraction for application code.

    Defines the mapping between `User` objects and the `users` database table.
    Meant to contain all SQLAlchemy-specific extension of `UserBase`.
    """

    __tablename__ = 'users'

    id = sa.Column(sa.Integer, primary_key=True)
    uid = sa.Column(sa.Unicode, unique=True)
    passwordhash = sa.Column(sa.Unicode)
    utype = sa.Column(sa.Enum(UserType))
    description = sa.Column(sa.Unicode)
    is_remote = sa.Column(sa.Boolean)

    # CockroachDB does not support adding constraints in the same transaction
    # that the column is added. By default, the Enum column type adds a
    # "alter table ... add column varchar" entry, followed by a constraint
    # "alter table ... add constraint ..." to ensure that the column's values
    # match the Enum's. Due to a limitation in cockroachdb
    # (https://github.com/cockroachdb/cockroach/issues/26508)
    # adding a column and then adding a constraint to that column
    # in the same transaction is not possible.
    # We prevent the constraint being added by setting `create_constraint=False`.
    provider_type = sa.Column(sa.Enum(ProviderType, create_constraint=False))
    provider_id = sa.Column(sa.Unicode)

    @classmethod
    def get(cls, uid, attrs=None):
        try:
            if attrs is not None:
                return dbsession.query(cls).options(load_only(*attrs)).filter_by(uid=uid).one()
            return dbsession.query(cls).filter_by(uid=uid).one()
        except sa.orm.exc.NoResultFound:
            raise EntityNotFound

    @classmethod
    def get_or_terminate_request(cls, uid, logger, attrs=None):
        """foo bar.

        Heavily coupled to the web application, but useful!
        """
        try:
            return cls.get(uid, attrs=attrs)
        except EntityNotFound:
            errors.raise_user_not_found(logger, uid)

    @classmethod
    def get_all(cls, utype):
        return dbsession.query(cls).filter_by(utype=utype).all()


# Hook for extending the User class in downstream
try:
    from .user_extension import extend_userclass
    log.info('Modify User class with downstream extensions')
    extend_userclass(User)
except ImportError:
    pass
