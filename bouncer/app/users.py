# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""Implement handlers for /users* endpoints."""


import logging
import re

import falcon

from bouncer.app import utils, crypt, errors, oidcidtokenlogin
from bouncer.app.models import User, UserType, ProviderType, dbsession

from bouncer.app.exceptions import (
    InvalidPassword,
    InvalidPubkey,
    EntityExists,
    UidValidationError,
    ProviderTypeValidationError,
    ProviderIdValidationError,
    )


KEY_PUBLIC_PREFIX = ":public:"


def get_module_route_handlers():
    return {
        '/users': Users,
        '/users/{uid}': UserItem
        }


def ensure_at_least_one_superuser_will_be_left(user):
    """Extension point for downstream logic. Here it is a noop.

    In downstream this function can be patched during runtime for calling custom
    logic.
    """
    pass


class UserResource:

    def __init__(self):
        self.log = logging.getLogger(
            'bouncer.app.users.' + self.__class__.__name__)


class Users(UserResource):

    def on_get(self, req, resp):
        show_services = req.params.get('type', None) == 'service'
        utype = UserType.service if show_services else UserType.regular
        users = User.get_all(utype)
        req.context['odata'] = {'array': [u.jsonobj() for u in users]}


class UserItem(UserResource):

    def raise_invalid_data(self, descr):
        errors.raise_invalid_data(self.log, descr)

    def _validate_hash_password(self, pw_given):
        try:
            crypt.validate_password(pw_given)
        except InvalidPassword as e:
            raise falcon.HTTPBadRequest(
                description='Password does not match rules: %s' % e,
                code='ERR_INVALID_DATA')
        return crypt.hash_password(pw_given)

    def _validate_public_key(self, public_key):
        try:
            crypt.validate_pubkey(public_key)
        except InvalidPubkey as e:
            raise falcon.HTTPBadRequest(
                description='Invalid public key: %s' % e,
                code='ERR_INVALID_PUBLIC_KEY')
        return public_key

    def _parse_provider_type_str(self, provider_type_str):
        if provider_type_str is None:
            return ProviderType.internal
        try:
            return getattr(ProviderType, provider_type_str)
        except AttributeError:
            self.raise_invalid_data(
                f'Invalid provider_type: {provider_type_str}')

    @falcon.before(utils.gen_jsonvalidator('UserCreate'))
    def on_put(self, req, resp, uid):

        pw_given = req.context['idata'].get('password', None)
        key_given = req.context['idata'].get('public_key', None)
        description = req.context['idata'].get('description', '')
        provider_type_str = req.context['idata'].get('provider_type', None)
        # Note(JP): why is the default of this not None?
        provider_id = req.context['idata'].get('provider_id', '')

        # Check if this is upstream Bouncer.
        if hasattr(oidcidtokenlogin, 'ISSUER_WHITELIST'):
            # Yes, it is. Implement a fallback to support inserting users with a
            # uid that looks like an email address, and where the HTTP request
            # lacks meaningful data in the request body. This is what the DC/OS
            # UI actually does up to version 1.12, and what other external
            # tooling might also do. What such an HTTP request actually means
            # is: insert user record with 'provider_type': 'oidc',
            # 'provider_id': 'https://dcos.auth0.com/'
            if not provider_id and provider_type_str is None:
                if not pw_given and not key_given:
                    if re.match(r'[^@]+@[^@]+\.[^@]+', uid):
                        # The email check really is meant to be very liberal.
                        # See https://stackoverflow.com/a/8022584/145400
                        provider_type_str = 'oidc'
                        # Expect a single key in the whitelist dict, get it.
                        provider_id = 'https://dcos.auth0.com/'

        # Basic validation: do not allow empty strings for password and public
        # key, under no circumstances.
        if pw_given == '':
            self.raise_invalid_data(
                '`password` must not be empty when provided')

        if key_given == '':
            self.raise_invalid_data(
                '`public_key` must not be empty when provided')

        ptype = self._parse_provider_type_str(provider_type_str)

        # Basic validation for non-internal providers:no password or public key
        # must be provided.
        if ptype is not ProviderType.internal:

            if pw_given:
                self.raise_invalid_data('external provider: `password` is unexpected')

            if key_given:
                self.raise_invalid_data('external provider: `public_key` is unexpected')

        # Assume that the user is a regular user account.
        utype = UserType.regular

        # Set defaults.
        publickey = None
        pw_hashed = None

        if ptype is ProviderType.internal:

            if len([_ for _ in (pw_given, key_given) if _]) != 1:
                self.raise_invalid_data(
                    'One of `password` or `public_key` must be provided')

            if pw_given:
                pw_hashed = self._validate_hash_password(pw_given)

            else:
                # Service user account. As long as there is no distinct notion
                # of service accounts in our data model, piggyback `pw_hashed`
                # for storing its public key. Note(JP): clean this up:
                # https://jira.mesosphere.com/browse/DCOS-43663
                self._validate_public_key(key_given)
                publickey = key_given
                # This is an internal user that is using key-based
                # authentication. This implies that the it is a service account.
                utype = UserType.service

        # Todo(jp): add validation logic to the User object creation.
        try:
            user = User(
                uid=uid,
                passwordhash=pw_hashed,
                publickey=publickey,
                utype=utype,
                description=description,
                provider_type=ptype,
                provider_id=provider_id,
                )
        except UidValidationError:
            raise falcon.HTTPBadRequest(
                description='Invalid user ID: %s' % uid,
                code='ERR_INVALID_USER_ID'
                )
        except ProviderTypeValidationError as exc:
            self.raise_invalid_data(
                'Invalid provider_type: %s' % str(exc))
        except ProviderIdValidationError as exc:
            self.raise_invalid_data(
                'Invalid provider_id: %s' % str(exc))

        try:
            User.add(user)
        except EntityExists:
            raise falcon.HTTPConflict(
                description='User with id `%s` already exists.' % uid,
                code='ERR_USER_EXISTS'
                )

        self.log.info('User with uid `%s` added to database.', uid)
        resp.status = falcon.HTTP_201

    def on_get(self, req, resp, uid):
        user = User.get_or_terminate_request(uid, self.log)
        user_json_obj = user.jsonobj()
        req.context['odata'] = user_json_obj

    @falcon.before(utils.gen_jsonvalidator('UserUpdate'))
    def on_patch(self, req, resp, uid):

        pw_given = req.context['idata'].get('password', None)
        update_description = req.context['idata'].get('description', None)

        if pw_given is None and update_description is None:
            raise falcon.HTTPBadRequest(
                description='One of `description` and `password` must be provided.',
                code='ERR_INVALID_DATA',
                )

        user = User.get_or_terminate_request(uid, self.log)

        if pw_given is not None:
            if user.is_service:
                raise falcon.HTTPBadRequest(
                    description='Password update is not available for service user accounts.',
                    code='ERR_INVALID_DATA',
                    )

            update_pw_hashed = self._validate_hash_password(pw_given)
            user.passwordhash = update_pw_hashed

        if update_description is not None:
            user.description = update_description

        dbsession.commit()

        resp.status = falcon.HTTP_NO_CONTENT

    def on_delete(self, req, resp, uid):
        user = User.get_or_terminate_request(uid, self.log)
        ensure_at_least_one_superuser_will_be_left(user)
        dbsession.delete(user)
        dbsession.commit()
        resp.status = falcon.HTTP_NO_CONTENT
