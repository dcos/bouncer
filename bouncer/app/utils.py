# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""Implement utilities, e.g. for schema validation or (JSON) object
creation."""


import logging
from datetime import datetime
from itertools import chain

import falcon
import jsonschema

from bouncer.app import urlbuild, http_openapi_spec, jsonschemas


log = logging.getLogger('bouncer.app.utils')


# Create custom resolver for resolving schema cross-references. This for
# instance allows validation of the `LDAPConfiguration` schema which itself
# refers to the `#/definitions/LDAPUserSearchConfig` schema.
_jsonschema_resolver = jsonschema.RefResolver('', referrer=http_openapi_spec)


def rid_slash_decoder(req, resp, resource, params):
    # Rely on the WSGI layer to decode %252F into %2F.
    params['rid'] = params['rid'].replace('%2F', '/')


def badrequest(msg):
    log.info('Terminate request handling as of bad request: %s', msg)
    raise falcon.HTTPBadRequest('Bad Request', msg)


def gen_jsonvalidator(schema_name):
    """Generate a validator function adjusted to a specific JSON schema.

    This function is intended to be used as decorator to Falcon resource
    methods.

    The arguments passed to the validator function are documented at
    http://falcon.readthedocs.org/en/latest/api/hooks.html#falcon.before
    """
    # Generate validator instance only upon decoration, re-use afterwards.
    validator = jsonschema.Draft4Validator(
        schema=jsonschemas[schema_name],
        resolver=_jsonschema_resolver
        )

    def validate(req, resp, resource, params):
        idata = req.context['idata']
        if idata is None:
            badrequest('Request has bad Content-Type or lacks JSON data')
        try:
            validator.validate(idata)
        except jsonschema.ValidationError as e:
            # str(e) is too largish. However, it looks like `e.message`
            # always is a proper short description:
            # https://github.com/Julian/jsonschema/blob/master/jsonschema/exceptions.py
            badrequest('Unexpected JSON input. Hint: %s' % e.message)
    return validate


def gen_allowed_obj(allowed):
    """Generate dict in compliance with the ActionAllowed JSON Schema."""
    if allowed:
        return {'allowed': True}
    return {'allowed': False}


def gen_action_obj_user(rid, uid, action):
    """Generate dict in compliance with the Action JSON Schema."""
    return {
        "name": action,
        "url": urlbuild.user_action(rid, uid, action)
    }


def gen_action_obj_group(rid, gid, action):
    """Generate dict in compliance with the Action JSON Schema."""
    return {
        "name": action,
        "url": urlbuild.group_action(rid, gid, action)
    }


def gen_group_obj(gid, ds_group_dict):
    """Generate dict in compliance with the Group JSON Schema."""
    return {
        'gid': gid,
        'description': ds_group_dict['description'],
        'url': urlbuild.group(gid)
        }


def gen_user_obj(uid, ds_user_dict):
    """Generate dict in compliance with the User JSON Schema."""
    return {
        'uid': uid,
        'description': ds_user_dict['description'],
        'url': urlbuild.user(uid),
        'is_remote': ds_user_dict['is_remote'],
        'is_service': ds_user_dict['is_service'],
        'provider_type': ds_user_dict['provider_type'],
        'provider_id': ds_user_dict['provider_id'],
        }


def gen_acl_obj(rid, ds_acl_dict):
    """Generate dict in compliance with the ACL JSON Schema."""
    return {
        'rid': rid,
        'description': ds_acl_dict['description'],
        'url': urlbuild.acl(rid)
        }


def dict_deep_merge(a, b, path=None):
    """Credit: http://stackoverflow.com/a/7205107/145400"""
    if path is None:
        path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                dict_deep_merge(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                # Same value, leave a unchanged.
                pass
            else:
                # Different value, leave a unchanged.
                log.info(
                    "Dict merge conflict on key `%s`. Prioritize "
                    "`%s` over `%s`", key, a[key], b[key]
                    )
        else:
            a[key] = b[key]
    return a


class AuditLogEntry(dict):
    """Audit log entry with a string representation in logfmt style."""

    # List required keys and define their order for the string representation.
    # To be extended by a subclass.
    _required_keys = [
        'type',
        'timestamp',
        'srcip'
        ]
    _optional_keys = []

    def __init__(self, req, details):
        """
        Args:
            details: dictionary specifying key/value pairs to end up in the
                log message.
        """

        # Merge detail key/value pairs into myself, yeah.
        dict.__init__(self, details)

        self['type'] = 'audit'

        # Obtain remote address from X-Forwarded-For header (passed along by a
        # reverse proxy in front of the WSGI server) or, if not set, use
        # `req.remote_addr` which is the IP address that actually connected to
        # the WSGI server.
        self['srcip'] = req.headers.get(
            'X-Forwarded-For', None) or req.remote_addr

        # Create iso8601/rfc 3339 timestamp, also see
        # http://stackoverflow.com/a/8556555/145400
        self['timestamp'] = datetime.utcnow().isoformat("T") + "Z"

        # Conditionally quote values that contain spaces. Note(jp): that still
        # is not great, there can be equal signs and quotes in the value which
        # will cripple the format, but how well-defined is 'logfmt' anyway.
        for key, value in self.items():
            if ' ' in value:
                self[key] = '"%s"' % value

    def __str__(self):
        keys = chain(
            (k for k in self._required_keys),
            (k for k in self._optional_keys if k in self)
            )
        return ' '.join('%s=%s' % (k, self[k]) for k in keys)


class AuthorizerAuditLogEntry(AuditLogEntry):

    _required_keys = AuditLogEntry._required_keys.copy()
    _required_keys.extend([
        'authorizer',
        'uid',
        'action',
        'object',
        'result',
        'reason',
        ])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self['authorizer'] = 'bouncer'
        assert self['result'] in ('allow', 'deny')


class SecurityEventAuditLogEntry(AuditLogEntry):

    _required_keys = AuditLogEntry._required_keys.copy()
    _required_keys.extend([
        'component',
        'action',
        'result',
        'reason'
        ])
    _optional_keys = AuditLogEntry._optional_keys.copy()
    _optional_keys.extend(['uid'])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self['component'] = 'bouncer'
