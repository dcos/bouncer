# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""Implement URL constructors for API objects."""


from bouncer.app import config


PREFIX = config['URLPREFIX']


def membership(gid, uid):
    return '%s/groups/%s/users/%s' % (PREFIX, gid, uid)


def user(uid):
    return '%s/users/%s' % (PREFIX, uid)


def group(gid):
    return '%s/groups/%s' % (PREFIX, gid)


def acl(rid):
    # Percent-encode slashes, twice!
    # That is, encode the `%` in `%2F` with a `%25`.
    rid_slash_encoded = rid.replace('/', '%252F')
    return '%s/acls/%s' % (PREFIX, rid_slash_encoded)


def user_action(rid, uid, action):
    rid_slash_encoded = rid.replace('/', '%252F')
    return '%s/acls/%s/users/%s/%s' % (
        PREFIX, rid_slash_encoded, uid, action)


def group_action(rid, gid, action):
    rid_slash_encoded = rid.replace('/', '%252F')
    return '%s/acls/%s/groups/%s/%s' % (
        PREFIX, rid_slash_encoded, gid, action)
