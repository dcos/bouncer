# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""Implement common error raisers."""


import falcon


def raise_bad_request(logger, description, code=None):
    logger.info('Send 400 Bad Request: %s', description)
    raise falcon.HTTPBadRequest(description=description, code=code)


def raise_unauthorized(logger, description):
    logger.info('Send 401 Unauthorized: %s', description)
    raise falcon.HTTPUnauthorized(
        description=description,
        code=None,
        challenges=['acsjwt']
        )


def raise_invalid_data(logger, descr):
    logger.info('Send 400 Bad Request, ERR_INVALID_DATA: %s', descr)
    raise falcon.HTTPBadRequest(description=descr, code='ERR_INVALID_DATA')


def raise_user_not_found(logger, uid):
    d = 'User with uid `%s` not known.' % uid
    logger.info('Send 400 Bad Request: %s', d)
    raise falcon.HTTPBadRequest(description=d, code='ERR_UNKNOWN_USER_ID')


def raise_group_not_found(logger, gid):
    d = 'Group with gid `%s` not known.' % gid
    logger.info('Send 400 Bad Request: %s', d)
    raise falcon.HTTPBadRequest(description=d, code='ERR_UNKNOWN_GROUP_ID')


def raise_protectedresource_not_found(logger, rid):
    d = 'Protected resource with rid `%s` not known.' % rid
    logger.info('Send 400 Bad Request: %s', d)
    raise falcon.HTTPBadRequest(description=d, code='ERR_UNKNOWN_RESOURCE_ID')


def raise_user_not_in_acl(logger, uid, rid):
    d = 'User `%s` is not part of ACL for resource `%s`' % (uid, rid)
    logger.info('Send 400 Bad Request: %s', d)
    raise falcon.HTTPBadRequest(description=d, code='ERR_USER_NOT_IN_ACL')


def raise_group_not_in_acl(logger, gid, rid):
    d = 'Group `%s` is not part of ACL for resource `%s`' % (gid, rid)
    logger.info('Send 400 Bad Request: %s', d)
    raise falcon.HTTPBadRequest(description=d, code='ERR_GROUP_NOT_IN_ACL')


def raise_group_exists(logger, gid):
    d = 'Group with id `%s` already exists.' % gid
    logger.info('Send 409 Conflict: %s', d)
    raise falcon.HTTPConflict(description=d, code='ERR_GROUP_EXISTS')


def raise_user_action_not_in_acl(logger, uid, rid, action):
    d = ('Action `%s` unknown for user `%s` in ACL for '
         'resource `%s`' % (action, uid, rid))
    logger.info('Send 400 Bad Request: %s', d)
    raise falcon.HTTPBadRequest(description=d, code='ERR_ACTION_NOT_YET_STORED')


def raise_group_action_not_in_acl(logger, gid, rid, action):
    d = ('Action `%s` unknown for group `%s` in ACL for '
         'resource `%s`' % (action, gid, rid))
    logger.info('Send 400 Bad Request: %s', d)
    raise falcon.HTTPBadRequest(description=d, code='ERR_ACTION_NOT_YET_STORED')


def raise_no_more_superusers(logger):
    d = 'Last member from `superusers` group cannot be removed'
    logger.info('Send 400 Bad Request: %s', d)
    raise falcon.HTTPBadRequest(description=d, code='ERR_NO_MORE_SUPERUSERS')


def raise_is_superuser_group(logger):
    d = ('The `superusers` group must have `full` '
         'permission on the `dcos:superuser` resource.')
    logger.info('Send 400 Bad Request: %s', d)
    raise falcon.HTTPBadRequest(description=d, code='ERR_IS_SUPERUSER_GROUP')
