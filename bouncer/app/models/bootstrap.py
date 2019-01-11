# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


import logging

from .user import ProviderType, UserType, User  # noqa: E402


log = logging.getLogger(__name__)


def insert_bootstrap_data(dbsession, bouncer_config):

    su_svc_acc_uid_cfg = bouncer_config.get(
        'SUPERUSER_SERVICE_ACCOUNT_UID', None)
    su_svc_acc_pubkey_cfg = bouncer_config.get(
        'SUPERUSER_SERVICE_ACCOUNT_PUBLIC_KEY', None)

    # Require both properties to be non-emtpy strings.
    if not su_svc_acc_uid_cfg or not su_svc_acc_pubkey_cfg:
        return

    import bouncer.app.crypt

    # Let it crash: for an invalid key this will raise an InvalidPubkey
    # exception which will crash the gunicorn worker process, leaving behind an
    # expressive stacktrace with error detail. The gunicorn master will shut
    # down with the log message "Worker failed to boot".
    bouncer.app.crypt.validate_pubkey(su_svc_acc_pubkey_cfg)

    log.info('Inject superuser service account details injected via config')

    # Todo(JP): clean the pubkey/password dirtiness up:
    # https://jira.mesosphere.com/browse/DCOS-43663
    dbsession.add(User(
        uid=su_svc_acc_uid_cfg,
        publickey=su_svc_acc_pubkey_cfg,
        utype=UserType.service,
        description='Superuser service account defined via DC/OS config',
        provider_type=ProviderType.internal,
        provider_id=None,
        )
    )


def tables_cleanup_order(tables):
    """
    Defines order in which will be tables cleaned up on datastore reset.
    """
    return tables
