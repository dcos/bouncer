# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
Build configuration from a class hierarchy and compile it into a dictionary. The
configuration type to be used is to be injected via the environment variable
BOUNCER_CONFIG_CLASS.

Individual configuration parameters can be overridden or added using either of
the environment variables BOUNCER_CONFIG_FILE_PATH and BOUNCER_CONFIG:

    * If the environment variable BOUNCER_CONFIG_FILE_PATH is set, read the
      corresponding file, expect its contents to be a flat JSON document, and
      update the configuration with the specified key/value pairs. This
      environment variable cannot be specified if BOUNCER_CONFIG is also
      specified.

    * If the environment variable BOUNCER_CONFIG is set, read the value, expect
      it to be a flat JSON document, and update the configuration with with the
      specified key/value pairs. This environment variable cannot be specified
      if BOUNCER_CONFIG_FILE_PATH is also specified.

    * Key/value pairs specified in the JSON document take precedence over the
      defaults defined in the configuration classes.

Expose the resulting configuration as a ChainMap (dictionary interface), using
the name `config`.
"""

import os
import json
import inspect
import logging
from collections import ChainMap, OrderedDict

from bouncer.exceptions import BouncerException


log = logging.getLogger('bouncer.config')


class BaseConfig:
    """Class for describing available configuration keys.

    It is OK to set proper/sane values only in one of the children.
    """

    # URL path prefix for absolute path generation, required for route setup.
    URLPREFIX = '/acs/api/v1'

    # Path to file (absolute or relative to current working directory)
    # containing the secret key used for token signature generation. Path to
    # file (absolute or relative to current working directory) containing the
    # private key used for token signature generation in case of RS256 JWTs.
    SECRET_KEY_FILE_PATH = 'secret.key'

    # Algorithm for issued authentication tokens. RS256 is currently the only
    # supported algorithm
    AUTH_TOKEN_SIGNATURE_ALGORITHM = 'RS256'

    # Time until auth token signature expires.
    EXPIRATION_AUTH_TOKEN_DAYS = 2.0

    # Cookie lifetime (defines the `expires` attributes in cookies)
    # Keep cookie lifetime below auth (default) token lifetime.
    # Both cookie lifetimes should really be in sync.
    EXPIRATION_AUTH_COOKIE_DAYS = 1.9
    EXPIRATION_INFO_COOKIE_DAYS = 1.9

    # Strong password hashing consumes CPU and significantly slows down tests.
    # You may want to use a dummy/noop method for testing.
    PASSWORD_HASHING_DUMMY = False

    # General notion of testing mode. This enables e.g. database reset.
    TESTING = False

    # Set the `secure` flag for the auth cookie.
    AUTH_COOKIE_SECURE_FLAG = False

    # LDAP module settings.
    # This needs to be coordinated with the with Admin Router proxy settings in DC/OS.
    LDAP_GROUP_IMPORT_LIMIT_SECONDS = 120

    # SQLAlchemy settings. The DB URL must be provided by a subclass.
    SQLALCHEMY_DB_URL = None
    SQLALCHEMY_CONNECT_ARGS = {}

    # Tthe path to the directory containing the alembic `env.py` configuration
    # file for this project as well as the `./versions/` subdirectory
    # containing individual migration scripts.
    #
    # See http://alembic.zzzcomputing.com/en/latest/tutorial.html#the-migration-environment
    ALEMBIC_DIR_PATH = ''

    # Set the default log level for the Bouncer code logger.`
    LOG_LEVEL_STDERR = 'INFO'

    # If this is not `None`, set up a rotating log file handler.
    LOG_LEVEL_FILE = None

    # Set the log level for the SQLAlchemy library.
    LOG_LEVEL_SQLALCHEMY = 'WARNING'

    # Whether or not the policyquery cache is enabled.
    POLICYQUERY_CACHE_ENABLED = True
    # Time in seconds to cache /internal/policyquery results.
    POLICYQUERY_CACHE_TTL_SECONDS = 5
    # Maximum size of the /internal/policyquery cache.
    POLICYQUERY_CACHE_MAX_SIZE = 1000

    # Maximum lifetime of a response to the `/users/<uid>/permissions` endpoint.
    USER_PERMISSIONS_RESPONSE_MAX_AGE_SECONDS = 5

    def _set_if_in_env(self, key):
        """
        Convenience method for setting an attribute from an environment var.
        """
        if key in os.environ:
            setattr(self, key, os.environ[key])


class TestConfigBase(BaseConfig):
    """Useful for running unit tests against file back-end."""
    TESTING = True
    PASSWORD_HASHING_DUMMY = True
    LOG_LEVEL_STDERR = 'DEBUG'
    LOG_LEVEL_SQLALCHEMY = 'DEBUG'

    # Assume that in the test environment there is a containerized CockroachDB
    # database running reachable via the hostname `bouncer-test-hostmachine`.
    SQLALCHEMY_DB_URL = 'cockroachdb://root@bouncer-test-hostmachine:26257/iam'

    ALEMBIC_DIR_PATH = 'alembic'

    def __init__(self):

        self._set_if_in_env('SECRET_KEY_FILE_PATH')
        self._set_if_in_env('SUPERUSER_SERVICE_ACCOUNT_UID')
        self._set_if_in_env('SUPERUSER_SERVICE_ACCOUNT_PUBLIC_KEY')


class TestConfig60sUserPermissionsMaxAge(TestConfigBase):
    USER_PERMISSIONS_RESPONSE_MAX_AGE_SECONDS = 60


class TestConfigSlowLDAPDirectory(TestConfigBase):
    LDAP_GROUP_IMPORT_LIMIT_SECONDS = 1


class TestConfigSQLite(TestConfigBase):
    # This is useful for a simple containerized test deployment.
    SQLALCHEMY_DB_URL = 'sqlite:///:memory:'


class DCOSConfig(BaseConfig):
    """DCOS configuration class.

    Usually enriched with a configuration file.
    """

    def __init__(self):
        # In DC/OS this part of the main configuration is injected via
        # environment. Error out if these variables are not set.
        self.SECRET_KEY_FILE_PATH = os.environ['SECRET_KEY_FILE_PATH']
        self.SQLALCHEMY_DB_URL = os.environ['SQLALCHEMY_DB_URL']


def _get_config_instance():
    """Obtain name of configuration class from environment. Validate and
    instantiate.
    """
    varname = 'BOUNCER_CONFIG_CLASS'
    config_class_name = os.environ.get(varname, None)
    if config_class_name is None:
        m = '%s environment variable not set.' % varname
        log.error(m)
        raise BouncerException(m)

    log.info('%s from environment: `%s`', varname, config_class_name)

    try:
        config_class = globals()[config_class_name]
    except KeyError:
        m = '%s set to an unknown name: `%s`' % (varname, config_class_name)
        log.error(m)
        raise BouncerException(m)

    if not inspect.isclass(config_class):
        m = '`%s` is not a class.' % config_class_name
        log.error(m)
        raise BouncerException(m)

    config_instance = config_class()

    if not isinstance(config_instance, BaseConfig):
        m = '`%s` is not a configuration class.' % config_class_name
        log.error(m)
        raise BouncerException(m)
    return config_instance


def _build_dict_from_pubattrs(o):
    """Collect attributes of object `o` that do not start with an underscore.
    Walk the entire class hierarchy, using the `dir()` builtin. For each
    attribute discovered, store the corresponding key/value pair. Return a
    dict of these pairs.
    """
    return {n: getattr(o, n) for n in dir(o) if not n.startswith('_')}


def _build_config():
    log.info('Populate configuration dictionary from configuration class.')
    cfg = _build_dict_from_pubattrs(_get_config_instance())

    # If corresponding environment variable is set, read JSON config file,
    # and let corresponding key/value pairs take precedence.
    cfgfilepath = os.environ.get('BOUNCER_CONFIG_FILE_PATH', None)
    cfgenv = os.environ.get('BOUNCER_CONFIG', None)

    if cfgfilepath and cfgenv:
        raise BouncerException(
            'the BOUNCER_CONFIG and BOUNCER_CONFIG_FILE_PATH environment '
            'variables cannot be used together')

    cfgjson = None
    if cfgfilepath:
        log.info('Update configuration from `%s`.', cfgfilepath)
        with open(cfgfilepath) as f:
            cfgjson = f.read()

    if cfgenv:
        log.info('Update configuration from environment variable.')
        cfgjson = cfgenv

    if cfgjson is not None:
        cfg = ChainMap(json.loads(cfgjson), cfg)

    return cfg


config = _build_config()

log.info(
    'Configuration has been built. JSONized:\n%s',
    json.dumps(OrderedDict(sorted(config.items())), indent=2)
    )
