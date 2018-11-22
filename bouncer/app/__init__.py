# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
Initialize Bouncer, order matters.

1. Set up logging.
2. Build configuration.
3. Re-configure logging, using config details.
4. Import data models package and SQLAlchemy engine (uses config details).
5. Read (decode) OpenAPI/Swagger spec (fail fast).
6. Create database abstraction.
"""


import logging
import os

import yaml

# The import of the logging module triggers the first application-wide import
# of the config module, which triggers the configuration builder. The
# subsequent config import loads the pre-built configuration object.
import bouncer.logging  # noqa: F401
from bouncer.config import config
from bouncer.app.models import Database
from bouncer.exceptions import BouncerException


log = logging.getLogger(__name__)


def _load_http_openapi_specification():
    """Load the IAM's HTTP API specification from a YAML file.

    Load the specification from docs/openapi-spec-extended.yaml if it exists or
    otherwise fall back to docs/openapi-spec.yaml. Expect the file to contain a
    YAML document in accordance with the OpenAPI specification notation:
    https://github.com/OAI/OpenAPI-Specification

    Returns:
        (The deserialized YAML document, the utf-8-encoded yaml doc)
    """
    docs_dirpath = os.path.join(os.path.dirname(__file__), '../../docs')

    # Define OpenAPI specification filenames; higher priority item first.
    for fn in ('openapi-spec-extended.yaml', 'openapi-spec.yaml'):
        apispec_filepath = os.path.join(docs_dirpath, fn)
        if os.path.isfile(apispec_filepath):
            log.info('Load OpenAPI specification from %s', apispec_filepath)
            with open(apispec_filepath, 'rb') as f:
                spec_yaml_doc_utf8 = f.read()
                spec = yaml.load(spec_yaml_doc_utf8.decode('utf-8'))
                return spec, spec_yaml_doc_utf8

    raise BouncerException('No OpenAPI specification file found')


# Create database abstraction for DB management tasks, expose to other modules.
# Assume that object construction does not lead to database interaction.
db = Database(testing_mode=config['TESTING'])


# Read OpenAPI (HTTP API) specification.
http_openapi_spec, http_openapi_spec_utf8 = _load_http_openapi_specification()
jsonschemas = http_openapi_spec['definitions']


# A temporary directory prepared during load and provided to the application.
tempdir_abspath = None
