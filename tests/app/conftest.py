# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

import logging
import pytest
import requests

from tests.misc import Url


log = logging.getLogger(__name__)


@pytest.fixture()
def datastore_reset(wsgi_app):
    r = requests.get(Url('/testing/reset-datastore'))
    assert r.status_code == 200


@pytest.fixture()
def datastore_reset_bootstrap(wsgi_app):
    r = requests.get(Url('/testing/reset-datastore?bootstrap=true'))
    assert r.status_code == 200
