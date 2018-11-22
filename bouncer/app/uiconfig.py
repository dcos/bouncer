# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""Implement handler for the /uiconfig endpoint.

In a DC/OS cluster it is exposed via /dcos-metadata/ui-config.json. It is there
so that the UI can display a special message to visitors of the login page ("you
will be the superuser!") before the first regular user has been created in the
database.
"""


import logging
import json


from bouncer.app import config
from bouncer.app.models import User, UserType, dbsession


UI_CONFIG_FILEPATH = '/opt/mesosphere/etc/ui-config.json'
CLUSTER_ID_FILEPATH = '/var/lib/dcos/cluster-id'


def get_module_route_handlers():
    return {
        '/uiconfig': UIConfig,
        }


def read_ui_config():
    if config['TESTING']:
        return {'dummy': 'yes'}

    # Expect that this code is integration-tested. Not reached in unit tests.
    with open(UI_CONFIG_FILEPATH, 'rb') as f:
        return json.loads(f.read().decode('utf-8'))


def read_cluster_id():
    if config['TESTING']:
        return 'a-dummy-cluster-id'

    # Expect that this code is integration-tested. Not reached in unit tests.
    with open(CLUSTER_ID_FILEPATH, 'rb') as f:
        return f.read().decode('utf-8').strip()


class UIConfig:

    def __init__(self):
        self.log = logging.getLogger(
            'bouncer.app.uiconfig.' + self.__class__.__name__)

    def on_get(self, req, resp):
        # The legacy code behavior (dcos-oauth) is to emit a 500 Internal Server
        # Error when reading the file(s) or when decoding their contents fails,
        # and also when the interaction with the database fails.
        cluster_id = read_cluster_id()
        ui_config = read_ui_config()
        is_first_regular_user = dbsession.query(User).filter_by(
            utype=UserType.regular).count() == 0

        ui_config['clusterConfiguration'] = {
            'firstUser': is_first_regular_user,
            'id': cluster_id
        }

        req.context['odata'] = ui_config
