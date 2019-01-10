# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


import logging
import time

import psycopg2
import psycopg2.errorcodes
import sqlalchemy
import sqlalchemy.exc

from .containerbase import ContainerBase


log = logging.getLogger(__name__)


COCKROACH_IMAGE = 'cockroachdb/cockroach:v2.0.7'


class ContainerCockroach(ContainerBase):

    imagename = COCKROACH_IMAGE
    container_name = 'bouncer-test-cockroach'
    # Listen on all interfaces on the host machine so that CockroachDB is
    # reachable through the Docker bridge network.
    listen_ip = '0.0.0.0'

    def __init__(self):
        super().__init__()

        port_bindings = {
            26257: (self.listen_ip, 26257),
            }

        host_config = self._cli.create_host_config(
            port_bindings=port_bindings)

        self._container = self._cli.create_container(
            image=self.imagename,
            detach=True,
            ports=list(port_bindings),
            host_config=host_config,
            name=self.container_name,
            command=['start', '--insecure', '--http-port=8090', '--host=0.0.0.0']
            )

    def start_and_wait(self):
        # Start container.
        self.start()
        # Wait for cockroachdb to be up and running.
        self._wait_for_cockroach_start()

    def _wait_for_cockroach_start(self):

        log.info('Waiting for CockroachDB to start')

        def _accepting_connections():
            _engine = sqlalchemy.create_engine(
                'cockroachdb://root@bouncer-test-hostmachine:26257/iam',
                echo=False,
                connect_args={}
            )
            session_factory = sqlalchemy.orm.sessionmaker(bind=_engine)
            session = session_factory(autocommit=True)
            try:
                session.execute('show tables;')
                return True
            except sqlalchemy.exc.ProgrammingError as exc:
                if hasattr(exc.orig, 'pgcode'):
                    # This works with CockroachDB.
                    if exc.orig.pgcode == psycopg2.errorcodes.INVALID_CATALOG_NAME:
                        log.info('Database `iam` does not exist.')
                        return True
            except sqlalchemy.exc.OperationalError:
                # Connection failed
                return False
            finally:
                session.close()
        while True:
            if _accepting_connections():
                log.info('CockroachDB accepts connections')
                return
            time.sleep(0.2)
