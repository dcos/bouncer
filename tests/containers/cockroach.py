# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


import io
import logging
import tarfile
import time
from pathlib import Path
from uuid import uuid4

import psycopg2
import psycopg2.errorcodes
import sqlalchemy
import sqlalchemy.exc

from .containerbase import ContainerBase


log = logging.getLogger(__name__)


COCKROACH_IMAGE = 'cockroachdb/cockroach:v2.0.7'


class ContainerCockroach(ContainerBase):

    # Listen on all interfaces on the host machine so that CockroachDB is
    # reachable through the Docker bridge network.
    listen_ip = '0.0.0.0'

    # Port on which the cockroachdb listens inside the container
    db_port = 26257

    sql_alchemy_base_url = 'cockroachdb://root@bouncer-test-hostmachine'

    def __init__(
            self,
            container_name='bouncer-test-cockroach',
            imagename=COCKROACH_IMAGE,
            port=26257,
            volume_binds={},
        ):
        """
        Args:
            imagename (str): Name of the image that will be used to launch
                the cockroachdb container.
            port (int): Number on which will be cockroachdb available to
                other containers.
            volume_binds (dict): Bind volumes to a docker container running
                cockroachdb.
                See: https://docker-py.readthedocs.io/en/1.10.0/volumes/
        """
        self.container_name = container_name
        self.imagename = imagename
        self.port = port

        super().__init__()

        port_bindings = {
            self.db_port: (self.listen_ip, self.port),
            }

        host_config = self._cli.create_host_config(
            port_bindings=port_bindings,
            binds=volume_binds)

        self._container = self._cli.create_container(
            image=imagename,
            detach=True,
            ports=list(port_bindings),
            host_config=host_config,
            name=container_name,
            command=[
                'start', '--insecure', '--http-port=8090',
                '--host={listen_ip}'.format(listen_ip=self.listen_ip),
                ]
            )

    def sql_alchemy_url_for_db(self, db):
        """
        Returns a SQL Alchemy compatible URL for connecting to cockroach DB
        instance to provided database name.

        args:
            db (str): Name of the database
        """
        return "{base}:{port}/{db}".format(
            base=self.sql_alchemy_base_url,
            port=self.port,
            db=db,
        )

    def import_database_from_backup_file(self, backup_file_path, database_name='iam'):
        if not isinstance(backup_file_path, Path):
            backup_file_path = Path(backup_file_path)

        remote_name = str(uuid4().hex) + '.sql'

        # Copy the backup_file_path file into a container
        tarstream = io.BytesIO()
        with tarfile.TarFile(
            fileobj=tarstream,
            mode='w',
            dereference=True,
        ) as tar:
            tar.add(name=str(backup_file_path), arcname='/' + remote_name)
        tarstream.seek(0)

        self._cli.put_archive(
            container=self.container_name,
            path='/tmp',
            data=tarstream,
            )

        # Create database if not exists
        exec_id = self._cli.exec_create(
            container=self.container_name,
            cmd=(
                "bash -c './cockroach sql --insecure"
                " -e \"CREATE DATABASE IF NOT EXISTS {database_name};\"'".format(
                    database_name=database_name,
                )
            ),
        )
        res = self._cli.exec_start(exec_id=exec_id)
        assert self._cli.exec_inspect(exec_id=exec_id)['ExitCode'] == 0, res

        # Import a backup into the database
        exec_id = self._cli.exec_create(
            container=self.container_name,
            cmd=(
                "bash -c './cockroach sql --insecure --database={database_name}"
                " < /tmp/{filename}'"
            ).format(
                database_name=database_name,
                filename=remote_name,
            ),
        )
        res = self._cli.exec_start(exec_id=exec_id)
        assert self._cli.exec_inspect(exec_id=exec_id)['ExitCode'] == 0, res

    def start_and_wait(self):
        # Start container.
        self.start()
        # Wait for cockroachdb to be up and running.
        self._wait_for_cockroach_start()

    def _wait_for_cockroach_start(self):

        log.info('Waiting for CockroachDB to start')

        def _accepting_connections():
            _engine = sqlalchemy.create_engine(
                self.sql_alchemy_url_for_db('iam'),
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
