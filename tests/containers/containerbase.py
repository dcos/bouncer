# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
Module for managing Docker containers required by unit tests.

Currently using https://github.com/docker/docker-py which is
flexible, but also a mess.
"""

import errno
import logging
import socket
import time
from itertools import chain

import docker
import docker.errors
import pytest


log = logging.getLogger(__name__)


class ContainerBase():

    # Class attributes that must be defined by child classes.
    env = None
    imagename = None
    container_name = None

    def __init__(self):
        log.info('Set up Docker client')
        try:
            c = docker.APIClient(
                base_url='unix://var/run/docker.sock',
                version='auto')
        except Exception as e:
            pytest.fail('Failed to connect to docker daemon: %s' % str(e))

        # Some images may not be tagged, exclude them.
        def has_repotags(x):
            return 'RepoTags' in x and x['RepoTags'] is not None

        repotags = list(
            chain.from_iterable(i['RepoTags'] for i in c.images() if has_repotags(i)))
        log.debug('repotags: %s', repotags)

        if self.imagename not in repotags:
            log.info('Pull image: %s', self.imagename)
            c.pull(self.imagename)
        else:
            log.info('Using image: %s', self.imagename)

        self._cli = c

        # Handle if a previous run did not exit cleanly.
        if self._get_state() != 'uninitialized':
            self.close()

    def _get_state(self):
        try:
            state = self._cli.inspect_container(self.container_name)['State']
        except docker.errors.NotFound:
            return 'uninitialized'

        if state['Status'] in ['exited', 'created']:
            return 'stopped'

        if state['Status'] == 'paused':
            return 'paused'

        assert state['Status'] == 'running'
        assert state['Dead'] is False
        assert state['OOMKilled'] is False
        assert state['Restarting'] is False

        return 'running'

    def _get_network_state(self):
        # Ensure there is only one bridge network.
        bridge_network = [x for x in self._cli.networks()
                          if x['Name'] == 'bridge']

        assert len(bridge_network) == 1

        # Check whether the container is attached to the bridge
        # network.
        info = self._cli.inspect_container(self.container_name)
        network_settings = info['NetworkSettings']
        if 'bridge' in network_settings['Networks']:
            return 'connected'
        return 'disconnected'

    def _assert_current_state_is(self, state):
        cur_state = self._get_state()
        assert cur_state == state

    def _assert_current_network_state_is(self, state):
        assert self._get_network_state() == state

    def get_logtail(self, n_tail):
        return self._cli.logs(
            self.container_name,
            stdout=True,
            stderr=True,
            tail=n_tail
            ).decode('utf-8')

    def log_logtail(self, n_tail=200):
        tail = self.get_logtail(n_tail)
        log.debug(
            "\nStdout/err from container %s (up to %s lines):\n%s",
            self.container_name, n_tail, tail
            )

    def close(self):
        log.info('close() for container %s.', self.container_name)

        cur_state = self._get_state()
        if cur_state == 'uninitialized':
            return
        if cur_state == 'paused':
            self.unpause()
            self.stop()
        elif cur_state == 'running':
            self.stop()

        log.debug('Log tail after stop(): %s', self.get_logtail(300))
        log.info('Remove container %s.', self.container_name)
        self._cli.remove_container(self.container_name)
        log.info('Invoke %s.cleanup()', self.__class__.__name__)
        self.cleanup()

    def make_clean(self):
        """Clean up after certain tests, used as pytest fixture finalizer for
        certain tests."""
        cur_state = self._get_state()

        assert cur_state in ['paused', 'running', 'stopped']

        if cur_state == 'paused':
            self.unpause()
        elif cur_state == 'stopped':
            self.start()

        if self._get_network_state() == "disconnected":
            self.reattach_network()
            self._assert_current_network_state_is("connected")

    def start(self):
        log.info("start() for container %s", self.container_name)
        self._assert_current_state_is("stopped")
        self._cli.start(self.container_name)
        self._assert_current_state_is("running")
        log.debug('Log tail after start: %s', self.get_logtail(300))

    def stop(self):
        # Use stop instead of kill, as stop first sends SIGTERM whereas
        # kill immediately sends SIGKILL.
        self._assert_current_state_is("running")
        self._cli.stop(self.container_name)
        self._assert_current_state_is("stopped")

    def detach_network(self):
        self._assert_current_network_state_is("connected")
        self._cli.disconnect_container_from_network(
            self.container_name, 'bridge')
        self._assert_current_network_state_is("disconnected")

    def reattach_network(self):
        self._assert_current_network_state_is("disconnected")
        self._cli.connect_container_to_network(self.container_name, 'bridge')
        self._assert_current_network_state_is("connected")

    def pause(self):
        self._assert_current_state_is("running")
        self._cli.pause(self.container_name)
        self._assert_current_state_is("paused")

    def unpause(self):
        self._assert_current_state_is("paused")
        self._cli.unpause(self.container_name)
        self._assert_current_state_is("running")

    def cleanup(self):
        """Invoked by self.close(). To be overridden by child class,
        as a general-purpose cleanup entrypoint.
        """
        pass


def wait_net_service(server, port, timeout=None):
    """Wait for socket to be reachable.

    Args:
        timeout: timeout in seconds. Wait forever if it evaluates to False.

    Returns: True of False. Without timeout, return True or throw exception.

    Props to https://code.activestate.com/recipes/576655-wait-for-network-service-to-appear
    """
    log.info('wait_net_service() for %s:%s', server, port)

    s = socket.socket()
    if timeout:
        end = time.time() + timeout

    while True:
        try:
            if timeout:
                next_timeout = end - time.time()
                if next_timeout < 0:
                    return False
                else:
                    s.settimeout(next_timeout)

            s.connect((server, port))

        except socket.timeout:
            if timeout:
                return False

        except socket.error as err:
            if err.errno not in (
                    errno.ETIMEDOUT, errno.ECONNREFUSED, errno.ECONNABORTED):
                raise
        else:
            s.close()
            return True
