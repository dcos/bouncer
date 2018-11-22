# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
This module manages containers providing OpenID Connect providers.

The providers are based on
- https://github.com/rohe/pyoidc/tree/master/oidc_example/op2
- https://github.com/coreos/dex
"""


import json
import logging
import os
import shutil
import time

from bs4 import BeautifulSoup
import pytest
import requests
from oic.oic import Client as OIDCClient
from oic.utils.authn.client import CLIENT_AUTHN_METHOD as OIDC_AUTHN_METHOD

from tests.containers.containerbase import ContainerBase


log = logging.getLogger(__name__)


class ContainerOIDCProvider(ContainerBase):
    """Generic abstraction for a containerized OpenID Connect provider."""
    def __init__(self, tmpdir_factory):
        super().__init__()

        self.log = logging.getLogger(
            '%s.%s' % (__name__, self.__class__.__name__))

        assert self.issuer.endswith('/')

        # Build absolute path to directory containing various certificate and
        # key files. For now, use the files in the pyoidc-op directory also
        # for the Dex-based container.
        self.certs_dir_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'pyoidc-op', 'certs'
            )

        # Prepare temporary directory with cert/key files, to be mounted in the
        # OP container.
        host_tmp_certs_dir_path = self._prepare_tmp_certs_dir(tmpdir_factory)

        volume_binds = {
            host_tmp_certs_dir_path: {
                'bind': self.container_certs_dir_mount_target,
                'mode': 'ro'
                }
            }

        # In the container, the OP listens on `self.container_listen_port`.
        # Expose on all interfaces on the host which includes the Docker
        # interface which is what is required.
        port_bindings = {
            self.container_listen_port: ('0.0.0.0', self.host_listen_port)
            }

        host_config = self._cli.create_host_config(
            port_bindings=port_bindings,
            binds=volume_binds
            )

        self._container = self._cli.create_container(
            command=self._run_cmd,
            image=self.imagename,
            detach=True,
            ports=list(port_bindings),
            host_config=host_config,
            name=self.container_name
            )

        self._read_ca_cert_data()
        self.log.info('Container image: %s', self.imagename)
        self.log.info('Container port bindings: %r', port_bindings)
        self.log.info('Container volume binds: %r', volume_binds)

    def _prepare_tmp_certs_dir(self, tmpdir_factory):
        """Create temporary directory populated with the certificate and key
        file which the OP should use for serving TLS.

        Within the temporary directory, create another directory called `certs`.
        Then select the crt/key files from `tests/containers/pyoidc-op/certs`
        based on the class attributes `op_certfile_name` and `op_keyfile_name`
        and copy them so that the final temporary struture is:

            <tempdir>/certs/server.crt
            <tempdir>/certs/server.key

        Returns:
            Absolute path to the `<tempdir>/certs` directory.
        """
        # Create a temporary directory and create `certs` dir in there.
        tmp_dir_path = str(tmpdir_factory.mktemp('bouncer-oidctests'))
        tmp_certs_dir_path = os.path.join(tmp_dir_path, 'certs')
        os.mkdir(tmp_certs_dir_path)

        # Populate the `<tempdir>/certs` directory with server.crt/key.
        certfile_path = os.path.join(self.certs_dir_path, self.op_certfile_name)
        keyfile_path = os.path.join(self.certs_dir_path, self.op_keyfile_name)

        log.info(
            'Prepare cert and key files for OP: %s and %s',
            certfile_path,
            keyfile_path
            )
        shutil.copy(
            certfile_path,
            os.path.join(tmp_certs_dir_path, 'server.crt')
            )
        shutil.copy(
            keyfile_path,
            os.path.join(tmp_certs_dir_path, 'server.key')
            )

        return tmp_certs_dir_path

    def start_and_wait(self):
        self.start()
        self._wait_for_provider_start()
        self._poststart()

    def _read_ca_cert_data(self):
        cert_data_filepath = os.path.join(self.certs_dir_path, 'ca-chain.pem')
        cert_data_filepath_no_match = os.path.join(
            self.certs_dir_path, 'ca-chain-no-match.pem')

        with open(cert_data_filepath, 'rb') as f:
            self.ca_cert_data = f.read().decode('utf-8')

        with open(cert_data_filepath_no_match, 'rb') as f:
            self.ca_cert_data_no_match = f.read().decode('utf-8')

    def _wait_for_provider_start(self, timeout=5):

        # The following URL is a valid resource as of the OIDC spec.
        url = '{}.well-known/openid-configuration'.format(self.issuer)

        log.info('Wait for containerized OIDC provider to serve at URL %s', url)
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                r = requests.get(url, timeout=0.1, verify=False)
            except requests.exceptions.SSLError:
                # This happens when web app is still starting.
                pass
            except requests.exceptions.Timeout:
                pass
            except requests.exceptions.ConnectionError:
                pass
            else:
                if r.status_code == 200:
                    log.info("OIDC provider serves, proceed.")
                    return

            time.sleep(0.1)

        # That's an unexpected condition, exit test run.
        self.log_logtail()
        pytest.fail('Timeout while waiting for OIDC container. Cf. logs.')

    def _build_bouncer_config(self):
        cfg = self._config
        self.log.info('Provider config for Bouncer: %s', cfg)
        return cfg

    def _poststart(self):
        self.provider_config_for_bouncer = self._build_bouncer_config()

    def _register_client(self):
        """Dynamically register RP (OIDC client) with OP, using
        just the issuer as input.

        Example registration response:

        {
            "registration_client_uri": "https://host/registration?client_id=x",
            "response_types": [
            "code"
            ],
            "redirect_uris": [
            "http://127.0.0.1:8101/acs/api/v1/auth/oidc/callback"
            ],
            "client_id": "N2x760gY3bW1",
            "client_secret_expires_at": 1460651213,
            "registration_access_token": "IfZdsIU1UEkoir4JHvNYwFfdnFRc1Jgz",
            "application_type": "web",
            "client_id_issued_at": 1460564813,
            "token_endpoint_auth_method": "client_secret_basic",
            "client_secret": "2dc1<snip>3e462cc696033843de334f"
        }
        """

        self.log.info('Dynamically register client with OIDC provider.')

        c = OIDCClient(client_authn_method=OIDC_AUTHN_METHOD, verify_ssl=False)

        provider_info = c.provider_config(self.issuer)
        self.log.debug(
            'provider_info: %s',
            json.dumps(provider_info.to_dict(), indent=4)
            )

        c.redirect_uris = [
            'http://127.0.0.1:8101/acs/api/v1/auth/oidc/callback'
            ]

        registration_response = c.register(
            provider_info['registration_endpoint'])
        reg = registration_response.to_dict()

        self.log.debug('registration_response: %s', json.dumps(reg, indent=4))
        self.log.info('Dynamically registered OIDC client.')
        return reg


class ContainerPyOIDC(ContainerOIDCProvider):
    """Abstraction for a PyOIDC-based OpenID Connect provider.

    Ref: https://github.com/rohe/pyoidc/tree/master/oidc_example/op2

    This provider support dynamic client registration, so let's do so!
    """

    imagename = 'mesosphereci/bouncer-test-pyoidc-op2:latest'
    container_name = 'bouncer-test-pyoidc-op2'
    container_certs_dir_mount_target = '/pyoidc/oidc_example/op2/certs'

    host_listen_port = 8092
    container_listen_port = 8092

    op_certfile_name = 'oidc-idp-SAN-DNS-bouncer-test-hostmachine.crt'
    op_keyfile_name = 'oidc-idp-SAN-DNS-bouncer-test-hostmachine.key'

    issuer = 'https://bouncer-test-hostmachine:8092/'

    @property
    def _run_cmd(self):
        # The meaning of the command line arguments is documented in the PyOIDC
        # repository at pyoidc/oidc_example/op2/server.py.
        return [
            'python',
            'server.py',
            '-p', '8092',  # Define listen port _within_ the container.
            '-i', self.issuer,
            '-t',  # Enable TLS.
            '-d',  # Enable debug mode.
            'config'
            ]

    @property
    def _config(self):
        """Register client dynamically with OP.

        Construct a configuration dictionary of this form:

        {
            "description": "Local test OP (PyOIDC-based)",
            "issuer": "https://bouncer-test-hostmachine:8092/",
            "base_url": "http://127.0.0.1:8101/",
            "client_secret": "fd3325<snip>9d42ca84785b52",
            "client_id": "VOjXHOLLrQkf",
            "verify_server_certificate": False
        }
        """

        reg_resp = self._register_client()

        return {
            'description': 'Local test OP (PyOIDC-based)',
            'issuer': self.issuer,
            'base_url': 'http://127.0.0.1:8101/',
            'client_secret': reg_resp['client_secret'],
            'client_id': reg_resp['client_id'],
            'verify_server_certificate': False
            }


class ContainerPyOIDCLosPollos(ContainerPyOIDC):
    """Same as ContainerPyOIDC, but presenting a different TLS cert.

    Start OP serving a certificate with a DNSName SAN (`los-pollos.io`) that
    does not match the hostname used by the client to address the server
    (`bouncer-test-hostmachine`).
    """
    op_certfile_name = 'oidc-idp-SAN-DNS-los-pollos.crt'
    op_keyfile_name = 'oidc-idp-SAN-DNS-los-pollos.key'

    container_name = 'bouncer-test-pyoidc-op2-los-pollos'

    host_listen_port = 8093
    issuer = 'https://bouncer-test-hostmachine:8093/'


class ContainerDex(ContainerOIDCProvider):
    """Abstraction for a Dex-based OpenID Connect provider.

    Ref: https://github.com/coreos/dex
    """

    imagename = 'mesosphereci/bouncer-test-dex:latest'
    container_name = 'bouncer-test-dex'
    container_certs_dir_mount_target = '/dexcerts'
    container_listen_port = 8900

    host_listen_port = 8900

    op_certfile_name = 'oidc-idp-SAN-DNS-bouncer-test-hostmachine.crt'
    op_keyfile_name = 'oidc-idp-SAN-DNS-bouncer-test-hostmachine.key'

    issuer = 'https://bouncer-test-hostmachine:8900/dex-for-bouncer/'

    _run_cmd = ['dex', 'serve', 'config-for-bouncer-unit-tests.yaml']

    @property
    def _config(self):
        """Use static configuration, enrich it with CA cert data."""
        return {
            'description': 'Local test OP (Dex-based)',
            'issuer': self.issuer,
            'base_url': 'http://127.0.0.1:8101/',
            'client_secret': 'AnotherStaticSecret',
            'client_id': 'bouncer-test-client',
            'verify_server_certificate': True,
            'ca_certs': self.ca_cert_data
            }

    def parse_login_page(self, html):
        """Parse HTML, extract all info required for form submission.

        If the `connectors` enumeration in Dex' config.yaml is empty, then this
        landing page presents a form. If it is not empty, then this landing page
        requires selecting one of the connectors. Rely on no connectors being
        defined.
        """
        page = BeautifulSoup(html, features='lxml')

        # Dex emits just a relative POST URL in the login HTML doc.
        rel_post_url = page.find('form')['action']

        return rel_post_url

    def parse_consent_review_page(self, html):
        """Parse HTML, extract all info required for form submission.

        Form example:

              <form method="post">
                <input type="hidden" name="req" value="vinfxhadooorlhxikzae"/>
                <input type="hidden" name="approval" value="approve">
                <button type="submit" class="dex-btn theme-btn--success">
                    <span class="dex-btn-text">Grant Access</span>
                </button>
              </form>

        """
        page = BeautifulSoup(html, features='lxml')
        form_data = {
            'approval': 'approve',
            'req': page.find('input', attrs={'name': 'req'})['value']
            }

        return form_data
