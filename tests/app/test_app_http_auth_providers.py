# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
HTTP tests for the /auth/providers endpoint.

This lives in its own test module so that this type of test can conveniently be
replaced downstream.
"""


import pytest
import requests

from tests.misc import Url


pytestmark = [pytest.mark.usefixtures('wsgi_app')]


@pytest.mark.usefixtures('datastore_reset')
class TestListAuthProviders:

    def test_default_providers(self):
        providers_url = Url('/auth/providers')
        r = requests.get(providers_url)
        assert r.status_code == 200
        d = r.json()
        assert set(d.keys()) == set([
            'dcos-users',
            'dcos-services',
            'dcos-oidc-auth0'
        ])

    def test_legacy_user_creation_with_meaningless_request_body(self):
        """Test for a special property of the `dcos-oidc-auth0` auth provider.

        Legacy HTTP clients, such as the web UI, might insert users in the
        following way and expect those users to be usable with the legacy OIDC
        ID Token login method through the 'https://dcos.auth0.com/' provider.
        """
        r = requests.put(Url('/users/user@example.com'), json={})
        assert r.status_code == 201

        r = requests.get(Url('/users/user@example.com'))
        assert r.json()['provider_type'] == 'oidc'
        assert r.json()['provider_id'] == 'https://dcos.auth0.com/'

        # Make sure that the above magic depends on the uid looking like an
        # email address.
        r = requests.put(Url('/users/user1'), json={})
        assert r.status_code == 400
        assert 'One of `password` or `public_key` must be provided' in r.text
