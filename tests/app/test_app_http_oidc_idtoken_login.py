# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


import json
import logging
import urllib.parse
from urllib.parse import urljoin

import pytest
import requests
import jwt
from jwt.utils import base64url_decode, base64url_encode

from tests.misc import Url


log = logging.getLogger('tests.test_app_http_oidc_idtoken_login')


pytestmark = [pytest.mark.usefixtures('datastore_reset')]


class TestLegacyIDTokenLogin:

    """
    These tests require that the OP supports the id_token response type (an OP
    has to support this for supporting the so-called "implicit flow"). This can
    be confirmed via e.g.:

    GET .../dex-for-bouncer/.well-known/openid-configuration:

    [...]

      "issuer": "https://bouncer-test-hostmachine:8900/dex-for-bouncer/",
      "authorization_endpoint": "https://bouncer-test-hostmachine:8900/dex-for-bouncer/auth",
      "token_endpoint": "https://bouncer-test-hostmachine:8900/dex-for-bouncer/token",
      "jwks_uri": "https://bouncer-test-hostmachine:8900/dex-for-bouncer/keys",
      "response_types_supported": [
        "code",
        "id_token",
        "token"
      ],

    [...]

    This is just *one* of many ways to obtain an ID Token. The core business
    logic that we test is then if a specific ID Token (no matter how it was
    obtained) can be used to log in.
    """

    def _get_id_token(
            self,
            dex,
            username,
            password,
            scope='openid%20profile%20email',
            clientid='bouncer-test-client-for-legacy-id-token-login'
            ):

        # Construct request as specified in section "3.2.2.1.  Authentication
        # Request" of https://openid.net/specs/openid-connect-core-1_0.html.
        # That is, construct URL encoding all relevant detail for the
        # authentication request. Use aspects known from the OP configuration
        # (redirect URI, client ID). Use arbitrary nonce. Construct `scope`
        # dynamically.

        authentication_request_url = dex.issuer + \
            'auth?response_type=id_token&' + \
            f'client_id={clientid}&' + \
            'redirect_uri=is.not.followed.by.the.user.agent&' + \
            f'scope={scope}&nonce=123456abcdefg'

        with requests.Session() as s:

            # Disable cert verification for all requests in this session.
            s.verify = False

            r1 = s.get(authentication_request_url)

            # Extract the full URL we've been redirected to. It is required for
            # constructing the URL to POST the credentials form to.
            login_page_url = r1.url
            rel_login_post_url = dex.parse_login_page(r1.text)
            login_post_url = urljoin(login_page_url, rel_login_post_url)

            login_form_data = {
                'login': username,
                'password': password,
                }

            log.info('rel_login_post_url: %s', rel_login_post_url)
            log.info('login_form_data: %s', login_form_data)
            log.info('login_post_url: %s', login_post_url)
            r2 = s.post(login_post_url, data=login_form_data)

            # `r2.text` is expected to be an HTML document containing the
            # consent form. Parse the document and POST the form data to the
            # same endpoint that served it. Upon success, the response emitted
            # by Dex redirects back to the RP (Bouncer) which (in the
            # back-channel) communicates with the OP and eventually emits the
            # auth token.
            consent_form_data = dex.parse_consent_review_page(r2.text)

            # Extract the full URL for the endpoint that served the consent
            # form from the previous response.
            consent_post_url = r2.url

            log.info('consent_post_url: %s', consent_post_url)
            log.info('consent_form_data: %s', consent_form_data)
            r3 = s.post(
                consent_post_url,
                data=consent_form_data,
                allow_redirects=False
                )

        # The authentication response parameters are encoded in the anchor
        # string of the redirect location. Do not follow the redirect,
        # inspect the ID token, expect nonce to be set as (this is not
        # critical for this test but is helpful for understanding things).
        anchortext = r3.headers['Location'].split('#')[1]
        id_token = urllib.parse.parse_qs(anchortext)['id_token'][0]

        id_token_decoded = jwt.decode(id_token, verify=False)

        # Note(JP): the nonce check is just an intermediate checkpoint, not too
        # relevant for this test, but since we are in the middle of a
        # complicated flow it serves like an assertion: is everything still as
        # it's expected to be?
        assert id_token_decoded['nonce'] == '123456abcdefg'
        return id_token

    def setup(self):
        """Executed before every test in this class. Skip if this Bouncer
        variant does not offer the OIDC ID Token login.
        """
        providers_url = Url('/auth/providers')
        r = requests.get(providers_url)
        assert r.status_code == 200
        d = r.json()
        if 'dcos-oidc-auth0' not in d:
            pytest.skip('OIDC ID Token login not activated')

    def test_login_succeeds(self, dex):

        id_token = self._get_id_token(dex, 'admin@example.com', 'password')

        # With the OIDC ID token (text) at hand the goal of this test is to
        # confirm that it can be exchanged into a DC/OS authentication token.
        # This login method was built for (open) DC/OS in April 2016, and the
        # goal here is to resemble that implementation. Sadly, the entry point
        # is not really explicit (POST request JSON body with a 'token' key).
        r = requests.post(Url('/auth/login'), json={'token': id_token})
        assert r.status_code == 200
        assert 'token' in r.json()

        # Confirm that user was imported implicitly.
        users = {u['uid']: u for u in requests.get(Url('/users')).json()['array']}
        assert 'admin@example.com' in users
        assert users['admin@example.com']['is_remote']

    def test_login_succeeds_twice_for_same_user(self, dex):
        """
        So far we allow a reply attack. Hence, technically we could use the same
        `id_token`. However, don't do this here in hopefully anticipation of us
        fixing the replay vulnerability.
        """

        id_token_1 = self._get_id_token(dex, 'admin@example.com', 'password')
        r = requests.post(Url('/auth/login'), json={'token': id_token_1})
        assert r.status_code == 200

        id_token_2 = self._get_id_token(dex, 'admin@example.com', 'password')
        r = requests.post(Url('/auth/login'), json={'token': id_token_2})
        assert r.status_code == 200

        # When one understands the inner workings of _get_id_token() then it is
        # obvious that the two ID tokens differ. The following assertion proves
        # that fact to the reader (however, testing this is not essential for
        # this test).
        assert id_token_1 != id_token_2

    def test_login_first_user_wins(self, dex):
        """
        DC/OS uses the dead-simple "first user wins" approach, where the first
        user that presents a valid ID Token from one of the white-listed
        providers is accepted and imported by the IAM. A subsequent login
        attempt with valid ID Token results in a 401 if the user is not known
        in the database.
        """

        id_token_1 = self._get_id_token(dex, 'admin@example.com', 'password')
        r = requests.post(Url('/auth/login'), json={'token': id_token_1})
        assert r.status_code == 200

        id_token_2 = self._get_id_token(dex, 'user2@example.com', 'password')
        r = requests.post(Url('/auth/login'), json={'token': id_token_2})
        assert r.status_code == 401
        assert 'user unknown' in r.text

    def test_login_after_manual_add(self, dex):
        """
        This test is similar to `test_login_first_user_wins` but makes use of
        the idea that the second login will succeed if the user is manually
        added to the database before the login attempt. Note that in a real
        cluster setup only an authenticated request is allowed to create the
        user record.
        """

        id_token_1 = self._get_id_token(dex, 'admin@example.com', 'password')
        r = requests.post(Url('/auth/login'), json={'token': id_token_1})
        assert r.status_code == 200

        # Create user record and set the matching provider type and id (this is
        # required).
        udata = {
            'provider_type': 'oidc',
            'provider_id': dex.issuer
            }
        r = requests.put(Url('/users/user2@example.com'), json=udata)
        assert r.status_code == 201

        id_token_2 = self._get_id_token(
            dex, 'user2@example.com', 'password')
        r = requests.post(Url('/auth/login'), json={'token': id_token_2})
        assert r.status_code == 200

    def test_login_after_manual_add_provider_mismatch(self, dex):
        """
        This test is similar to `test_login_after_manual_add` but confirms that
        when the manually created user record has a provider ID mismatch that
        the login then fails.
        """

        id_token_1 = self._get_id_token(dex, 'admin@example.com', 'password')
        r = requests.post(Url('/auth/login'), json={'token': id_token_1})
        assert r.status_code == 200

        # Create user record and set the matching provider type and id (this is
        # required).
        udata = {
            'provider_type': 'oidc',
            'provider_id': 'this-should-be-the-token-issuer-but-it-is-not'
            }
        r = requests.put(Url('/users/user2@example.com'), json=udata)
        assert r.status_code == 201

        id_token_2 = self._get_id_token(dex, 'user2@example.com', 'password')
        r = requests.post(Url('/auth/login'), json={'token': id_token_2})
        assert r.status_code == 401
        assert 'provider ID mismatch' in r.text

    def test_login_fails_old_auth0_id_token(self, dex):

        # As of the time of writing the test this is an expired ID Token with
        # the issuer `https://dcos.auth0.com`. The validation will always fail
        # in the future either as of the expiry or because Auth0 rotates a key
        # (which they don't without us telling them, I think). If the JWKS data
        # for this issuer cannot be fetched the response will be a 500 Internal
        # Server Error.
        old_auth0_id_token = (
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik9UQkVOakZFTWtWQ09VRT'
            'RPRVpGTlRNMFJrWXlRa015Tnprd1JrSkVRemRCTWpBM1FqYzVOZyJ9.eyJlbWFpbCI'
            '6ImpnZWhyY2tlQGdvb2dsZW1haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsI'
            'mlzcyI6Imh0dHBzOi8vZGNvcy5hdXRoMC5jb20vIiwic3ViIjoiZ2l0aHVifDI2NTY'
            'zMCIsImF1ZCI6IjN5RjVUT1N6ZGxJNDVRMXhzcHh6ZW9HQmU5Zk54bTltIiwiaWF0I'
            'joxNTM2MzIzMTk3LCJleHAiOjE1MzY3NTUxOTd9.ii721w56lCBqvfqdsm23TIn9-H'
            'jQ9T9IFyfq9yW9t9sgcxAiQzH6GQfdQk4Nqacqjn8CwNzxmqq9YZGKTLt_N0Eqqxkr'
            'l3RJ_5kuz2FZsSnWBh8BipynSdDCymSm9oYXXpM7IF51Nxq6jZSuU_KqKwYb5RIFsI'
            '3nJpQMI_gpbA5QXRqj3KpzudIcC2JPNA2aADQDAs7UPUt2KnN3SVjxnvq_Xnx83DTZ'
            'oygb7JM24KBCDmfQLQOpDHKVrSNFvTuLSst6WzSlXPRpuhp4jSzK0-Z5Xebz4974Q0'
            '8O619b8BJmQx-VbauD7SQ0wcorKevJdh98X4cuiiag9B9xfuo0EA'
        )
        r = requests.post(Url('/auth/login'), json={'token': old_auth0_id_token})
        assert r.status_code == 401
        assert 'token expired' in r.json()['description']

    def test_login_fails_bad_signature(self, dex):

        # This token is not expired, but has a bad signature.
        id_token = self._get_id_token(dex, 'admin@example.com', 'password')

        header_bytes, payload_bytes, signature_bytes = [
            base64url_decode(_.encode('ascii')) for _ in id_token.split(".")]
        payload_dict = json.loads(payload_bytes.decode('ascii'))

        # Change `email` and invert token decode procedure.
        forged_payload_dict = payload_dict.copy()
        forged_payload_dict['email'] = 'h@xx.lol'
        forged_payload_bytes = json.dumps(forged_payload_dict).encode('utf-8')

        forged_token = '.'.join(
            base64url_encode(_).decode('ascii') for _ in (
                header_bytes, forged_payload_bytes, signature_bytes)
            )

        r = requests.post(Url('/auth/login'), json={'token': forged_token})
        assert r.status_code == 401
        assert 'bad token' in r.json()['description']

    def test_login_fails_missing_email_claim(self, dex):

        # Get ID Token but do not request `email` and `profile` claims (override
        # `scope` which is communicated to the OP in the authentication
        # request). That results in the ID Token to lack the required claims
        # `email` and `email_verified`.
        id_token = self._get_id_token(
            dex, 'admin@example.com', 'password', scope='openid')

        r = requests.post(Url('/auth/login'), json={'token': id_token})
        assert r.status_code == 401
        assert 'ID Token lacks non-standard claim' in r.json()['description']
        assert 'email' in r.json()['description']

    def test_login_fails_audience_mismatch(self, dex):

        # Get a "valid ID Token" from a whitelisted issuer, but for a different
        # client ID. That is, validation of the audience of the ID Token is
        # expected to fail.
        id_token = self._get_id_token(
            dex,
            'admin@example.com',
            'password',
            clientid='bouncer-test-client2-for-legacy-id-token-login'
        )

        r = requests.post(Url('/auth/login'), json={'token': id_token})
        assert r.status_code == 401
        # This is treated as a "malicious token", so the error description is
        # generic. The IAM log will say "Error: unexpected `aud`".
        assert 'bad token' in r.json()['description']

    def test_login_first_user_and_ui_config_change(self, dex):
        """
        Build on the `test_login_first_user_wins` test and confirm that the
        dynamically generated UI config contains the expected value for the
        `firstUser` key. This implements the initial phase of an (open) DC/OS
        cluster lifecycle.
        """

        assert requests.get(Url('/uiconfig')).json()[
            'clusterConfiguration']['firstUser'] is True

        id_token_1 = self._get_id_token(dex, 'admin@example.com', 'password')
        r = requests.post(Url('/auth/login'), json={'token': id_token_1})
        assert r.status_code == 200

        assert requests.get(Url('/uiconfig')).json()[
            'clusterConfiguration']['firstUser'] is False
