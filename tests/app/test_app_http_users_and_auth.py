# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
End-to-end tests for the HTTP API, using requests as HTTP client.
"""


import base64
import logging
import json
import time
from textwrap import dedent

import jwt
import pytest
import requests
import cryptography.hazmat.backends
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.utils import base64url_decode, bytes_to_number

from tests.misc import (
    PROVIDER_TYPES,
    Url,
    UrlBootstrapServiceAcc,
    generate_RSA_keypair
)


# Apply markers and fixtures to *all* tests in this module.
# From pytest docs:
# "Note that the assigned variable must be called pytestmark"
# Assigning a list is not well-documented, found that here:
# https://github.com/pytest-dev/pytest/issues/816#issuecomment-119545763
pytestmark = [pytest.mark.usefixtures('wsgi_app')]


cryptography_backend = cryptography.hazmat.backends.default_backend()


log = logging.getLogger(__name__)


# Pre-generate keypair for performance reasons.
default_rsa_privkey, default_rsa_pubkey = generate_RSA_keypair()


class _UserProviderFieldsValidator:
    """
    Provides validation for the various legal combinations
    of password / public_key, provider_type and provider_id.
    """

    def __init__(self, resp, password, public_key, provider_type, provider_id):
        self.resp = resp
        self.password = password
        self.public_key = public_key
        self.provider_type = provider_type
        self.provider_id = provider_id

    def _provider_id_required(self):
        types = ['oidc', 'saml']
        return self.provider_type in types

    def _password_or_public_key_required(self):
        """This means setting the corresponding fields at all, and setting them
        to non-empty string values.
        """
        if not self.provider_type:
            return True
        return self.provider_type == 'internal'

    def request_was_valid(self):
        """
        Returns True if the request passed validation and the
        user object may be considered created.
        Returns None if the request was expected not to pass
        validation to signal the caller that it should terminate.

        Raises AssertionError if any expectations are not met.
        """
        if self.password == '' or self.public_key == '':
            # A password or public key is required. Neither must be an empty
            # string.
            assert self.resp.status_code == 400, self.resp.text
            assert 'must not be empty when provided' in self.resp.json()['description']
            return

        # Assert failure if an incorrect provider_type was provided
        if self.provider_type is not None and self.provider_type not in PROVIDER_TYPES:
            assert self.resp.status_code == 400
            assert 'Invalid provider_type' in self.resp.json()['description']
            return

        # Assert failure if password/public_key fields are incorrectly specified.

        pw_given = (self.password, self.public_key)
        if self._password_or_public_key_required():

            if len([_ for _ in pw_given if _]) != 1:
                # Check that at least one is given, as a non-empty string
                assert self.resp.status_code == 400, self.resp.text
                errmsg = 'One of `password` or `public_key` must be provided'
                assert errmsg in self.resp.json()['description']
                return

        else:
            if self.password:
                assert self.resp.status_code == 400, self.resp.text
                assert '`password` is unexpected' in self.resp.json()['description']
                return

            if self.public_key:
                assert self.resp.status_code == 400, self.resp.text
                assert '`public_key` is unexpected' in self.resp.json()['description']
                return

        # Assert failure if provider_id is incorrectly specified.
        if self._provider_id_required():
            # Check provider_id is a non-empty, non-blank string if
            # provider_type is oidc or saml.
            if not self.provider_id:
                assert self.resp.status_code == 400, self.resp.text
                assert self.resp.json()['code'] == 'ERR_INVALID_DATA'
                errmsg = (
                    'Invalid provider_id: provider_id must be provided '
                    'if provider_type is saml or oidc'
                    )
                assert errmsg in self.resp.json()['description']
                return
        else:
            # Check provider_id is not provided if provider_type is neither
            # oidc nor saml.
            if self.provider_id:
                assert self.resp.status_code == 400, self.resp.text
                assert self.resp.json()['code'] == 'ERR_INVALID_DATA'
                errmsg = (
                    'Invalid provider_id: provider_id must not be provided '
                    'unless provider_type is saml or oidc'
                    )
                assert errmsg in self.resp.json()['description']
                return
        # The request was expected to succeed and did so. Yield to the context manager.
        return True


def user_provider_fields_are_valid(
        response, password, public_key, provider_type, provider_id):
    v = _UserProviderFieldsValidator(
        response,
        password,
        public_key,
        provider_type,
        provider_id,
        )
    return v.request_was_valid()


@pytest.mark.usefixtures("datastore_reset")
class TestUserCreate:
    """This is just for testing a simple user creation scenario.

    Prerequisite in more complex tests (and then automated within unit test
    setup, for bootstrapping the datastore).
    """

    def test_put_user(self):
        uid = 'usera'
        data = {
            'description': 'User A',
            'password': 'ThisIsAPassword'
            }
        url = Url('/users/%s' % uid)
        r = requests.put(url, json=data)
        assert r.status_code == 201

    @pytest.mark.parametrize(
        "provider_type", [None, '', 'bad'] + PROVIDER_TYPES)
    def test_put_user_provider_type(self, provider_type):
        """Test that only valid provider types are allowed.

        Also test that '', None, and `internal` are equivalent.
        """
        uid = 'usera'
        data = {'description': 'User A'}
        if provider_type is not None:
            data['provider_type'] = provider_type
        if not provider_type or provider_type == 'internal':
            # Add a dummy password if required so we don't get stuck on unrelated
            # validation checks.
            data['password'] = 'some password'
        if provider_type in ['saml', 'oidc']:
            # Add a dummy provider_id if required so we don't get stuck on
            # unrelated validation checks.
            data['provider_id'] = 'some provider id'

        url = Url('/users/%s' % uid)
        r = requests.put(url, json=data)

        if user_provider_fields_are_valid(
                r,
                data.get('password'),
                data.get('public_key'),
                data.get('provider_type'),
                data.get('provider_id')):

            # All validation checks are expected to pass, so the user should be created.
            assert r.status_code == 201, r.text

            r = requests.get(url)
            assert r.status_code == 200, r.text
            if provider_type:
                exp_provider_type = provider_type
            else:
                exp_provider_type = 'internal'
            assert r.json()['provider_type'] == exp_provider_type

    @pytest.mark.parametrize("password", [None, '', 'ThisIsAPassword'])
    @pytest.mark.parametrize("public_key", [None, '', default_rsa_pubkey])
    @pytest.mark.parametrize("provider_type", [None] + PROVIDER_TYPES)
    @pytest.mark.parametrize("provider_id", [None, '', ' ', 'some id'])
    def test_put_user_provider_fields(self, password, public_key, provider_type, provider_id):
        """
        Test that only legal combinations of provider_type,
        provider_id, password / public_key work.
        """

        uid = 'usera'
        data = {'description': 'User A'}
        if password is not None:
            data['password'] = password
        if public_key is not None:
            data['public_key'] = public_key
        if provider_type is not None:
            data['provider_type'] = provider_type
        if provider_id is not None:
            data['provider_id'] = provider_id

        url = Url('/users/%s' % uid)
        r = requests.put(url, json=data)

        if user_provider_fields_are_valid(
                r,
                password,
                public_key,
                provider_type,
                provider_id,
                ):

            # All validation checks are expected to pass, so the user should be
            # created.
            assert r.status_code == 201

            # Check that the user was created and that the provider_type and
            # provider_id was set as expected.
            r = requests.get(url)
            d = r.json()
            assert r.status_code == 200
            if provider_type:
                assert d['provider_type'] == provider_type
            else:
                assert d['provider_type'] == 'internal'
            if provider_id:
                assert d['provider_id'] == provider_id
            else:
                assert d['provider_id'] == ''

    @pytest.mark.parametrize("uid", ["a!", "!a", "a" * 97])
    def test_put_uid_validation_invalid_strings(self, uid):
        url = Url('/users/{uid}'.format(uid=uid))
        data = {
            'description': 'User A',
            'password': 'ThisIsAPassword'
            }
        r = requests.put(url, json=data)
        assert r.status_code == 400
        assert r.json()['code'] == 'ERR_INVALID_USER_ID'
        assert 'Invalid user ID' in r.json()['description']

    @pytest.mark.parametrize(
        "uid", ["a", "Az09@.", "a-", "a.a", "a" * 96, "ldap.username-X09", "a_a"])
    def test_put_uid_validation_valid_strings(self, uid):
        url = Url('/users/{uid}'.format(uid=uid))
        data = {
            'description': 'User A',
            'password': 'ThisIsAPassword'
            }
        r = requests.put(url, json=data)
        assert r.status_code == 201

    def test_put_service(self):
        uid = 'servicea'
        data = {
            'description': 'Service A',
            'public_key': default_rsa_pubkey
        }
        url = Url('/users/%s' % uid)
        r = requests.put(url, json=data)
        assert r.status_code == 201

    def test_put_service_wrong_pem_pubkey_1(self):
        # Make dashed lines indicate that this is a PKCS#1 PEM key format
        # instead of the X.509 pubkey format.
        wrongkey = default_rsa_pubkey.replace('PUBLIC KEY', 'RSA PUBLIC KEY')
        uid = 'servicea'
        data = {
            'description': 'Service A',
            'public_key': wrongkey
        }
        url = Url('/users/%s' % uid)
        r = requests.put(url, json=data)
        assert r.status_code == 400
        assert 'Invalid public key' in r.text

    def test_put_service_wrong_pem_pubkey_2(self):
        # Present an Elliptic Curve public key in X.509 PEM format. It has the
        # same header (dashy lines) as an RSA type X.509 pubkey would have,
        # but encodes a different key type in its payload. See
        # http://stackoverflow.com/a/29707204/145400

        # Define pre-generated key. Created with the cryptography module with
        # the OpenSSL back-end:
        # >>> from cryptography.hazmat.backends import default_backend
        # >>> from cryptography.hazmat.primitives.asymmetric import ec
        # >>> from cryptography.hazmat.primitives import serialization
        # >>> c = ec.EllipticCurve
        # >>> c.name = "secp256r1">>> c.key_size = 256
        # >>> privkey = ec.generate_private_key(curve=c, backend=default_backend())
        # >>> pubkey = privkey.public_key()
        # >>> pubkey.public_bytes(
        #    encoding=serialization.Encoding.PEM,
        #    format=serialization.PublicFormat.SubjectPublicKeyInfo)

        elliptic_curve_pubkey_pem_x509 = dedent("""
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/wMXOeN0OLzsO22VUsOhwwhaMaxk
            fPBF/7ZXjTv86oBCbnqThDnvpDE/8kp7Y8OQ6I4UO72f9HiA3NZLtiPWSg==
            -----END PUBLIC KEY-----
            """).lstrip()

        uid = 'servicea'
        data = {
            'description': 'Service A',
            'public_key': elliptic_curve_pubkey_pem_x509
        }
        url = Url('/users/%s' % uid)
        r = requests.put(url, json=data)
        assert r.status_code == 400
        assert 'must be of type RSA' in r.text

    def test_put_service_empty_pubkey(self):
        uid = 'servicea'
        data = {
            'description': 'Service A',
            'public_key': ''
        }
        url = Url('/users/%s' % uid)
        r = requests.put(url, json=data)
        assert r.status_code == 400
        assert '`public_key` must not be empty when provided' in r.text

    def test_put_service_too_many_args(self):
        uid = 'servicea'
        data = {
            'description': 'Service A',
            'password': 'ThisIsAPassword',
            'public_key': 'secret',
        }
        url = Url('/users/%s' % uid)
        r = requests.put(url, json=data)
        assert r.status_code == 400
        assert 'One of `password` or `public_key` must be provided' in r.text


@pytest.mark.usefixtures("datastore_reset")
class TestUsersCollection:

    def test_get_users_empty(self):
        r = requests.get(Url('/users'))
        assert r.status_code == 200
        assert r.json() == {'array': []}

    def test_get_users_check_content_type(self):
        r = requests.get(Url('/users'))
        assert r.headers['Content-Type'] == 'application/json; charset=utf-8'

    def test_putget_users_one_user(self):
        uid = 'usera'
        data = {
            'description': 'User A',
            'password': 'ThisIsAPassword'
            }
        url = Url('/users/%s' % uid)
        r = requests.put(url, json=data)
        assert r.status_code == 201
        r = requests.get(Url('/users'))
        assert r.status_code == 200
        d = r.json()
        assert isinstance(d['array'], list)
        assert d['array'] == [{
            'uid': uid,
            'description': 'User A',
            'url': url.rel(),
            'is_remote': False,
            'is_service': False,
            'provider_type': 'internal',
            'provider_id': '',
            }]

    def test_putget_users_two_users(self):
        uid1 = 'usera'
        data1 = {
            'description': 'User A',
            'password': 'ThisIsAPassword'
            }
        url1 = Url('/users/%s' % uid1)
        r = requests.put(url1, json=data1)
        assert r.status_code == 201
        uid2 = 'userb'
        data2 = {
            'description': 'User B',
            'password': 'ThisIsPassword2'
            }
        url2 = Url('/users/%s' % uid2)
        r = requests.put(url2, json=data2)
        assert r.status_code == 201
        r = requests.get(Url('/users'))
        assert r.status_code == 200
        d = r.json()
        assert isinstance(d['array'], list)
        correct = sorted([{
            'uid': uid1,
            'description': 'User A',
            'url': url1.rel(),
            'is_remote': False,
            'is_service': False,
            'provider_type': 'internal',
            'provider_id': '',
        }, {
            'uid': uid2,
            'description': 'User B',
            'url': url2.rel(),
            'is_remote': False,
            'is_service': False,
            'provider_type': 'internal',
            'provider_id': '',
        }], key=lambda x: x['uid'])
        assert correct == sorted(d['array'], key=lambda x: x['uid'])

    def test_putget_one_service_public_key(self):
        uid = 'servicea'
        data = {
            'description': 'Service A',
            'public_key': default_rsa_pubkey
            }
        url = Url('/users/%s' % uid)
        r = requests.put(url, json=data)
        assert r.status_code == 201
        r = requests.get(Url('/users/%s' % uid))
        assert r.status_code == 200
        d = r.json()
        assert d == {
            'uid': uid,
            'description': 'Service A',
            'url': url.rel(),
            'is_remote': False,
            'is_service': True,
            'provider_type': 'internal',
            'provider_id': '',
            'public_key': default_rsa_pubkey
            }


class TestUsersBaseUndecorated:
    """This is the base for mid-complex testing of user endpoints.

    Create users in the setup method.
    """
    # Make URL class changable by subclasses.
    urlclass = Url

    def setup(self):
        # Create two users.
        self.user1_uid = 'usera'
        self.user1_description = 'User A'
        self.user1_password = 'ThisIsAPassword'
        self.user1_url = self.urlclass('/users/%s' % self.user1_uid)
        r = requests.put(
            self.user1_url,
            json={
                'description': self.user1_description,
                'password': self.user1_password
                }
            )
        assert r.status_code == 201, r.json()
        self.user2_uid = 'userb'
        self.user2_description = 'User B'
        self.user2_password = 'ThisIsAnotherassword'
        self.user2_url = self.urlclass('/users/%s' % self.user2_uid)
        r = requests.put(
            self.user2_url,
            json={
                'description': self.user2_description,
                'password': self.user2_password
                }
            )
        assert r.status_code == 201

        # Create two services.
        self.service1_uid = 'servicea'
        self.service1_description = 'Service A'
        self.service1_private_key = default_rsa_privkey
        self.service1_public_key = default_rsa_pubkey
        self.service1_url = self.urlclass('/users/%s' % self.service1_uid)
        r = requests.put(
            self.service1_url,
            json={
                'description': self.service1_description,
                'public_key': self.service1_public_key
                }
            )
        assert r.status_code == 201

        self.service2_uid = 'serviceb'
        self.service2_description = 'Service B'
        self.service2_private_key = default_rsa_privkey
        self.service2_public_key = default_rsa_pubkey
        self.service2_url = self.urlclass('/users/%s' % self.service2_uid)
        r = requests.put(
            self.service2_url,
            json={
                'description': self.service2_description,
                'public_key': self.service2_public_key
                }
            )
        assert r.status_code == 201

    def teardown(self):
        pass


@pytest.mark.usefixtures("datastore_reset")
class TestUsersBase(TestUsersBaseUndecorated):
    pass


class TestServiceCollection(TestUsersBase):

    def test_wo_servicefilter(self):
        r = requests.get(Url('/users'))
        assert r.status_code == 200
        # Expect two users, no service.
        users = r.json()['array']
        assert len(users) == 2
        uids = [d['uid'] for d in users]
        assert self.user1_uid in uids
        assert self.user2_uid in uids

    def test_with_servicefilter(self):
        r = requests.get(Url('/users?type=service'))
        assert r.status_code == 200
        # Expect one service, no users.
        services = r.json()['array']
        assert len(services) == 2
        uids = [d['uid'] for d in services]
        assert self.service1_uid in uids
        assert self.service2_uid in uids


class TestUserLogin(TestUsersBase):

    def test_login_user(self):
        url = Url('/auth/login')
        credentials = {
            'uid': self.user1_uid,
            'password': self.user1_password
            }
        r = requests.post(url, json=credentials)
        assert r.status_code == 200
        d = r.json()
        assert 'token' in d

    def test_login_invalid_password(self):
        url = Url('/auth/login')
        credentials = {
            'uid': self.user1_uid,
            'password': 'wrongpassword'
            }
        r = requests.post(url, json=credentials)
        assert r.status_code == 401
        d = r.json()
        assert d['code'] == 'ERR_INVALID_CREDENTIALS'
        assert r.headers['WWW-Authenticate'] == 'acsjwt'

    def test_login_invalid_uid(self):
        url = Url('/auth/login')
        credentials = {
            'uid': 'wronguid',
            'password': 'wrongpassword'
            }
        r = requests.post(url, json=credentials)
        assert r.status_code == 401
        d = r.json()
        assert d['code'] == 'ERR_INVALID_CREDENTIALS'
        assert r.headers['WWW-Authenticate'] == 'acsjwt'

    def test_login_no_password_nor_token(self):
        url = Url('/auth/login')
        credentials = {
            'uid': self.user1_uid
            }
        r = requests.post(url, json=credentials)
        assert r.status_code == 400

    def test_login_after_password_change(self):
        # Change password.
        data = {'password': 'new-password'}
        r = requests.patch(self.user1_url, json=data)
        assert r.status_code == 204
        # Attempt auth.
        url = Url('/auth/login')
        credentials = {
            'uid': self.user1_uid,
            'password': 'new-password'
            }
        r = requests.post(url, json=credentials)
        assert r.status_code == 200
        d = r.json()
        assert 'token' in d

    def test_authtoken_rs256_anatomy(self):
        url = Url('/auth/login')
        credentials = {
            'uid': self.user1_uid,
            'password': self.user1_password
            }
        r = requests.post(url, json=credentials)
        assert r.status_code == 200
        token = r.json()['token']

        header_bytes, payload_bytes, signature_bytes = [
            base64url_decode(_.encode('ascii')) for _ in token.split(".")]

        # Make sure the header is valid JSON.
        header_dict = json.loads(header_bytes.decode('ascii'))

        assert header_dict['typ'] == "JWT"
        assert header_dict['alg'] == "RS256"

        # Make sure that the payload section is valid JSON.
        payload_dict = json.loads(payload_bytes.decode('ascii'))
        return token, payload_dict

    def test_authtoken_payload_anatomy(self):
        # API consumers expect to see `uid` as well as `exp` in
        # the payload section of the token.
        _, payload_dict = self.test_authtoken_rs256_anatomy()

        # Check presence and value type of expiration time.
        assert 'exp' in payload_dict
        # According to RFC 7519, the type of the expiration field must be a
        # JSON numeric value. Currently, Bouncer emits an integer.
        assert isinstance(payload_dict['exp'], int)

        # Check presence and value of uid.
        assert 'uid' in payload_dict
        assert payload_dict['uid'] == self.user1_uid

    def test_authtoken_rs256_verification(self):
        # Verify that the auth token (signed by Bouncer's private key)
        # can be validated using Bouncer's public key. Obtain/construct
        # Bouncer's public key from it's JSON Web Key Set (jwks) entpoint

        # Obtain authentication token.
        token, _ = self.test_authtoken_rs256_anatomy()

        # Obtain the JSON Web Key Set.
        r = requests.get(Url('/auth/jwks'))
        keys = r.json()['keys'][0]

        # Extract the public modulus and exponent from the data.
        exponent_bytes = base64url_decode(keys['e'].encode('ascii'))
        exponent_int = bytes_to_number(exponent_bytes)

        modulus_bytes = base64url_decode(keys['n'].encode('ascii'))
        modulus_int = bytes_to_number(modulus_bytes)

        # Generate a public key instance from these numbers.
        public_numbers = rsa.RSAPublicNumbers(n=modulus_int, e=exponent_int)
        public_key = public_numbers.public_key(backend=cryptography_backend)

        # Verify token signature using that public key.
        payload = jwt.decode(token, public_key, algorithms='RS256')
        assert payload['uid'] == self.user1_uid

    def test_cookies_after_login(self):
        url = Url('/auth/login')
        credentials = {
            'uid': self.user1_uid,
            'password': self.user1_password
            }
        r = requests.post(url, json=credentials)
        token = r.json()['token']
        assert r.status_code == 200
        assert 'dcos-acs-auth-cookie' in r.cookies
        assert 'dcos-acs-info-cookie' in r.cookies

        # Validate auth cookie content.
        assert r.cookies['dcos-acs-auth-cookie'] == token

        # Validate info cookie content.
        # 'ASCII-only Unicode strings' are allowed to be decoded since
        # Python 3.3, but the result is bytes, so decode it.
        info_json = base64.b64decode(
            r.cookies['dcos-acs-info-cookie']).decode('utf-8')
        info = json.loads(info_json)
        assert info == {
            'uid': self.user1_uid,
            'description': self.user1_description,
            'is_remote': False
            }

        # Look at response headers directly, validate state of cookies, w.r.t.
        # httponly, domain, secure attributes. requests combines/inflates
        # set-cookie headers, cf. http://docs.python-
        # requests.org/en/latest/user/quickstart/#response-headers
        cookies = r.headers['set-cookie'].split(',')
        assert len(cookies) == 2
        for c in cookies:
            if 'dcos-acs-auth-cookie' in c:
                assert 'httponly' in c.lower()
                assert 'path=/' in c.lower()
                assert 'domain' not in c.lower()
                assert 'secure' not in c.lower()
            if 'dcos-acs-info-cookie' in c:
                assert 'httponly' not in c.lower()
                assert 'domain' not in c.lower()
                assert 'secure' not in c.lower()
                assert 'path=/' in c.lower()

    def test_logout(self):
        r = requests.get(Url('/auth/logout'))
        assert r.status_code == 200
        # Look at the raw header, make validation there (obviously
        # cannot use requests' cookie jar, as this cookie ideally
        # is deleted!).
        cookie = r.headers['set-cookie']
        # Make sure there is only one cookie in the header.
        # Only one comma expected, in the date string (multiple
        # cookies would be concatenated with a comma).
        assert len([char for char in cookie if char == ',']) == 1
        # Make sure this sets an empty value to dcos-acs-auth-cookie.
        assert 'dcos-acs-auth-cookie=;' in cookie or \
            'dcos-acs-auth-cookie="";' in cookie
        # Make sure this sets `expires` to a date in the past.
        # Expect date to be compliant with
        # https://tools.ietf.org/html/rfc2616#section-3.3.1
        assert 'expires=Sat, 01 Jan 2000 00:00:00 GMT' in cookie

    def test_auth_endpoint_get_missing_query_parameter(self):
        r = requests.get(Url('/auth/login'))
        assert r.status_code == 400
        assert 'Expected query parameter' in r.json()['description']


class TestServiceLogin(TestUsersBase):
    """Test service login."""

    def _test_login_fails(self, credentials):
        r = requests.post(Url('/auth/login'), json=credentials)
        assert r.status_code == 401
        d = r.json()
        assert d['code'] == 'ERR_INVALID_CREDENTIALS'
        assert r.headers['WWW-Authenticate'] == 'acsjwt'

    def test_password_login_fails(self):
        credentials = {
            'uid': self.service1_uid,
            'password': 'somepassword'
            }
        self._test_login_fails(credentials)

    def test_unknown_service(self):
        credentials = {
            'uid': 'unknown',
            'token': 'abc'
            }
        self._test_login_fails(credentials)

    def test_privkey_login_succeeds(self):
        credentials = {
            'uid': self.service1_uid,
            'token': jwt.encode(
                {
                    'exp': int(time.time() + 5 * 60),
                    'uid': self.service1_uid
                },
                self.service1_private_key,
                algorithm='RS256')
            .decode('ascii')
            }
        r = requests.post(Url('/auth/login'), json=credentials)
        assert r.status_code == 200
        return r.json()['token']

    def test_logintoken_missing_claims(self):
        credentials = {
            'uid': self.service1_uid,
            'token': jwt.encode(
                {
                    'invalid': 'payload'
                },
                self.service1_private_key,
                algorithm='RS256')
            .decode('ascii')
            }
        self._test_login_fails(credentials)

    def test_logintoken_missing_uid_claim(self):
        # Make the service login token miss the uid payload key.
        credentials = {
            'uid': self.service1_uid,
            'token': jwt.encode(
                {
                    'exp': int(time.time() + 5 * 60)
                },
                self.service1_private_key,
                algorithm='RS256')
            .decode('ascii')
            }
        self._test_login_fails(credentials)

    def test_logintoken_expired(self):
        credentials = {
            'uid': self.service1_uid,
            'token': jwt.encode(
                {
                    'uid': self.service1_uid,
                    'exp': int(time.time() - 5 * 60)
                },
                self.service1_private_key,
                algorithm='RS256')
            .decode('ascii')
            }
        self._test_login_fails(credentials)

    def test_logintoken_invalid_uid_claim(self):
        credentials = {
            'uid': self.service1_uid,
            'token': jwt.encode(
                {
                    'exp': int(time.time() + 5 * 60),
                    'uid': self.service1_uid + 'invalid'
                },
                self.service1_private_key,
                algorithm='RS256')
            .decode('ascii')
            }
        self._test_login_fails(credentials)

    def test_logintoken_additional_claims(self):
        credentials = {
            'uid': self.service1_uid,
            'token': jwt.encode(
                {
                    'exp': int(time.time() + 5 * 60),
                    'uid': self.service1_uid,
                    'additional': 'claim'
                },
                self.service1_private_key,
                algorithm='RS256')
            .decode('ascii')
            }
        r = requests.post(Url('/auth/login'), json=credentials)
        assert r.status_code == 200
        assert 'token' in r.json()

    def test_logintoken_corrupt_base64payload(self):
        # Should create an 'Invalid payload padding' error message in
        # Bouncer's log.
        credentials = {
            'uid': self.service1_uid,
            'token': jwt.encode(
                {},
                self.service1_private_key,
                algorithm='RS256')
            .decode('ascii')
            }
        # Inject invalid base64 payload
        parts = credentials['token'].split('.')
        corrupt_token = ".".join((parts[0], '0', parts[2]))
        credentials['token'] = corrupt_token
        self._test_login_fails(credentials)

    def test_logintoken_unexpected_algo(self):
        credentials = {
            'uid': self.service1_uid,
            'token': jwt.encode(
                {
                    'exp': int(time.time() + 5 * 60),
                    'uid': self.service1_uid,
                },
                self.service1_private_key,
                algorithm='HS256')
            .decode('ascii')
            }
        self._test_login_fails(credentials)

    def test_logintoken_20min_exp(self):
        # Should create a warning in Bouncer's log:
        # 'WARNING: long-lived service login token (> 10 minutes)''
        credentials = {
            'uid': self.service1_uid,
            'token': jwt.encode(
                {
                    'exp': int(time.time() + 20 * 60),
                    'uid': self.service1_uid,
                },
                self.service1_private_key,
                algorithm='RS256')
            .decode('ascii')
            }
        r = requests.post(Url('/auth/login'), json=credentials)
        assert r.status_code == 200
        assert 'token' in r.json()

    def test_authtoken_rs256_anatomy(self):
        token = self.test_privkey_login_succeeds()

        header_bytes, payload_bytes, signature_bytes = [
            base64url_decode(_.encode('ascii')) for _ in token.split(".")]

        assert b'typ' in header_bytes
        header_dict = json.loads(header_bytes.decode('ascii'))

        assert header_dict['alg'] == "RS256"
        assert header_dict['typ'] == "JWT"
        payload_dict = json.loads(payload_bytes.decode('ascii'))

        assert 'exp' in payload_dict
        assert 'uid' in payload_dict
        assert payload_dict['uid'] == self.service1_uid

    def test_request_authtoken_with_custom_expiration(self):
        # Include the `exp` key in the `data` dictionary, with a non-zero
        # integer value. Note(JP): this is a private DC/OS interface introduced
        # as a workaround for the problem of reliable authentication token
        # refresh. It must never be publicly documented, and should be removed
        # in a future version, together with this test.
        url = Url('/auth/login')
        data = {
            'uid': self.service1_uid,
            'exp': 84600,
            'token': jwt.encode(
                {
                    'exp': int(time.time() + 5 * 60),
                    'uid': self.service1_uid
                },
                self.service1_private_key,
                algorithm='RS256')
            .decode('ascii')
            }
        r = requests.post(url, json=data)
        assert r.status_code == 200
        token = r.json()['token']
        _, payload_bytes, _ = [
            base64url_decode(_.encode('ascii')) for _ in token.split(".")]
        payload_dict = json.loads(payload_bytes.decode('ascii'))
        assert payload_dict['exp'] == 84600

    def test_request_authtoken_without_expiration(self):
        # Include the `exp` key in the `data` dictionary, with the value 0.
        # Note(JP): this is a private DC/OS interface introduced as a workaround
        # for the problem of reliable authentication token refresh. It must
        # never be publicly documented, and should be removed in a future
        # version.
        login_token = jwt.encode(
            {'exp': int(time.time() + 5 * 60), 'uid': self.service1_uid},
            self.service1_private_key,
            algorithm='RS256').decode('ascii')

        r = requests.post(
            url=Url('/auth/login'),
            json={'exp': 0, 'uid': self.service1_uid, 'token': login_token}
            )
        assert r.status_code == 200
        token = r.json()['token']
        _, payload_bytes, _ = [
            base64url_decode(_.encode('ascii')) for _ in token.split(".")]
        payload_dict = json.loads(payload_bytes.decode('ascii'))
        assert 'exp' not in payload_dict


class TestUserItem(TestUsersBase):

    def test_put_user_invalid_json_schema_1(self):
        uid = 'userx'
        data = {
            'description': 'User X',
            'password': 'ThisIsAPassword',
            'someprop': 'someval'
            }
        url = Url('/users/%s' % uid)
        r = requests.put(url, json=data)
        assert r.status_code == 400
        assert 'Unexpected JSON input' in r.text
        m = ('Additional properties are not allowed (\'someprop\' was'
             ' unexpected)')
        assert m in r.text

    def test_put_user_invalid_password_properties(self):
        uid = 'userx'
        data = {
            'description': 'User X',
            'password': '1234',
            }
        url = Url('/users/%s' % uid)
        r = requests.put(url, json=data)
        assert r.status_code == 400
        assert 'Password does not match rules' in r.text

    def test_put_user_twice(self):
        uid = 'userx'
        data = {
            'description': 'User X',
            'password': 'ThisIsAPassword'
            }
        url = Url('/users/%s' % uid)
        r = requests.put(url, json=data)
        assert r.status_code == 201
        r = requests.put(url, json=data)
        assert r.status_code == 409
        assert r.json()['code'] == 'ERR_USER_EXISTS'

    def test_put_user_invalid_id(self):
        uid = 'user!'
        data = {
            'description': 'User A',
            'password': 'ThisIsAPassword'
            }
        url = Url('/users/%s' % uid)
        r = requests.put(url, json=data)
        assert r.status_code == 400
        assert r.json()['code'] == 'ERR_INVALID_USER_ID'
        assert 'Invalid user ID' in r.text

    def test_put_invalid_public_key(self):
        # Numbers are currently not allowed.
        data = {
            'description': self.service1_description,
            'public_key': "ThisIsAnIvalidPublicKey"
            }
        r = requests.put(self.service1_url, json=data)
        assert r.status_code == 400
        assert r.json()['code'] == 'ERR_INVALID_PUBLIC_KEY'
        assert 'Invalid public key' in r.text

    def test_get_nonexisting_user(self):
        r = requests.get(Url('/users/unknownid'))
        assert r.status_code == 400
        d = r.json()
        assert d['code'] == 'ERR_UNKNOWN_USER_ID'
        assert 'User with uid `unknownid` not known' in d['description']

    def test_get_user(self):
        r = requests.get(self.user1_url)
        assert r.status_code == 200
        d = r.json()
        assert d == {
            'uid': self.user1_uid,
            'description': self.user1_description,
            'url': self.user1_url.rel(),
            'is_remote': False,
            'is_service': False,
            'provider_type': 'internal',
            'provider_id': '',
            }

    def test_patch_user_descr(self):
        # Patch description.
        data = {'description': 'new'}
        r = requests.patch(self.user1_url, json=data)
        assert r.status_code == 204
        # Validate PATCH response: empty body, no content type, as of
        # RFC 7231, saying "a message containing a payload body SHOULD
        # generate a Content-Type header".
        assert not r.text
        assert 'Content-Type' not in r.headers
        # Get user, validate new description.
        r = requests.get(self.user1_url)
        assert r.status_code == 200
        d = r.json()
        assert d == {
            'uid': self.user1_uid,
            'description': 'new',
            'url': self.user1_url.rel(),
            'is_remote': False,
            'is_service': False,
            'provider_type': 'internal',
            'provider_id': '',
            }

    def test_patch_user_password(self):
        # Patch password.
        # Do not test login in this unit test.
        data = {'password': 'new-password'}
        r = requests.patch(self.user1_url, json=data)
        assert r.status_code == 204
        # Get user, validate data.
        r = requests.get(self.user1_url)
        assert r.status_code == 200
        d = r.json()
        assert d == {
            'uid': self.user1_uid,
            'description': self.user1_description,
            'url': self.user1_url.rel(),
            'is_remote': False,
            'is_service': False,
            'provider_type': 'internal',
            'provider_id': '',
            }

    def test_patch_service_password(self):
        # Patching password of service account must fail.
        # Do not test login in this unit test.
        data = {'password': 'new-password'}
        r = requests.patch(self.service1_url, json=data)
        assert r.status_code == 400

    def test_patch_user_password_and_description(self):
        # Patch password and description
        # Do not test login in this unit test.
        data = {
            'password': 'new-password',
            'description': 'new'
            }
        r = requests.patch(self.user1_url, json=data)
        assert r.status_code == 204
        # Get user, validate data.
        r = requests.get(self.user1_url)
        assert r.status_code == 200
        d = r.json()
        assert d == {
            'uid': self.user1_uid,
            'description': 'new',
            'url': self.user1_url.rel(),
            'is_remote': False,
            'is_service': False,
            'provider_type': 'internal',
            'provider_id': '',
            }

    def test_patch_user_no_pass_no_descr(self):
        # Neither password nor description is set to
        # 'required' in the schema, because one of them is
        # sufficient. So this is caught differently.
        data = {}
        r = requests.patch(self.user1_url, json=data)
        assert r.status_code == 400
        m = 'One of `description` and `password` must be provided'
        assert m in r.text

    def test_patch_unknown_user(self):
        data = {'description': 'new'}
        r = requests.patch(Url('/users/unknownid'), json=data)
        assert r.status_code == 400
        d = r.json()
        assert d['code'] == 'ERR_UNKNOWN_USER_ID'
        assert 'User with uid `unknownid` not known' in d['description']

    def test_delete_user(self):
        # Validate that user exists.
        r = requests.get(self.user1_url)
        assert r.status_code == 200
        # Delete user.
        r = requests.delete(self.user1_url)
        assert r.status_code == 204
        # Validate DELETE response: empty body, no content type.
        assert not r.text
        assert 'Content-Type' not in r.headers
        # Validate that user does not exist anymore.
        r = requests.get(self.user1_url)
        assert r.status_code == 400
        d = r.json()
        assert d['code'] == 'ERR_UNKNOWN_USER_ID'
        assert 'User with uid `%s` not known' % self.user1_uid in d['description']

    def test_delete_unknown_user(self):
        r = requests.delete(Url('/users/unknownid'))
        assert r.status_code == 400
        d = r.json()
        assert d['code'] == 'ERR_UNKNOWN_USER_ID'
        assert 'User with uid `unknownid` not known' in d['description']


@pytest.mark.usefixtures('datastore_reset')
class TestUIConfig:

    def put_user(self):
        data = {'description': 'User A', 'password': 'ThisIsAPassword'}
        assert requests.put(Url('/users/usera'), json=data).status_code == 201

    def put_service(self):
        data = {'description': 'Svc A', 'public_key': default_rsa_pubkey}
        assert requests.put(Url('/users/svc'), json=data).status_code == 201

    def test_first_regular_user(self):
        assert requests.get(Url('/uiconfig')).json()[
            'clusterConfiguration']['firstUser'] is True
        self.put_user()
        assert requests.get(Url('/uiconfig')).json()[
            'clusterConfiguration']['firstUser'] is False

    def test_first_service_user(self):
        assert requests.get(Url('/uiconfig')).json()[
            'clusterConfiguration']['firstUser'] is True
        self.put_service()
        # A service user account is not expected to change the outcome.
        assert requests.get(Url('/uiconfig')).json()[
            'clusterConfiguration']['firstUser'] is True


class TestBootstrapWithOptionalServiceAccountSuperuser:
    """Test optional creation of a superuser svc account during DB bootstrap.

    The `wsgi_app_with_bootstrap_service_account` is a session scope fixture
    which launches an instance of Bouncer; with environment variables set that
    (in combination with TestConfigBase) instruct Bouncer to create a service
    account during database bootstrap. Multiple Bouncer instances might be
    running at the same time (each running in an independent child process, all
    managed by the test runner) and they all connect to the same database
    container. For that reason, before the tests in this class can succeed, a
    database reset (plus bootstrap) needs to be initiated before every test. Do
    that explicitly via _reset_and_bootstrap_db() instead of going through
    pytest fixture magic.
    """

    def _reset_and_bootstrap_db(self):
        """
        """
        r = requests.get(
            UrlBootstrapServiceAcc('/testing/reset-datastore?bootstrap=true'))
        assert r.status_code == 200

    def test_if_user_shows_up(self, wsgi_app_with_bootstrap_service_account):

        self._reset_and_bootstrap_db()

        uid, pubkey, privkey = wsgi_app_with_bootstrap_service_account
        url = UrlBootstrapServiceAcc('/users/%s' % uid)
        r = requests.get(url)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d == {
            'uid': uid,
            'description': 'Superuser service account defined via DC/OS config',
            'url': url.rel(),
            'is_remote': False,
            'is_service': True,
            'provider_type': 'internal',
            'provider_id': '',
            'public_key': pubkey
            }

    def test_login(self, wsgi_app_with_bootstrap_service_account):

        self._reset_and_bootstrap_db()

        uid, pubkey, privkey = wsgi_app_with_bootstrap_service_account
        credentials = {
            'uid': uid,
            'token': jwt.encode(
                {
                    'exp': int(time.time() + 60),
                    'uid': uid,
                },
                privkey,
                algorithm='RS256')
            .decode('ascii')
            }
        url = UrlBootstrapServiceAcc('/auth/login')
        r = requests.post(url, json=credentials)
        assert r.status_code == 200
        assert 'token' in r.json()
