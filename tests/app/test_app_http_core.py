# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
End-to-end tests for the HTTP API, using requests as HTTP client.
"""


import urllib
import yaml

import pytest
import requests

from tests.misc import Url

# Apply markers and fixtures to *all* tests in this module.
# From pytest docs:
# "Note that the assigned variable must be called pytestmark"
# Assigning a list is not well-documented, found that here:
# https://github.com/pytest-dev/pytest/issues/816#issuecomment-119545763
pytestmark = [pytest.mark.app, pytest.mark.usefixtures("wsgi_app")]


class TestMiddlewareHeaderValidation:

    def test_get_blank_accept_header(self):
        # From RFC 7231: A request without any Accept header field implies
        # that the user agent will accept any media type in response.
        url = Url('/users')
        # The requests module sends a couple of header fields
        # by default, such as Accept: */* -- urllib.request is more raw.
        # Do not send any Accept header here.
        req = urllib.request.Request(str(url), headers={})
        resp = urllib.request.urlopen(req)
        assert resp.status == 200

    def test_get_valid_but_unexpected_accept_header(self):
        url = Url('/users')
        req = urllib.request.Request(
            str(url), headers={'Accept': 'text/html'})
        try:
            urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            # We require application/json, so expect 406 Not Acceptable
            assert e.code == 406

    def test_get_json_accept_header(self):
        url = Url('/users')
        req = urllib.request.Request(
            str(url), headers={'Accept': 'application/json'})
        resp = urllib.request.urlopen(req)
        assert resp.status == 200

    def test_put_unknown_content_type(self):
        url = Url('/users')
        req = urllib.request.Request(
            str(url),
            headers={'Content-Type': 'application/whatsthat'},
            method='PUT',
            data=b'x'
            )
        try:
            urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            # Expect 415 Unsupported Media Type.
            assert e.code == 415
            msg = b'Unexpected or undefined Content-Type'
            assert msg in e.read()

    def test_put_json_endpoint_content_type_formurlencoded(self):
        # For PUT and POST requests, the x-www-form-urlencoded content type is
        # the default in cURL as well as in urllib. Set it here explicitly,
        # against an endpoint that expects JSON data. The resulting error is
        # what people see when they forget to specify the application/json
        # content type header.
        url = Url('/users/rolf')
        req = urllib.request.Request(
            str(url),
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            method='PUT',
            data=b'x'
            )
        try:
            urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            assert e.code == 400
            msg = b'Request has bad Content-Type or lacks JSON data'
            assert msg in e.read()

    def test_put_content_type_json_plus_charset_def(self):
        url = Url('/users')
        req = urllib.request.Request(
            str(url),
            headers={'Content-Type': 'application/json; charset=utf-8'},
            method='PUT',
            data=b'x'
            )
        try:
            urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            # Expect 400 indicating invalid JSON data, rather than 415
            # Unsupported Media Type.
            assert e.code == 400
            assert b'Cannot decode JSON body' in e.read()

    def test_get_nonzero_content_length(self):
        url = Url('/users')
        # Send a GET request containing a body (urllib allows doing that).
        req = urllib.request.Request(
            str(url),
            headers={'Content-Length': '1'},
            method='GET',
            data=b'x'
            )
        try:
            urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            assert e.code == 400
            assert b'Cannot decode JSON body' in e.read()


class TestMiddlewareJSONProcessing:

    def test_nondecodable_utf8(self):
        url = Url('/users')
        nondecodable_bytes = b'\x01\x80'
        req = urllib.request.Request(
            str(url),
            headers={'Content-Type': 'application/json'},
            data=nondecodable_bytes
            )
        try:
            urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            assert e.code == 400
            body = e.read().decode('utf-8')
            assert 'Cannot decode JSON body using UTF-8' in body
            assert 'Reason' in body

    def test_nondecodable_json(self):
        url = Url('/users')
        invalid_json_bytes = 'This is not JSON!'.encode('utf-8')
        req = urllib.request.Request(
            str(url),
            headers={'Content-Type': 'application/json'},
            data=invalid_json_bytes
            )
        try:
            urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            assert e.code == 400
            body = e.read().decode('utf-8')
            assert 'Cannot decode JSON body' in body


class TestJSONSchemavalidator:
    """The Schema invalidation part of the validator implemented by the
    function `utils.gen_jsonvalidator(schema)` is implicitly tested by other
    tests. Here, test only special error cases.
    """

    def test_missing_body(self):
        uid1 = 'usera'
        url1 = Url('/users/%s' % uid1)
        r = requests.put(url1)
        assert r.status_code == 400
        assert 'Request has bad Content-Type or lacks JSON data' in r.text


class TestOpenAPIspec:

    def test_yaml_spec_is_served(self):
        r = requests.get(Url('/internal/openapispec.yaml'))
        r.raise_for_status()
        assert r.headers['Content-Type'] == 'application/x-yaml; charset=utf-8'
        yaml_bytes = r.content
        # Confirm that a byte sequence of non-zero length was served.
        assert yaml_bytes
        # Confirm that the byte sequences can be decoded using UTF-8, and that
        # the resulting text is a serialized YAML document.
        yaml.safe_load(yaml_bytes.decode('utf-8'))
