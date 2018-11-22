# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""Implement handlers for /internal* endpoints."""


from bouncer.app import http_openapi_spec_utf8


def get_module_route_handlers():
    return {
        '/internal/openapispec.yaml': OpenAPISpecYAML
        }


class OpenAPISpecYAML:

    def on_get(self, req, resp):
        resp.content_type = 'application/x-yaml; charset=utf-8'
        resp.data = http_openapi_spec_utf8
