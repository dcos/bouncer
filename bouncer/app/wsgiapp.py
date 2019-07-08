# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
Create Falcon WSGI application object, define routes, and wire them to the
various resource handlers. Expose WSGI app object.
"""


import importlib
import json
import logging
import os

import falcon

from bouncer.app import auth, config, crypt, db
from bouncer.app.models import dbsession, run_transaction

log = logging.getLogger(__name__)


log.info('Load wsgiapp module.')


class RequestMiddleware:
    """Generic middleware for app-level request validation and automatic JSON
    (de)serialization.

    Automatically manage `idata` and `odata` keys of the context dict (attribute
    of falcon.Request instance):

    `idata`: Incoming data. None, or data structure after decoding JSON request
    body. To be used in request handlers for accessing the data provided with
    the request.

    `odata`: Outgoing data. If set, this is expected to be JSON-serializable. Is
    serialized and then transmitted as response body.

    Falcon creates request and response objects for each HTTP request, and
    the `context` dictionary is meant for these purposes.
    """

    def process_request(self, req, resp):
        # Default: indicate that no incoming body data was retrieved.
        req.context['idata'] = None

        # Log the client connection
        remote_service = req.get_header('X-Sender')
        if remote_service is None:
            if req.user_agent in (
                'curl/7.65.1', 'dcos-go', 'Go-http-client/1.1', 'Master Admin Router',
                'python-requests/2.20.1'
            ):
                remote_service = req.user_agent
            else:
                log.error("Rejecting direct access by User-Agent %s", req.user_agent)
                raise falcon.HTTPBadRequest(
                    description='Bad sender', code='ERR_BAD_SENDER')
        log.info('%s:%s ->', req.remote_addr, remote_service)

        # Require that the client accepts JSON responses. This is fulfilled
        # when Accept header is missing or when it is wildcarded, or when it
        # is explicitly set to application/json. From RFC 7231: "A request
        # without any Accept header field implies that the user agent will
        # accept any media type in response."
        if not req.client_accepts_json:
            raise falcon.HTTPNotAcceptable(
                'The user agent must support application/json responses.')

        # Content-Length is not required to be set, according to RFC2616: "The
        # presence of a message-body in a request is signaled by the inclusion
        # of a Content-Length or Transfer-Encoding header field in the request's
        # message-headers" -- 0/No Content-Length header: nothing to decode and
        # no requirements regarding Content-Type request header.
        if req.content_length is None or req.content_length == 0:
            return

        # Non-empty body expected as of Content-Length: require Content-Type.
        # Note: currently Falcon does not invalidate non-PUT/POST with nonzero
        # Content-Length. These just do not have the req.stream property set.
        # TODO(jp): check validity of above comment after update to Falcon 1.0.
        if req.method in ('POST', 'PUT', 'PATCH'):
            if req.content_type is None:
                # This is difficult to reach for proper HTTP clients.
                raise falcon.HTTPBadRequest(
                    'Bad Request', 'Missing Content-Type header.')

            body = req.stream.read()
            if not body:
                raise falcon.HTTPBadRequest(
                    'Bad Request', 'Expected non-empty request body.')

            # Extract type and subtype of the Content-Type header (to make the
            # following checks invariant w.r.t. to further parameters such as
            # charset). Also account for type and subtype being case-
            # insensitive. See https://www.ietf.org/rfc/rfc1521.txt page 9.
            content_type = req.content_type.split(';', 1)[0].strip().lower()

            if content_type == 'application/json':
                return self._parse_body_json(req, body)

            if content_type == 'application/x-www-form-urlencoded':
                return self._parse_body_form(req, body)

            raise falcon.HTTPUnsupportedMediaType(
                'Unexpected or undefined Content-Type')

    def process_response(self, req, resp, resource):
        odata = req.context.get('odata', None)
        if odata is None:
            return
        # Mitigate JSON hijacking.
        # Ref: https://www.owasp.org/index.php/AJAX_Security_Cheat_Sheet
        if isinstance(odata, list):
            odata = {"array": odata}
        # Falcon docs: "If data is already a byte string,
        # use the data attribute instead (it's faster)."
        resp.data = (json.dumps(
            odata, ensure_ascii=False, indent=2) + '\n').encode('utf-8')

    def _parse_body_json(self, req, body):
        try:
            req.context['idata'] = json.loads(body.decode('utf-8'))
        except UnicodeDecodeError as e:
            raise falcon.HTTPBadRequest(
                'Bad Request',
                'Cannot decode JSON body using UTF-8. Reason: %s' % e.reason
                )
        except ValueError as e:
            raise falcon.HTTPBadRequest(
                'Bad Request', 'Cannot decode JSON body: %s' % e)

    def _parse_body_form(self, req, body):
        try:
            # From the HTML5 spec, section "To decode application/x-www-form-
            # urlencoded payloads": "Which default character encoding to use
            # can only be determined on a case-by-case basis, but generally
            # the best character encoding to use as a default is the one that
            # was used to encode the page on which the form used to create the
            # payload was itself found. In the absence of a better default,
            # UTF-8 is suggested."
            body = body.decode('utf-8')
        except UnicodeDecodeError as e:
            raise falcon.HTTPBadRequest(
                'Bad Request',
                'Cannot decode form body using UTF-8 codec'
                )
        # Falcon's uri.decode behaves like urllib.parse.unquote_plus.
        req.context['formparams'] = falcon.util.uri.parse_query_string(
            falcon.util.uri.decode(body),
            keep_blank_qs_values=False,
            )


class DatabaseResetter:
    def on_get(self, req, resp):
        do_bootstrap = True if req.get_param_as_bool('bootstrap') else False
        db.reset(do_bootstrap)


# class DatastoreReadOnlyMode:
#     # TODO(jp): this is a quick merge conflict resolution, pulling in a bit
#     # of the 1.9 Bounce read-only PR into the SQL branch.
#     def on_get(self, req, resp):
#         req.context['odata'] = ds.cur.read_only_get()

#     def on_post(self, req, resp):
#         log.info('Enabling datastore read-only mode')
#         ds.cur.read_only_enable()
#         resp.status = falcon.HTTP_NO_CONTENT

#     def on_delete(self, req, resp):
#         log.info('Disabling datastore read-only mode')
#         ds.cur.read_only_disable()
#         resp.status = falcon.HTTP_NO_CONTENT


def datastore_read_only_exception_handler(ex, req, resp, params):
    resp.body = (
        '503 Service Unavailable: the IAM is operating in read-only mode\n'
        )
    resp.status = falcon.HTTP_503
    log.info('Reject write request because datastore in read-only mode.')


def discover_and_import_app_modules():
    app_modules_dir = os.path.dirname(os.path.abspath(__file__))

    log.info('Discover Python modules in directory %s', app_modules_dir)
    module_filenames = list(sorted(
        m for m in os.listdir(app_modules_dir) if
        m.endswith('.py') and m not in ('wsgiapp.py', '__init__.py')
        ))

    log.info('Discovered module filenames: %s', module_filenames)

    imported_module_objects = []
    for filename in module_filenames:
        # Build absolute module path.
        modname = 'bouncer.app.%s' % (filename[:-3])
        log.info('Importing %s', modname)
        module_object = importlib.import_module(modname)
        log.info('Imported %s (%s)', modname, module_object)
        imported_module_objects.append(module_object)

    return imported_module_objects


class SQLAlchemySessionMiddleware:

    def process_response(self, req, resp, resource, req_succeeded):
        """Close SQLAlchemy session.

        This here is called after application-relevant business logic (after
        an HTTP response has been generated by the application).

        From the SQLAlchemy docs:

            "The scoped_session.remove() method first calls Session.close() on
            the current Session, which has the effect of releasing any
            connection/transactional resources owned by the Session first, then
            discarding the Session itself. “Releasing” here means that
            connections are returned to their connection pool and any
            transactional state is rolled back, ultimately using the rollback()
            method of the underlying DBAPI connection."

        Rely on the fact that `dbsession` is a proxy object yielding the session
        that has been used while handling the current HTTP request.
        """
        log.debug('SQLAlchemy session remove()')
        dbsession.remove()


# Get private key (to be used for signing authentication tokens) as native
# object from the `cryptography` module. Read it from file or, if that is not
# yet set, achieve consensus over potentially multiple Bouncer instances through
# the database (write the consensus result to disk).
crypt.read_private_key_from_file_or_generate_through_database(
    config['SECRET_KEY_FILE_PATH']
    )


route_callable_mapping = {}

# Add routes only relevant in TESTING mode.
if config['TESTING']:
    route_callable_mapping.update({
        '/testing/reset-datastore': DatabaseResetter,
        # '/testing/read-only': DatastoreReadOnlyMode,
        # '/testing/load': DatastoreLoader,
        # '/testing/dump': DatastoreDumper
        })

# Dynamically discover app modules, import them, and
# call their entrypoints for dynamic global state modification:
# - get route handlers, register them
# - call extension handlers
# - get 'login provider item' builder function
# - get module-specific middlewares
module_middlewares = []
imported_module_objects = discover_and_import_app_modules()
for mod in imported_module_objects:

    if hasattr(mod, 'get_module_route_handlers'):
        log.info('Get route handlers for module %s', mod)
        for route, handler in mod.get_module_route_handlers().items():
            if route in route_callable_mapping:
                raise Exception(
                    'Handler for route `%s` already installed: %s' % (
                        route, handler))
            route_callable_mapping[route] = handler

    # What follows requires the auth module to be in the namespace, which is
    # why it is _explicitly_ imported in the file header.
    if hasattr(mod, 'extend_login_class'):
        log.info('Call Login class extender for module %s', mod)
        mod.extend_login_class(auth.Login)

    if hasattr(mod, 'get_login_provider_items_from_database_cfgitems'):
        builder = mod.get_login_provider_items_from_database_cfgitems
        log.info(
            'Register login provider item builder for module %s: %s',
            mod, builder
            )
        auth.login_provider_item_builders.append(builder)

    if hasattr(mod, 'get_module_middlewares'):
        for mw in mod.get_module_middlewares():
            module_middlewares.append(mw)


app_middlewares = [
    RequestMiddleware(),
    SQLAlchemySessionMiddleware(),
]
app_middlewares.extend(module_middlewares)

log.info('Initialize Falcon WSGI application object.')
# Set default media type, used as value for the Content-Type
# header in responses.
wsgiapp = falcon.API(
    media_type='application/json; charset=utf-8',
    middleware=app_middlewares
    )


# Let Falcon not automatically consume the request body stream,
# and decode form data. Do this manually, in the corresponding
# request handlers.
wsgiapp.req_options.auto_parse_form_urlencoded = False


# TODO(jp): make sure that URLPREFIX is documented to be required to start
# with a slash, and not to end with a slash.
assert config['URLPREFIX'].startswith('/')
assert not config['URLPREFIX'].endswith('/')


class RetryTransactions:
    """Retry Falcon responders that raise retryable database exceptions."""

    def __init__(self, resource):
        self.resource = resource

    def on_get(self, req, resp, **params):
        def wrapped_responder():
            return self.resource.on_get(req, resp, **params)
        return run_transaction(wrapped_responder)

    def on_put(self, req, resp, **params):
        def wrapped_responder():
            return self.resource.on_put(req, resp, **params)
        return run_transaction(wrapped_responder)

    def on_post(self, req, resp, **params):
        def wrapped_responder():
            return self.resource.on_post(req, resp, **params)
        return run_transaction(wrapped_responder)

    def on_patch(self, req, resp, **params):
        def wrapped_responder():
            return self.resource.on_patch(req, resp, **params)
        return run_transaction(wrapped_responder)

    def on_delete(self, req, resp, **params):
        def wrapped_responder():
            return self.resource.on_delete(req, resp, **params)
        return run_transaction(wrapped_responder)


route_resource_mapping = {}
for route_suffix, resource_class in route_callable_mapping.items():

    if config['SQLALCHEMY_DB_URL'].startswith('cockroachdb://'):
        resource = RetryTransactions(resource_class())
    else:
        resource = resource_class()

    # Store mapping for inspection and lookup from within tests.
    # Todo(JP): use a Falcon-native way if there is one.
    route_resource_mapping[route_suffix] = resource
    wsgiapp.add_route(
        uri_template='%s%s' % (config['URLPREFIX'], route_suffix),
        resource=resource
        )


log.info('Falcon routes are set up')
