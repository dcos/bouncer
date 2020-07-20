# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""Implement /auth endpoints."""


import base64
import json
import logging
import os
import re
import string
import time
from collections import namedtuple
from datetime import datetime

import falcon
import falcon.uri
import jwt
import sqlalchemy

from bouncer.app import config, crypt, utils, oidcidtokenlogin
from bouncer.app.models import User, ProviderType, UserType, ConfigItem, dbsession
from bouncer.app.utils import SecurityEventAuditLogEntry
from bouncer.exceptions import BouncerException
import bouncer.app.exceptions
import bouncer.logutil


log = logging.getLogger('bouncer.app.auth')


# To be dynamically extended during application startup, in wsgiapp.py.
login_provider_item_builders = []


def get_module_route_handlers():
    return {
        '/auth/login': Login,
        '/auth/logout': Logout,
        '/auth/jwks': Jwks,
        '/auth/providers': Providers,
        }


def get_login_provider_items_from_database_cfgitems(_):
    """Return information for default login providers; present in all cluster
    configurations.
    """

    return {
        "dcos-users": {
            "authentication-type": "dcos-uid-password",
            "description": "Default DC/OS login provider",
            "client-method": "dcos-usercredential-post-receive-authtoken",
            "config": {
                "start_flow_url": "/acs/api/v1/auth/login"
                }
            },
        "dcos-services": {
            "authentication-type": "dcos-uid-servicekey",
            "description": "Default DC/OS login provider",
            "client-method": "dcos-servicecredential-post-receive-authtoken",
            "config": {
                "start_flow_url": "/acs/api/v1/auth/login"
                }
            }
        }


def get_all_login_providers():
    """
    Construct a dictionary containing all currently configured login providers,
    including those from dynamically loaded modules.

    Each item in the dictionary corresponds to one provider, and the key is the
    provider ID.

    This is public information, exposed through the /auth/providers endpoint.
    """
    login_providers = dict()
    with bouncer.logutil.temporary_log_level('sqlalchemy.engine', logging.INFO):
        # sqlalchemy logs read content at DEBUG level, revealing sensitive content
        configitems = ConfigItem.get_all()

    for builder in login_provider_item_builders:
        items = builder(configitems)
        login_providers.update(items)

    return login_providers


class Providers:
    """Falcon resource providing endpoint enumerating authentication providers
    enabled on current cluster."""

    def __init__(self):
        self.log = logging.getLogger(
            'bouncer.app.auth.' + self.__class__.__name__)

    def on_get(self, req, resp):
        req.context['odata'] = get_all_login_providers()


class Jwks():
    """Falcon resource providing the RFC 7517/7518 JWKS endpoint."""

    def __init__(self):
        self.log = logging.getLogger(
            'bouncer.app.auth.' + self.__class__.__name__)
        if config['AUTH_TOKEN_SIGNATURE_ALGORITHM'] == 'RS256':
            self._jwks = crypt.gen_jwks()
        else:
            self._jwks = None

    def on_get(self, req, resp):
        # Going forward, it is assumed that a JWKS endpoint is always there,
        # i.e. that the underlying concept is based on asymmetric cryptography
        # where public key material is exposed to other authenticators.
        req.context['odata'] = self._jwks


class Logout:

    def on_get(self, req, resp):
        """Instruct the user agent to overwrite the auth cookie value
        with an empty value, and to throw away the cookie, by setting
        an `expires` date in the past.

        Use `False` as Falcon cookie domain arg. This makes the domain key not
        appear in the cookie. From RFC 6265, section 4.1.2.3: "If the server
        omits the Domain attribute, the user agent will return the cookie only
        to the origin server.

        Refs:
            https://tools.ietf.org/html/rfc6265 section 4.1.2
            http://stackoverflow.com/a/5285982/145400
        """
        resp.set_cookie(
            name="dcos-acs-auth-cookie",
            value="",
            expires=datetime(year=2000, month=1, day=1),
            domain=False,
            path='/',
            http_only=True,
            secure=False
            )


LoginRequestParameters = namedtuple(
    'LoginRequestParameters',
    ['uid', 'pw', 'service_login_token', 'oidc_id_token', 'exp']
    )


class Login:

    def __init__(self):
        self.log = logging.getLogger(
            'bouncer.app.auth.' + self.__class__.__name__)

    def _raise_local_nonauth_error(self):
        raise falcon.HTTPUnauthorized(
            description='Invalid credentials.',
            code='ERR_INVALID_CREDENTIALS',
            challenges=['acsjwt']
            )

    def _validate_req_params(self, req, resp):
        """Perform parameter validation that cannot be covered by JSON schema
        validator.

        Returns:
            LoginRequestParameters (namedtuple) instance
        """
        uid = req.context['idata'].get('uid', None)
        password = req.context['idata'].get('password', None)
        token = req.context['idata'].get('token', None)

        # `exp` is undocumented, legacy. TODO(JP): remove this functionality,
        # also see `crypt` module.
        exp = req.context['idata'].get('exp', None)

        if len([_ for _ in (password, token) if _ is not None]) != 1:
            raise falcon.HTTPBadRequest(
                description=(
                    'Exactly one of `token` and `password` must be '
                    'provided in the request body'
                ))

        if password is not None and uid is None:
            raise falcon.HTTPBadRequest(
                description='`uid` missing in the request body')

        if password == '' or uid == '':
            raise falcon.HTTPBadRequest(
                description='`uid` and `password` must not be empty strings')

        # Distinguish between "service login token" (uid given) and OIDC ID
        # token (no uid given). Note(JP): this distinction is far from explicit
        # but it must be supported for now.
        oidc_id_token = None
        service_login_token = None
        if token:
            if uid is None:
                # Expect `token` to be an OIDC ID token.
                oidc_id_token = token
            else:
                # Expect `token` to be a service login token.
                service_login_token = token

        return LoginRequestParameters(
            uid, password, service_login_token, oidc_id_token, exp)

    def _login_local_regular_user(self, req, resp, user, login_params):
        pw_hashed = user.passwordhash
        self.log.debug('User login: Validate password.')

        if not crypt.verify_password(login_params.pw, pw_hashed):
            self.log.info(str(SecurityEventAuditLogEntry(req, {
                'action': 'password-login',
                'result': 'deny',
                'reason': 'invalid password provided',
                'uid': login_params.uid,
                })))
            self._raise_local_nonauth_error()

        authtoken = crypt.generate_auth_token(login_params.uid)
        generate_authtoken_json_response(
            authtoken,
            req,
            resp,
            login_params.uid,
            user.description
            )

    def _login_service(self, req, resp, user, login_params):

        self.log.debug('Service login token: `%s`', login_params.service_login_token)

        service_pubkey = user.pubkey
        self.log.info(
            "Service login: validate service login JWT using "
            "the service's public key"
            )
        try:
            payload = jwt.decode(
                jwt=login_params.service_login_token,
                key=service_pubkey,
                algorithms='RS256'
                )
        except (jwt.InvalidTokenError, ValueError) as e:
            self.log.info(
                'Service login for `%s`: invalid token `%s`: %s',
                login_params.uid, login_params.service_login_token, e
                )
            self._raise_local_nonauth_error()

        if 'uid' not in payload:
            self.log.info('Service login: token misses `uid` claim')
            self._raise_local_nonauth_error()

        if payload['uid'] != login_params.uid:
            self.log.info('Service login: `uid` claim mismatch')
            self._raise_local_nonauth_error()

        # Emit warning log messages about insecurely constructed login tokens.
        if 'exp' not in payload:
            self.log.warning(
                'long-lived service login token (no exp claim) for uid `%s`',
                login_params.uid)

        elif payload['exp'] > time.time() + 600:
            self.log.warning(
                'long-lived service login token (> 10 minutes) for uid `%s`',
                login_params.uid)

        # In the special case of 'service user accounts', interpret `exp`
        # parameter (token expiration time) from request, if given (this is a
        # private interface, must not be used by relying parties. See crypt.py
        # for more commentary.
        authtoken = crypt.generate_auth_token(
            login_params.uid, login_params.exp)

        generate_authtoken_json_response(
            authtoken,
            req,
            resp,
            login_params.uid,
            user.description
            )

    def _oidc_id_token_login(self, req, resp, oidc_id_token):

        # Hand off the ID Token validation business logic to the
        # `oidcidtokenlogin` module.
        issuer, email = oidcidtokenlogin.verify_id_token_or_terminate(
            req, resp, oidc_id_token)

        uid = sanitize_remote_uid(email)

        regular_user_count = dbsession.query(User).filter_by(
            utype=UserType.regular).count()

        if regular_user_count == 0:

            log.info('There is no regular user account yet. Create one.')

            # Add user to database. Rely on that we have just checked that no
            # user is there, i.e. a conflict is unexpected. Technically, there
            # is race condition and if a separate party was faster adding the
            # same user, `import_remote_user()` below could raise
            # `bouncer.app.exceptions.EntityExists`. In practice, that requires
            # the same user to log in multiple times via the external login
            # method on a sub-second timescale through different Bouncer
            # instances. Leave this unhandled (one request will succeed, the
            # others will see a 500 Internal Server Error response). Store
            # issuer as provider_id so that we keep record of which identity
            # provider precisely emitted the data.
            user = import_remote_user(
                uid=uid,
                description=email,
                provider_type=ProviderType.oidc,
                provider_id=issuer
            )

        else:
            try:
                user = User.get(uid)
            except bouncer.app.exceptions.EntityNotFound:
                log.info(
                    "I know %s user(s), but `%s` ain't one of them. Emit 401.",
                    regular_user_count,
                    uid
                )
                # Note(JP): 403 is more appropriate because this is effectively
                # our coarse-grained authorization mechanism hitting in, but 401
                # I think should be maintained for legacy reasons.
                raise falcon.HTTPUnauthorized(
                    description='ID Token login failed: user unknown',
                )

            # Make sure that provider ID and type are matching. That is if a
            # user is known in the database with the same uid as presented by
            # the current ID Token but stemming from a different provider type
            # or from a different issuer than recorded in the database then
            # reject the login request.
            if user.provider_type != ProviderType.oidc:
                raise falcon.HTTPUnauthorized(
                    description='ID Token login failed: provider type mismatch',
                )
            if user.provider_id != issuer:
                raise falcon.HTTPUnauthorized(
                    description='ID Token login failed: provider ID mismatch',
                )

        generate_authtoken_json_response(
            crypt.generate_auth_token(user.uid),
            req,
            resp,
            user.uid,
            user.description
        )

    @falcon.before(utils.gen_jsonvalidator('LoginObject'))
    def on_post(self, req, resp):
        """Authenticate against cluster-local user DB or against
        directory back-end (via LDAP, if configured).

        Create internal representation for remote user if it does not yet
        exist.

        This auto-populate concept is also used in:

            - http://www.roundup-tracker.org/cgi-bin/moin.cgi/LDAPLogin2
            - https://pythonhosted.org/django-auth-ldap/users.html

        Treat different combinations of local/remote user/service account
        and error out early.
        """
        login_params = self._validate_req_params(req, resp)

        if login_params.uid is None:

            # Rely on login_params.oidc_id_token to be set (that's a guarantee
            # `_validate_req_params()` has to give. It means initiation of an
            # OIDC ID token-based login (legacy for (open) DC/OS).
            assert login_params.oidc_id_token

            self._oidc_id_token_login(req, resp, login_params.oidc_id_token)

            # Make it explicit that the request handling must terminate here.
            return

        self.log.info('Trigger login procedure for uid `%s`', login_params.uid)

        try:
            user = User.get(login_params.uid)
        except bouncer.app.exceptions.EntityNotFound:
            if login_params.service_login_token is not None:
                # Do not fall back to an external username/password login system
                # for an attempted service account login.
                self._raise_local_nonauth_error()
            try:
                self._unknown_user_external_login_fallback(req, resp, login_params)
            except AttributeError:
                # The `uid` is not known, and an AttributeError means that there
                # is no login fallback to an external system. Emit a 401
                # response. Note(JP): a cleaner plugin interface between this
                # auth module and and an external username/password login system
                # is required.
                self._raise_local_nonauth_error()
            # Terminate request processing after external username/password
            # login system fallback.
            return

        # Prepare expressive booleans to mitigate logic bugs.
        is_service = user.utype is UserType.service
        is_remote = user.is_remote
        local_regular_user = not is_service and not is_remote
        remote_user = not is_service and is_remote

        if is_service and login_params.service_login_token is None:
            # We know for a fact that this is a service user account, but the
            # request did not send a service login token along. Treat as bad
            # credentials.
            self._raise_local_nonauth_error()

        if remote_user:
            # POSTing credentials to the login endpoint plus known regular user
            # with `is_remote` set means: delegate the login to the external
            # login system.
            self.log.info(
                'User login: uid `%s` refers to a known remote user.',
                login_params.uid)
            self._external_login_user(req, resp, user, login_params)
            return

        elif local_regular_user:
            # Regular user account login.
            self.log.info(
                'User login: uid `%s` refers to a known local user.',
                login_params.uid)
            self._login_local_regular_user(
                req, resp, user, login_params)
            return

        elif is_service:
            self.log.info(
                'Service login: uid `%s` refers to a known service account.',
                login_params.uid)
            self._login_service(req, resp, user, login_params)
            return

        raise BouncerException("Unexpected account setup")

    def on_get(self, req, resp):
        """Start a single sign-on (SSO) flow.

        As of now, the exclusive purpose of a GET request against this resource
        is to initiate an SSO flow.
        """
        oidc_provider = req.params.get('oidc-provider', None)
        saml_provider = req.params.get('saml-provider', None)
        target = req.params.get('target', None)

        if oidc_provider is None and saml_provider is None:
            d = 'Expected query parameter `oidc-provider` or `saml-provider`.'
            raise falcon.HTTPBadRequest(
                description=d, code='ERR_MISSING_QUERY_PARAMETERS')

        requested_provider_id = oidc_provider or saml_provider

        # Detect case where the requested provider is not known, and the request
        # was sent from a browser (detected based on the Accept header value).
        # In that case, redirect the user agent to the front page of the UI
        # (relative redirect to / and add a query parameter containing an error
        # message that the UI can display to the user).
        browser_request = 'text/html' in req.accept.lower()
        login_providers = get_all_login_providers()

        if browser_request and requested_provider_id not in login_providers:

            error_message = "The login provider with ID '%s' is not known" % (
                requested_provider_id, )
            error_message_url_encoded = falcon.uri.encode_value(error_message)

            # Emit 303 redirect response.
            raise falcon.HTTPSeeOther('/?iam-error=%s' % (
                error_message_url_encoded))

            # The `return` statement is not required, but explicit is better.
            return

        if oidc_provider:
            return self.__class__.openidconnect_start_flow(
                resp, oidc_provider, target)

        if saml_provider:
            return self.__class__.saml_start_flow(saml_provider, target)


def generate_authtoken_json_response(
        authtoken,
        req,
        resp,
        uid,
        description,
        is_remote=False):

    # Set dictionary for JSON response body.
    req.context['odata'] = {'token': authtoken}

    # https://tools.ietf.org/html/rfc6265 section 4.1.2
    cookie_domain = False

    # Communicate token as cookie header, for browser convenience.
    # Set path to / to ensure that a browser sends cookie on all requests.
    resp.set_cookie(
        name="dcos-acs-auth-cookie",
        value=authtoken,
        max_age=int(config['EXPIRATION_AUTH_COOKIE_DAYS'] * 86400),
        domain=cookie_domain,
        path='/',
        http_only=True,
        secure=config['AUTH_COOKIE_SECURE_FLAG']
        )

    # Also send a information cookie, for browser convenience. Make this
    # introspectable by a browser (i.e. do not set HttpOnly flag).

    # Build info dictionary, JSON-encode it and convert to bytes (using UTF-8
    # codec). Then base64-encode and convert to unicode object (required by
    # falcon as `value` to cookie).

    # After reading the value from the cookie, this operation can be
    # inverted in a browser via this line of JavaScript:
    #
    #   JSON.parse(atob('cookievalue'))
    #
    # Rationale: atob() is the inverse operation to base64.b64encode().
    # Cf. http://www.w3.org/TR/html5/webappapis.html#dom-windowbase64-btoa

    data = {
        'uid': uid,
        'description': description,
        'is_remote': is_remote
        }
    info_json_bytes = json.dumps(data).encode('ascii')
    info_json_b64encoded_unicode = base64.b64encode(
        info_json_bytes).decode('ascii')

    resp.set_cookie(
        name="dcos-acs-info-cookie",
        value=info_json_b64encoded_unicode,
        max_age=int(config['EXPIRATION_INFO_COOKIE_DAYS'] * 86400),
        domain=cookie_domain,
        path='/',
        http_only=False,
        secure=False
        )


def generate_authtoken_html_response(authtoken, resp):
    """
    Display authentication token in an HTML document. Do not emit any cookie.

    Load HTML document template from filesystem and interpolate it with the
    authentication token.
    """
    current_dir = os.path.dirname(os.path.realpath(__file__))
    static_dir = os.path.join(current_dir, 'static')
    template_path = os.path.join(static_dir, 'authtoken-template.tpl.html')

    with open(template_path, 'rb') as f:
        template = f.read().decode('utf-8')

    html_body = string.Template(template).substitute(authtoken=authtoken)
    resp.data = html_body.encode('utf-8')
    resp.set_header('Content-Type', 'text/html; charset=utf-8')

    # Set response headers for (best-effort) cache prevention.
    # http://stackoverflow.com/a/2068407/145400
    resp.set_header('Cache-Control', 'no-cache, no-store, must-revalidate')
    resp.set_header('Pragma', 'no-cache')
    resp.set_header('Expires', '0')
    resp.status = falcon.HTTP_200


def import_remote_user(uid, description, provider_type, provider_id):
    """
    Import and return user.

    Raises:
        EntityExists: user with that uid already exists.
    """
    log.debug('Attempt to create remote user with uid `%s`', uid)

    try:
        user = User(
            uid=uid,
            utype=UserType.regular,
            description=description,
            provider_type=provider_type,
            provider_id=provider_id,
            )
    except bouncer.app.exceptions.UidValidationError:
        _raise_cannot_import_user(
            'Cannot import user: invalid uid `%s`' % (uid,))

    # This might raise `bouncer.app.exceptions.EntityExists`. Let the caller of
    # this function handle it. Ususally, it has just checked before if the user
    # exists or not.
    User.add(user)
    return user


def sso_conditionally_import_and_auth(
        derived_uid,
        description,
        provider_type,
        provider_id,
        req,
        resp,
        target):
    """Conditionally import user at the end of an SSO flow, and send
    authentication response.

    Args:
        derived_uid: UID derived by the SSO component ("derived" from
            details provided by an identity provider).
        description: user description created by the SSO component,
            used only when the user record is newly created (import).
        provider_type (ProviderType): the type of provider (oidc, saml)
        provider_id (str): the provider id (if provider_type is oidc / saml)
        req: Falcon request object of currently handled request.
        resp: Falcon response object for currently handled request.
        target: a URI describing the target the SSO flow should be
            concluded with (`None` or a string).

    If the UID `derived_uid` is not yet known, create a new user (using
    `derived_uid` as well as `descr`), and emit a corresponding authentication
    response.

    If the user is already known, validate that it has previously been labeled
    as a remote user. Then emit authentication response based on previously
    set data.

    After conditional import, conclude the the SSO flow by triggering a
    redirect and by setting authentication details in the HTTP response. The
    HTTP response is built using the `_respond()` function, which delegates
    work to different response generators, for conditionally taking care of
    e.g.

        - setting a cookie
        - emitting the auth token via JSON or HTML
        - setting a redirect URL
    """

    def _respond(_uid, _description):
        token = crypt.generate_auth_token(_uid)

        if target == 'dcos:authenticationresponse:html':
            # Upon entering the SSO flow, the user-agent stored this target to
            # indicate that it desires to retrieve a special, human-readable
            # HTML authentication response.
            generate_authtoken_html_response(token, resp)

        else:
            generate_authtoken_json_response(
                token, req, resp, _uid, _description, is_remote=True)

            # Perform the redirect.
            if target is None:
                # `target` was not defined by user-agent while entering the
                # SSO flow. Redirect to root.
                raise falcon.HTTPSeeOther('/')

            else:
                # `target` was defined by user-agent upon entering the flow.
                # Redirect to it w/o further validation (although it may not
                # even be a valid URL).
                raise falcon.HTTPSeeOther(target)

    try:
        user = dbsession.query(User).filter_by(uid=derived_uid).one()
    except sqlalchemy.orm.exc.NoResultFound:
        log.info('Post-SSO: uid unknown. Trigger implicit user import.')

        # Add to database. Rely on that we've just checked that the user is
        # unknown. Technically, there is race condition and if a separate party
        # was faster adding the same user, the following import logic could
        # raise `bouncer.app.exceptions.EntityExists`. In practice, that
        # requires the same user to log in multiple times via the external login
        # method on a sub-second timescale through different Bouncer instances.
        # It is fine if that succeeds only once, so leave this unhandled (will
        # send a 500 Internal Server Error upon conflict).
        import_remote_user(derived_uid, description, provider_type, provider_id)
        _respond(derived_uid, description)

        # Make it explicit that request handling must terminate here.
        return

    # Handle the (expected) error case where there is a local regular user
    # account known; with the same uid as the subject provided by the single
    # sign-on provider.
    if not user.is_remote:
        _raise_cannot_import_user(
            'uid `%s` is known, but does not refer to a remote user.')

    # We have seen this user before (this user has already been imported
    # before). Use this data. Note(JP): since we now store provider ID and type
    # we should specfify intended behavior, and implement a comparison (the same
    # `uid` yielded from a different identity provider should probably not be
    # acounted as the same user -- should it?).
    log.info('uid refers to a known remote user.')
    _respond(derived_uid, user.description)


def sanitize_remote_uid(remote_uid):
    """Sanitize remote user ID.

    Replace all non-UID-compliant chars with an underscore.
    TODO(jp): this should be synced with the data model ID validation regular
    expressions, via code.

    Args:
        remote_uid: the user ID that the remote end (an external
            identity provider) communicated to Bouncer.
    """
    uid = re.sub(r'[^a-zA-Z0-9-_@\.]+', '_', remote_uid)
    log.info("Sanitized remote user ID to uid: `%s` -> `%s`", remote_uid, uid)
    return uid


def _raise_cannot_import_user(msg):
    log.error(msg)
    # Note(JP): isn't this more of an Internal Server Error?
    raise falcon.HTTPBadRequest(description=msg, code='ERR_CANNOT_IMPORT_USER')
