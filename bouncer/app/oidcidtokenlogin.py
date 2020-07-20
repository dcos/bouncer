# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
Implement the main business logic for the legacy OpenID Connect ID Token-based
login where an ID Token is exchanged into a DC/OS authentication token.
"""

import logging

import falcon
import jwt
import requests
from jose import jwk

from bouncer.app import config

log = logging.getLogger('bouncer.app.oidcidtokenlogin')


# They key is the issuer URL. They value is the Relying Party (RP) client ID.
ISSUER_WHITELIST = {
    'https://dcos.auth0.com/': '3yF5TOSzdlI45Q1xspxzeoGBe9fNxm9m'
}


if config['TESTING']:
    ISSUER_WHITELIST['https://bouncer-test-hostmachine:8900/dex-for-bouncer/'] = \
        'bouncer-test-client-for-legacy-id-token-login'


# Prepare cache for public keys.
ISSUER_PUBLIC_KEYS = dict()


def get_login_provider_items_from_database_cfgitems(_):
    """Hook into plugin interface."""

    return {
        "dcos-oidc-auth0": {
            "description": "DC/OS Auth0-based SSO through Google, GitHub, or Microsoft",
            "authentication-type": "oidc-implicit-flow",
            "client-method": "browser-prompt-oidcidtoken-get-authtoken",
            "config": {
                # Note(JP): it's actually Admin Router which starts some magic
                # at this endpoint. Bouncer does not actually start the flow.
                "start_flow_url": "/login"
            }
        }
    }


def verify_id_token_or_terminate(req, resp, id_token):
    """Implement (open) DC/OS legacy login method.

    This is not part of a flow which conforms with one of the standardized
    OpenID Connect flows.

    An OpenID Connect ID token is passed to the IAM. Verify it.
    """

    log.debug('Undecoded OIDC ID token: `%s`', id_token)

    # Decode ID token without signature verification. This is for seeing if
    # there is at the very least an issuer (`iss` claim) specified. If that is
    # not the case then this is not an OIDC ID token and request handling can be
    # terminated.

    try:
        unverified_claims = jwt.decode(id_token, verify=False)
    except ValueError as exc:
        _terminate_bad_token(f'decode error: {exc}', '', id_token)

    log.debug('Unverified claims of token: %s', unverified_claims)

    if 'iss' not in unverified_claims:
        _terminate_bad_token('missing `iss` claim', '', unverified_claims)

    unverified_issuer = unverified_claims['iss']
    if unverified_issuer not in ISSUER_WHITELIST:
        _terminate_bad_token(
            f'issuer not white-listed: {unverified_issuer}',
            unverified_claims,
            id_token
        )

    # From openid-connect-core-1_0: "If there are multiple keys in the
    # referenced JWK Set document, a kid value MUST be provided in the JOSE
    # Header." If no `kid` is present treat it as 'default' consistently across
    # this entire module (this is also relevant when doing the JWKS parsing).
    try:
        unverified_header = jwt.get_unverified_header(id_token)
        # Note(JP): it's unclear from docs which exceptions this can raise.
    except Exception as exc:
        _terminate_bad_token(f'cannot read header: {exc}', '', id_token)

    log.debug('Unverified header of token: %s', unverified_header)

    kid = jwt.get_unverified_header(id_token).get('kid', 'default')
    pubkey = _get_pubkey(unverified_issuer, kid)
    expected_audience = ISSUER_WHITELIST[unverified_issuer]

    try:
        verified_claims = jwt.decode(
            id_token,
            pubkey,
            algorithms='RS256',
            audience=expected_audience,
            options={'require_exp': True},
        )
    except jwt.exceptions.InvalidSignatureError:
        _terminate_bad_token('bad signature', unverified_claims, id_token)
    except jwt.exceptions.InvalidAudienceError:
        _terminate_bad_token('unexpected `aud`', unverified_claims, id_token)
    except jwt.exceptions.ExpiredSignatureError:
        _terminate_regular_401('token expired', unverified_claims)
    except jwt.exceptions.InvalidTokenError as exc:
        # Treat everything else as bad/malicious token.
        _terminate_bad_token(str(exc), unverified_claims, id_token)

    # https://openid.net/specs/openid-connect-core-1_0.html#IDToken specifies
    # which claims must be present in an OIDC ID Token. Five of them always
    # required. Check of all of them are there.
    # Todo(JP): handle `nonce` properly.
    required_standard_claims = ('iss', 'sub', 'aud', 'exp', 'iat')
    for c in required_standard_claims:
        if c not in verified_claims:
            # While this can be a broken OpenID Connect provider, it might also
            # be a malicious OpenID Connect provider. Note that this is the 2nd
            # place which enforces the presence of the `exp` claim.
            _terminate_bad_token(
                f'ID Token lacks standard claim: {c}',
                verified_claims,
                id_token
            )

    # Now check non-standard claims.
    required_nonstandard_claims = ('email', 'email_verified')
    for c in required_nonstandard_claims:
        if c not in verified_claims:
            _terminate_regular_401(
                f'ID Token lacks non-standard claim: {c}',
                verified_claims
            )

    if not verified_claims['email_verified']:
        _terminate_regular_401(
            'ID Token must have `"email_verified": true` claim',
            verified_claims
        )

    log.info(
        'ID Token login: token validation passed. Issuer: `%s`, email: `%s`',
        verified_claims['iss'],
        verified_claims['email']
    )
    return verified_claims['iss'], verified_claims['email']


def _terminate_bad_token(error, unverified_claims, oidc_id_token):
    """
    Terminate request handling because the OpenID Connect ID Token appears to be
    fundamentally bad.

    This is expected to handle the hard errors (examples: token text not
    b64-decodable into JSON, bad JSON, token misses required claims) and also
    malicous login attempts (example: signature verification failed, ...).

    This is not expected to handle the more subtle errors that are expected to
    happen as of misconfiguration (e.g. missing `email` claim) and regular
    errors (e.g. token expiration).

    Do not expose the real reason in all detail to user agents but log it so
    that an operator can understand the problem.

    One could think that it makes sense to distinguish between Bad Request (400)
    and Unauthorized (401) responses. Once one dives into that it becomes clear
    that a systematic distinction is hard. Others (e.g.
    https://github.com/mattupstate/flask-jwt) have opted for always sending 401,
    for simplicity. That's convincing.

    Log quite a bit of detail, and show a generic error to the user agent.
    """
    log.info(
        'OpenID Connect ID Token login failed. Bad (malicious?) JWT. Send '
        'generic 401 response. Error: %s. Token: %s, Unverified claims: %s',
        error,
        oidc_id_token,
        unverified_claims
    )

    raise falcon.HTTPUnauthorized(
        description='OpenID Connect ID Token login failed: bad token',
    )


def _terminate_regular_401(usermsg, claims):
    """
    Let the client know why its token was rejected. Also log claimset for
    debugging purposes.
    """
    log.info(
        "OpenID Connect ID Token login failed. Send 401 response with "
        "description: '%s'. Claims: %s", usermsg, claims
    )

    raise falcon.HTTPUnauthorized(
        description=f'OpenID Connect ID Token login failed: {usermsg}',
    )


def _get_pubkey(issuer, requested_kid):
    """
    Construct URL to .well-known/openid-configuration.

    Fetch the config JSON document. By spec, it is required to contain a
    `jwks_uri` key.

    Use that URL to fetch the JWKS JSON document, and decode it. Return the
    resulting data structure.

    # From the spec (https://openid.net/specs/openid-connect-core-1_0.html,
    # section 10.1.1): The verifier knows to go back to the jwks_uri location to
    # re-retrieve the keys when it sees an unfamiliar kid value.
    """

    # Try to read the data from the cache. The cache is a dictionary which is
    # thread-safe in CPython. The cache key is a combination of issuer and key
    # ID. That is, if there is just a single default key for an issuer (a key
    # without key ID) then we do not support rotation. A restart of the IAM is
    # required to pick that up. That is fine.
    try:
        return ISSUER_PUBLIC_KEYS[issuer][requested_kid]
    except KeyError:
        log.info(
            'Public key for issuer `%s` with key ID `%s` not in cache',
            issuer, requested_kid
        )
        pass

    # Note(JP): while I am sure the spec says something about leading/trailing
    # slashes I opt for making sure to not miss a slash, and to not have a
    # double slash.
    cfg_url = issuer.rstrip('/') + '/.well-known/openid-configuration'

    verify_tls = True
    if config['TESTING']:
        verify_tls = False

    # Any one of the following three lines can raise an exception, as in case of
    # transport errors, unexpected HTTP response status codes, JSON
    # deserialiation problems, and failing key lookup. Handle of them in the
    # same way.
    try:
        response = requests.get(cfg_url, verify=verify_tls)
        response.raise_for_status()
        jwks_url = response.json()['jwks_uri']
    except Exception as exc:
        log.error(
            'Could not fetch jwks_uri from `%s`: %s', cfg_url, exc)
        raise falcon.HTTPInternalServerError(
            description='Could not fetch public key material from token issuer'
            )

    # In terms of error-handling the same as above holds true.
    try:
        response = requests.get(jwks_url, verify=verify_tls)
        response.raise_for_status()
        jwks = response.json()
    except Exception as exc:
        log.error(
            'Could not fetch jwks_uri from `%s`: %s', cfg_url, exc)
        raise falcon.HTTPInternalServerError(
            description='Could not fetch public key material from token issuer'
            )

    # `jwks` is a Python data structure that is expected to represent a valid
    # JSON Web Key Set JSON document.

    # Note(JP): as of the JWKS spec it seems to be possible that a JWKS contains
    # more than one key where individual keys do not have a key ID. The keys can
    # then be distinguished by the key type. But even then.. to quote from RFC
    # 7517: "When "kid" values are used within a JWK Set, different keys within
    # the JWK Set SHOULD use distinct "kid" values.  (One example in which
    # different keys might use the same "kid" value is if they have different
    # "kty" (key type) values but are considered to be equivalent alternatives
    # by the application using them.)" -- so, here, plan for the simplest cases:
    # if there is no `kid` set then treat it as 'default'. Only support RSA type
    # keys. If there is more than one RSA type key without key ID in the JWKS
    # then the last one wins. This will only be a problem with exotic providers,
    # it is known to not be a problem for Auth0.
    for key_dict in jwks['keys']:
        # `kid` is optional. Use 'default' as the key ID when it is not set.
        kid = key_dict.get('kid', 'default')

        # `kty` (the key type) is required. `alg` (the intended algorithm within
        # which this key is supposed to be used) is optional. Assume RSA and
        # RS256 for starters. We can widen that to support other key types, but
        # for Auth0 support we know that this is not required.
        kty = key_dict.get('kty', None)
        if kty != 'RSA':
            continue

        # The `prepared_key` attribute exposes the `cryptography`-native public
        # key object.
        key = jwk.RSAKey(
            key=key_dict,
            algorithm=jwk.ALGORITHMS.RS256
        ).prepared_key

        log.info(
            'Public key for issuer `%s` with key ID `%s` retrieved',
            issuer, requested_kid
        )
        # Insert key into cache.
        if issuer not in ISSUER_PUBLIC_KEYS:
            ISSUER_PUBLIC_KEYS[issuer] = dict()
        ISSUER_PUBLIC_KEYS[issuer][kid] = key

    try:
        return ISSUER_PUBLIC_KEYS[issuer][requested_kid]
    except KeyError:
        log.warning(
            'Public key for issuer `%s` with key ID `%s` could not be obtained',
            issuer, requested_kid
        )
        # Let this exception terminate request handling, send an Internal Server
        # Error to the client.
        raise
