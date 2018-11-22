# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""Aggregate all functionality relevant for cryptography."""


import os
import uuid
import base64
import hashlib
import logging
from time import time

import jwt
import cryptography.hazmat.backends
from jose.utils import long_to_base64
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from passlib.apps import custom_app_context as passlib_context

from bouncer.app import config, db
from bouncer.exceptions import BouncerException
from bouncer.app.exceptions import InvalidPassword, InvalidPubkey
from bouncer.app.models import run_transaction

log = logging.getLogger('bouncer.app.crypt')


# Allow for reusal of this object.
cryptography_default_backend = cryptography.hazmat.backends.default_backend()


# A subset of the functions defined in this module requires initialization of a
# keypair. Initialization of that keypair, however, requires database
# interaction (for achieving consensus) and therefore happens late, after
# import, through invocation of
# `read_private_key_from_file_or_generate_through_database()`.
_public_key_cryptography = None
_private_key_cryptography = None


def validate_pubkey(key):
    """
    Make sure that `key_pem` is a string containing an RSA public key encoded
    using the X.509 SubjectPublicKeyInfo/OpenSSL PEM public key format. Refs:
        - https://tools.ietf.org/html/rfc5280.html
        - http://stackoverflow.com/a/29707204/145400

    Args:
        key_pem (str): serialized public key
    """
    log.debug("Validate public key.")
    try:
        key = serialization.load_pem_public_key(
            data=key.encode('ascii'),
            backend=cryptography_default_backend)
        # ValueError can be raised by either the encoding operation
        # or by the cryptography module upon key deserialization.
    except (ValueError, UnsupportedAlgorithm) as e:
        raise InvalidPubkey(e)

    if not isinstance(key, rsa.RSAPublicKey):
        raise InvalidPubkey('Key must be of type RSA')


def validate_password(password):
    """Implement password validation rules, such as length."""
    log.debug("Validate password.")
    if len(password) < 5:
        raise InvalidPassword("Must be at least 5 characters long.")


def _hash_password_passlib(password):
    log.debug('hash_password_passlib()')
    assert isinstance(password, str)
    # Passlib returns unicode (str) on Py3.
    pw = passlib_context.hash(password)
    log.debug('Hashing done.')
    return pw


def _verify_password_passlib(password, hashed_password):
    assert isinstance(password, str)
    assert isinstance(hashed_password, str)
    try:
        return passlib_context.verify(password, hashed_password)
    except ValueError as e:
        log.error("ValueError while verifying password: %s", e)
        return False


def generate_jwt(payload):
    """Generate and return JWT, select algorithm based on configuration.

    Args:
        payload: the payload dictionary

    `jwt.encode` returns bytes (expected to be ASCII-decodable).

    Returns:
        str: the token
    """
    algo = config['AUTH_TOKEN_SIGNATURE_ALGORITHM']

    if algo == 'RS256':
        return jwt.encode(
            payload, _private_key_cryptography, algorithm='RS256').decode('ascii')

    raise NotImplementedError


def verify_jwt(token):
    """Verify JWT, use algorithm based on configuration.

    Returns:
        dict: the payload dictionary
    """
    algo = config['AUTH_TOKEN_SIGNATURE_ALGORITHM']

    if algo == 'RS256':
        return jwt.decode(token, _public_key_cryptography, algorithms='RS256')

    raise NotImplementedError


def generate_auth_token(uid, exp=None):
    """Generate and return DC/OS authentication token (an RFC 7519 JSON Web
    Token).

    The exp claim in the payload section of a  JWT encodes the time the token
    expires in seconds since epoch (unix timestamp).

    Args:
        uid (str): the user ID to encode in the JWT payload
        exp:
            `None`: apply default expiration time
            `0`: do not include `exp` claim in token payload
            else: cast to integer, use this as expiration time

    Returns:
        str: the token
    """
    payload = {'uid': uid}

    # Represent this point in time in compliance with a "NumericDate" value
    # as spec'd here: https://tools.ietf.org/html/rfc7519#section-4.1.4
    # Any JSON numeric value is allowed. Use an integer.
    if exp is None:
        t = time() + config['EXPIRATION_AUTH_TOKEN_DAYS'] * 86400
        payload['exp'] = int(t)

    elif exp == 0:
        # Do not include exp claim in payload. Note(JP): this results in a DC/OS
        # authentication token which is not compliant with its specification. As
        # of the specification the authentication token must include an `exp`
        # claim. This code path was introduced as a hacky workaround around the
        # problem of authentication token refresh during DC/OS Enterprise 1.8
        # development. This code path needs to be removed as part of a
        # consolidation project.
        log.warning(
            'Non-standard auth token: no exp claim (uid `%s`).', uid)
        pass

    else:
        # Note(JP): this code path should never have been introduced. I believe
        # it was introduced as part of the hacky workaround around the problem
        # of authentication token refresh during DC/OS Enterprise 1.8
        # development (see above) but this should not have been required (one of
        # both mechanisms would have been enough). This code path needs to be
        # removed as part of a consolidation project.
        log.warning(
            'Non-standard auth token: custom exp claim (uid `%s`).', uid)
        payload['exp'] = int(exp)

    log.info('Generate auth token with payload `%s`', payload)
    return generate_jwt(payload)


def gen_jwks():
    """Generate JSON Web Key Set (JWKS), exposing the public key details,
    based on the private key.

    Returns:
        dict: an RFC 7517-compliant data structure

    Refs:
        - https://tools.ietf.org/html/rfc7517 (specifying the JWKS format)
        - https://tools.ietf.org/html/rfc7518 (specifying key parameterization)
    """
    log.info("Generate JSON Web Key Set")

    public_numbers = _public_key_cryptography.public_numbers()

    # Generate Key ID parameter, see
    # https://tools.ietf.org/html/rfc7517#section-4.5
    # Make it depend on the (public) key specifics.
    fingerprint = "%s%sRSA" % (public_numbers.e, public_numbers.n)
    key_id = hashlib.sha256(fingerprint.encode('utf-8')).hexdigest()

    # `n` and `e` are Base64urlUInt-encoded values, see
    # https://tools.ietf.org/html/rfc7518#section-6.3

    return {
        'keys': [{
            'kid': key_id,
            'kty': 'RSA',
            'n': long_to_base64(public_numbers.n).decode('ascii'),
            'e': long_to_base64(public_numbers.e).decode('ascii'),
            'alg': 'RS256',
            'use': 'sig'
        }]
    }


def generate_RSA_keypair(key_size=2048):
    """
    Generate an RSA keypair with an exponent of 65537. Serialize the public
    key in the the X.509 SubjectPublicKeyInfo/OpenSSL PEM public key format
    (RFC 5280). Serialize the private key in the PKCS#8 (RFC 3447) format.

    Args:
        bits (int): the key length in bits.
    Returns:
        (private key, public key) 2-tuple, both unicode
        objects holding the serialized keys.
    """
    log.debug("Generate RSA keypair.")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=cryptography_default_backend)

    privkey_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    public_key = private_key.public_key()
    pubkey_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return privkey_pem.decode('ascii'), pubkey_pem.decode('ascii')


def _hash_password_dummy(p):
    return p + "DUMMYENCRYPTED"


def _verify_password_dummy(p, encrypted_password):
    return p + "DUMMYENCRYPTED" == encrypted_password


def _generate_token_sign_sharedkey():
    """Generate an ASCII-safe key from proper randomness, time, MAC.

    Returns:
        str: key with 80 ASCII-safe characters.
    """
    # Pull in 512 bytes from the operating system's random source, and combine
    # this with MAC address and current time. Use the SHA512 method for
    # reducing this to 64 bytes.
    b = hashlib.sha512(os.urandom(512) + uuid.uuid1().bytes).digest()
    # Expand to ascii-safe representation with a ratio of 5/4 (get 80 chars).
    return base64.b85encode(b).decode('ascii')


def _validate_secretkey(key):
    """Implement secret key validation.

    Raise exception when key is invalid. To be filled with details.
    """
    if len(key) <= 20:
        raise BouncerException(
            'The secret key must be longer than 20 characters.')
    log.info('Secret key properties are valid. Proceed.')
    return key


def _validate_privatekey_pem(key_pem):
    """Implement private key validation.

    Args:
        key_pem (str): RSA PKCS#8 PEM private key (traditional OpenSSL format)
            of at least 2048 bit strength.
    """
    assert isinstance(key_pem, str)

    # Create the cryptography package private key object and perform basic
    # validation using functionality provided by the cryptography package.

    privkey = serialization.load_pem_private_key(
        data=key_pem.encode('ascii'),
        password=None,
        backend=cryptography_default_backend)

    if not isinstance(privkey, rsa.RSAPrivateKey):
        raise BouncerException('Unexpected private key type')

    if privkey.key_size < 2048:
        raise BouncerException('RSA key size too small')

    log.info('Private key properties are valid. Proceed.')
    return privkey


def _write_new_keyfile(path, key):
    """Write key (str) to file, using ascii codec."""
    # Attempt to write file in 600 mode. Take control of umask, also see
    # http://stackoverflow.com/a/15015748/145400.
    log.info('Write key to `%s` (600 perms).', path)

    # Create directory if it does not yet exist. The directory tree is meant to
    # be owned by the user running this process, and default permissions are
    # fine.
    dirpath = os.path.dirname(path)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    umask_original = os.umask(0)
    try:
        flags = os.O_WRONLY | os.O_CREAT
        with os.fdopen(os.open(path, flags, 0o600), 'wb') as f:
            f.write(key.encode('ascii'))
    finally:
        os.umask(umask_original)


def _read_secret_key_from_file_or_generate(path):

    if os.path.exists(path):
        return _validate_secretkey(_get_key_from_file(path))

    log.info('Secret key file `%s` does not exist.', path)

    def callback():
        return db.achieve_value_consensus(
            key='sharedkey',
            value=_generate_token_sign_sharedkey())

    key = run_transaction(callback)
    _write_new_keyfile(path, key)
    return key


def read_private_key_from_file_or_generate_through_database(path):

    # Expose private key and public key as module-level globals as native
    # `cryptography` objects.
    global _public_key_cryptography
    global _private_key_cryptography

    if not os.path.exists(path):
        log.info('Private key file `%s` does not exist.', path)
        privkey_pem_proposal, _ = generate_RSA_keypair()

        def callback():
            return db.achieve_value_consensus(
                key='privkey', value=privkey_pem_proposal)

        privkey_pem_consens = run_transaction(callback)
        _write_new_keyfile(path, privkey_pem_consens)

    # Go through validation function, although input is trusted: the validation
    # function returns the private key as a native `cryptography` object which
    # is what we want.
    _private_key_cryptography = _validate_privatekey_pem(_get_key_from_file(path))
    _public_key_cryptography = _private_key_cryptography.public_key()


def _get_key_from_file(path):
    """Read file, validate file permissions.

    Returns:
        str: key
    """
    log.info('Attempt to read secret key from file at path `%s`', path)
    # https://docs.python.org/3/glossary.html#term-eafp
    try:
        with open(path, 'rb') as f:
            # Treat key as text, encoded via ASCII.
            # Ignore leading and trailing whitespace.
            key = f.read().decode('ascii').strip()
    except OSError as e:
        m = 'Cannot read key file: %s' % e
        log.error(m)
        raise BouncerException(m)

    log.debug('Stat key file.')
    canonical_permission_triple = oct(os.stat(path).st_mode)[-3:]
    log.info('Secret key file permissions: %s', canonical_permission_triple)
    # Expecting '600', but only the two trailing are really important.
    if canonical_permission_triple[-2:] != '00':
        m = 'The key file must be readable by the owner only.'
        log.error(m)
        raise BouncerException(m)
    return key


# Select password hashing and verification method.
hash_password = _hash_password_passlib
verify_password = _verify_password_passlib
if config['PASSWORD_HASHING_DUMMY']:
    log.warning('Using dummy password hashing method!')
    hash_password = _hash_password_dummy
    verify_password = _verify_password_dummy
