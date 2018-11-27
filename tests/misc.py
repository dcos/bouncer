# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


import cryptography.hazmat.backends
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


COMMON_URL_PATH_PREFIX = '/acs/api/v1'


PROVIDER_TYPES = ['internal', 'ldap', 'oidc', 'saml']


def rid_slash_encoder(rid):
    return rid.replace('/', '%252F')


class UrlBase:
    # Supposed to be set by a subclass.
    wsgi_app_bind_address = None

    def __init__(self, path):
        assert path.startswith('/')
        # Build absolute path by prepending common prefix.
        self.path = "%s%s" % (COMMON_URL_PATH_PREFIX, path)

    def _abs(self):
        return "http://%s%s" % (self.wsgi_app_bind_address, self.path)

    def rel(self):
        """Return just the path (no scheme, host)."""
        return self.path

    def __str__(self):
        """Make text representation be absolute URL."""
        return self._abs()


class Url(UrlBase):
    wsgi_app_bind_address = '127.0.0.1:8101'


class UrlUserPermissionsMaxAgeSeconds60(UrlBase):
    # This bind address is adjusted to the WSGI app server
    # running with the configuration variable
    # ``USER_PERMISSIONS_RESPONSE_MAX_AGE_SECONDS`` set to 60.
    wsgi_app_bind_address = '127.0.0.1:8103'


class UrlSlowLDAPDirectory(UrlBase):
    # This bind address is adjusted to the WSGI app server
    # running with the configuration variable
    # ``LDAP_GROUP_IMPORT_LIMIT_SECONDS`` set to 0.
    wsgi_app_bind_address = '127.0.0.1:8104'


class UrlBootstrapServiceAcc(UrlBase):
    # This bind address is adjusted to the WSGI app server running Bouncer with
    # is supposed to create a superuser service account during bootstrap.
    wsgi_app_bind_address = '127.0.0.1:8105'


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
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=cryptography.hazmat.backends.default_backend())

    privkey_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    public_key = private_key.public_key()
    pubkey_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return privkey_pem.decode('ascii'), pubkey_pem.decode('ascii')
