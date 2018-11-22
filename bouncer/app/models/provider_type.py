# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


import enum


class ProviderType(enum.Enum):
    """Abstraction for provider types."""
    internal = 'internal'
    ldap = 'ldap'
    oidc = 'oidc'
    saml = 'saml'
