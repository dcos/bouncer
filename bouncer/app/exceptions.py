# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


from bouncer.exceptions import BouncerException


class InvalidPassword(BouncerException):
    """Password does not comply with rules."""


class InvalidPubkey(BouncerException):
    """Serialized public key does not comply with rules."""


class EntityExists(BouncerException):
    pass


class EntityNotFound(BouncerException):
    pass


class UidValidationError(BouncerException):
    pass


class ProviderTypeValidationError(BouncerException):
    pass


class ProviderIdValidationError(BouncerException):
    pass


class GidValidationError(BouncerException):
    pass


class RidValidationError(BouncerException):
    pass


class RidValidationWithUserMessageError(RidValidationError):
    pass


class ActionValidationError(BouncerException):
    pass
