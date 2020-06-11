"""Exceptions used in the google.verification package."""


class GoogleVerificationError(Exception):
    """Base class for all google.auth errors."""


class TransportError(GoogleVerificationError):
    """Used to indicate an error occurred during an HTTP request."""