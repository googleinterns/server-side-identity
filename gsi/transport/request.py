"""Transport adapter for Requests."""

from __future__ import absolute_import

import functools
import logging
import numbers
import time

try:
    import requests
except ImportError as error:  # pragma: NO COVER
    import six

    six.raise_from(
        ImportError(
            "The requests library is not installed, please install the "
            "requests package to use the requests transport."
        ),
        error,
    )
import requests.adapters  # pylint: disable=ungrouped-imports
import requests.exceptions  # pylint: disable=ungrouped-imports
from requests.packages.urllib3.util.ssl_ import (
    create_urllib3_context,
)  # pylint: disable=ungrouped-imports
import six  # pylint: disable=ungrouped-imports

from gsi import transport
from gsi.verification import exceptions

_LOGGER = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 120  # in seconds


class _Response(transport.Response):
    """Requests transport response adapter.
    Args:
        response (requests.Response): The raw Requests response.
    """

    def __init__(self, response):
        self._response = response

    @property
    def status(self):
        return self._response.status_code

    @property
    def headers(self):
        return self._response.headers

    @property
    def data(self):
        return self._response.content


class Request(transport.Request):
    """Requests request adapter.
    This class is used internally for making requests using various transports
    in a consistent way.
    Args:
        session (requests.Session): An instance :class:`requests.Session` used
            to make HTTP requests. If not specified, a session will be created.
    .. automethod:: __call__
    """

    def __init__(self, session=None):
        if not session:
            session = requests.Session()

        self.session = session

    def __call__(
        self,
        url,
        method="GET",
        body=None,
        headers=None,
        timeout=_DEFAULT_TIMEOUT,
        **kwargs
    ):
        """Make an HTTP request using requests.
        Args:
            url (str): The URI to be requested.
            method (str): The HTTP method to use for the request. Defaults
                to 'GET'.
            body (bytes): The payload / body in HTTP request.
            headers (Mapping[str, str]): Request headers.
            timeout (Optional[int]): The number of seconds to wait for a
                response from the server. If not specified or if None, the
                requests default timeout will be used.
            kwargs: Additional arguments passed through to the underlying
                requests :meth:`~requests.Session.request` method.
        Returns:
            google.transport.Response: The HTTP response.
        Raises:
            google.verification.exceptions.TransportError: If any exception occurred.
        """
        try:
            _LOGGER.debug("Making request: %s %s", method, url)
            response = self.session.request(
                method, url, data=body, headers=headers, timeout=timeout, **kwargs
            )
            return _Response(response)
        except requests.exceptions.RequestException as error:
            new_error = exceptions.TransportError(error)
            six.raise_from(new_error, error)
            
