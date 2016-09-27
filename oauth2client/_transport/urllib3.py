# Copyright 2016 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Transport implementation using urllib3"""

from __future__ import absolute_import

import logging

import urllib3
from urllib3 import request

from oauth2client._transport import _helpers


_LOGGER = logging.getLogger(__name__)
_MAX_REFRESH_ATTEMPTS = 2

HTTP_OBJECT_CLASSES = (urllib3.request.RequestMethods,)


def get_http_object(*args, **kwargs):
    """Return a new HTTP object.

    Args:
        *args: tuple, The positional arguments to be passed when
               contructing a new HTTP object.
        **kwargs: dict, The keyword arguments to be passed when
                  contructing a new HTTP object.

    Returns:
        urllib3.PoolManager: The new HTTP object.
    """
    return urllib3.PoolManager(*args, **kwargs)


class AuthorizedHttp(request.RequestMethods):
    """An authorized urllib3 HTTP class.

    Implements :class:`urllib3.request.RequestMethods` and can be used just
    like any other :class:`urllib3.PoolManager`.

    Provides an implementation of :meth:`urlopen` that handles adding the
    credentials to the request headers and refreshing credentials as needed.

    Args:
        http (urllib3.PoolManager): The underlying HTTP object to
            use to make requests.
        credentials (oauth2client.client.OAuth2Credentials): The credentials to
            add to the request.
        refresh_status_codes (Sequence): Which HTTP status code indicate that
            credentials should be refreshed and the request should be retried.
    """
    def __init__(self, http, credentials, refresh_status_codes):
        self.http = http
        self.credentials = credentials
        self.refresh_status_codes = refresh_status_codes

    def urlopen(self, method, url, body=None, headers=None, **kwargs):
        """Implementation of urllib3's urlopen."""
        _credential_refresh_attempt = kwargs.pop(
            '_credential_refresh_attempt', 0)

        if headers is None:
            headers = self.headers

        # Copy the request headers because this may be called recursively.
        request_headers = _helpers.initialize_headers(headers)
        _helpers.apply_user_agent(request_headers, self.credentials.user_agent)

        self.credentials._before_request(
            self.http, url, request_headers)
        request_headers = _helpers.clean_headers(request_headers)

        response = self.http.urlopen(
            method, url, body=body, headers=request_headers, **kwargs)

        # If the response indicated that the credentials needed to be
        # refreshed, then refresh the credentials and re-attempt the
        # request.
        # A stored token may expire between the time it is retrieved and
        # the time the request is made, so we may need to try twice.
        # The reason urllib3's retries aren't used is because they
        # don't allow you to modify the request headers. :/
        if (response.status in self.refresh_status_codes
                and _credential_refresh_attempt < _MAX_REFRESH_ATTEMPTS):

            _LOGGER.info(
                'Refreshing due to a %s (attempt %s/%s)',
                response.status, _credential_refresh_attempt + 1,
                _MAX_REFRESH_ATTEMPTS)

            self.credentials.refresh(self.http)

            # Recurse. Pass in the original headers, not our modified set.
            return self.urlopen(
                method, url, body=body, headers=headers,
                _credential_refresh_attempt=_credential_refresh_attempt + 1,
                **kwargs)

        return response

    # Proxy methods for compliance with the urllib3.PoolManager interface

    def __enter__(self):
        """Proxy to self.http."""
        return self.http.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Proxy to self.http."""
        return self.http.__exit__(exc_type, exc_val, exc_tb)

    @property
    def headers(self):
        """Proxy to self.http."""
        return self.http.headers

    @headers.setter
    def headers(self, value):
        """Proxy to self.http."""
        self.http.headers = value


def make_authorized_http(http, credentials, refresh_status_codes):
    """Creates an http object that provides credentials to requests.

    The behavior is transport-specific, but all transports will return a new
    http object that provides credentials to requests and refreshed credentials
    when a response in ``refresh_status_codes`` is received.

    Args:
        http (urllib3.PoolManager): The underlying HTTP object to
            use to make requests.
        credentials (oauth2client.client.OAuth2Credentials): The credentials to
            add to the request.
        refresh_status_codes (Sequence): Which HTTP status code indicate that
            credentials should be refreshed and the request should be retried.

    Returns:
        AuthorizedHttp: A new http object that provides credentials to
            requests.
    """
    return AuthorizedHttp(http, credentials, refresh_status_codes)


def request(http_object, uri, method='GET', body=None, headers=None,
            timeout=None, **kwargs):
    """Make an HTTP request with an HTTP object and arguments.

    The arguments and return value satisfy the match
    :func:`oauth2client.transport.request` interface. Additional
    arguments are passed through to
    :meth:`urllib3.request.RequestMethods.request`.

    Args:
        http_object (urllib3.request.RequestMethods): Any instance that
            provides the :class:`RequestMethods` interface.
        uri (str): The URI to be requested.
        method (str): The HTTP method to use for the request. Defaults
            to 'GET'.
        body (bytes): The payload / body in HTTP request.
        headers (Mapping): Request headers.
        timeout (Optional(int)): The number of seconds to wait for a response
            from the server. If not specified or if None, the urllib3 default
            timeout will be used.
    Returns:
        urllib3.response.HTTPResponse: The HTTP response.
    """

    # Urllib3 uses a sentinel default value for timeout, so only set it if
    # specified.
    if timeout is not None:
        kwargs['timeout'] = timeout

    return http_object.request(
        method, uri, body=body, headers=headers, **kwargs)
