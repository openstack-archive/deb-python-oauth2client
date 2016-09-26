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

"""Transport is used to make HTTP requests."""

from six.moves import http_client

from oauth2client.transport import httplib2


REFRESH_STATUS_CODES = (http_client.UNAUTHORIZED,)


class _SETTINGS(object):
    default_transport = httplib2


def set_default_transport(transport_module):
    """Sets the global default transport."""
    _SETTINGS.default_transport = transport_module


def get_default_transport():
    """Gets the global default transport."""
    return _SETTINGS.default_transport


def get_http_object(*args, **kwargs):
    """Returns an instance of default transport's http object."""
    return get_default_transport().get_http_object(*args, **kwargs)


def make_authorized_http(
        http_object, credentials, refresh_status_code=REFRESH_STATUS_CODES):
    """Creates an HTTP object that provides credentials to requests.

    The behavior is transport-specific, but all transports will return a new
    HTTP object that provides credentials to requests and refreshed credentials
    when a response in REFRESH_STATUS_CODES is received.

    Args:
        credentials: An instance of
            :class:`~oauth2client.client.OAuth2Credentials`.
        http: The HTTP object to wrap.
        refresh_status_codes: A sequence of status codes that indicate that
            credentials should be refreshed and the request retried. Defaults
            to REFRESH_STATUS_CODES.

    Returns:
        A new HTTP object that provides credentials to requests.
    """
    return get_default_transport().make_authorized_http(
        http_object, credentials, refresh_status_codes=refresh_status_code)


def request(http_object, uri, method='GET', body=None, headers=None,
            **kwargs):
    """Makes an HTTP request.

    Args:
        http_object: The transport-specific HTTP object to be used to make
            requests.
        uri: string, The URI to be requested.
        method: string, The HTTP method to use for the request. Defaults
            to 'GET'.
        body: string, The payload / body in HTTP request. By default
            there is no payload.
        headers: dict, Key-value pairs of request headers. By default
            there are no headers.

    Returns:
        A response object that will contain at least the following properties:

        * status: int, the HTTP status code.
        * headers: dict, the HTTP response headers.
        * data: bytes, the HTTP response body.
    """
    return get_default_transport().request(
        http_object, uri, method=method, body=body, headers=headers, **kwargs)
