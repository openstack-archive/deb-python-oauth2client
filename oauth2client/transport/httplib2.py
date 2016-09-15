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

"""Transport implementation using httplib2"""

from __future__ import absolute_import

import logging

import httplib2

from oauth2client.transport import _helpers


_LOGGER = logging.getLogger(__name__)
# Properties present in file-like streams / buffers.
_STREAM_PROPERTIES = ('read', 'seek', 'tell')


class MemoryCache(object):
    """httplib2 Cache implementation which only caches locally."""

    def __init__(self):
        self.cache = {}

    def get(self, key):
        return self.cache.get(key)

    def set(self, key, value):
        self.cache[key] = value

    def delete(self, key):
        self.cache.pop(key, None)


def get_cached_http():
    """Return an HTTP object which caches results returned.

    This is intended to be used in methods like
    oauth2client.client.verify_id_token(), which calls to the same URI
    to retrieve certs.

    Returns:
        httplib2.Http, an HTTP object with a MemoryCache
    """
    return _CACHED_HTTP


def get_http_object(*args, **kwargs):
    """Return a new HTTP object.

    Args:
        *args: tuple, The positional arguments to be passed when
               contructing a new HTTP object.
        **kwargs: dict, The keyword arguments to be passed when
                  contructing a new HTTP object.

    Returns:
        httplib2.Http, an HTTP object.
    """
    return httplib2.Http(*args, **kwargs)


def inject_credentials(credentials, http, refresh_status_codes):
    """Prepares an HTTP object's request method for auth.

    Wraps HTTP requests with logic to catch auth failures (typically
    identified via a 401 status code). In the event of failure, tries
    to refresh the token used and then retry the original request.

    Args:
        credentials: Credentials, the credentials used to identify
                     the authenticated user.
        http: httplib2.Http, an http object to be used to make
              auth requests.
    """
    orig_request_method = http.request

    # The closure that will replace 'httplib2.Http.request'.
    def new_request(uri, method='GET', body=None, headers=None,
                    redirections=httplib2.DEFAULT_MAX_REDIRECTS,
                    connection_type=None):
        if not credentials.access_token:
            _LOGGER.info('Attempting refresh to obtain '
                         'initial access_token')
            credentials._refresh(orig_request_method)

        # Clone and modify the request headers to add the appropriate
        # Authorization header.
        headers = _helpers.initialize_headers(headers)
        credentials.apply(headers)
        _helpers.apply_user_agent(headers, credentials.user_agent)

        body_stream_position = None
        # Check if the body is a file-like stream.
        if all(getattr(body, stream_prop, None) for stream_prop in
               _STREAM_PROPERTIES):
            body_stream_position = body.tell()

        resp, content = request(orig_request_method, uri, method, body,
                                _helpers.clean_headers(headers),
                                redirections, connection_type)

        # A stored token may expire between the time it is retrieved and
        # the time the request is made, so we may need to try twice.
        max_refresh_attempts = 2
        for refresh_attempt in range(max_refresh_attempts):
            if resp.status not in refresh_status_codes:
                break
            _LOGGER.info('Refreshing due to a %s (attempt %s/%s)',
                         resp.status, refresh_attempt + 1,
                         max_refresh_attempts)
            credentials._refresh(orig_request_method)
            credentials.apply(headers)
            if body_stream_position is not None:
                body.seek(body_stream_position)

            resp, content = request(orig_request_method, uri, method, body,
                                    _helpers.clean_headers(headers),
                                    redirections, connection_type)

        return resp, content

    # Replace the request method with our own closure.
    http.request = new_request

    # Set credentials as a property of the request method.
    http.request.credentials = credentials


def inject_assertion_credentials(
        credentials, http, refresh_status_codes):
    """Prepares an HTTP object's request method for JWT access.

    Wraps HTTP requests with logic to catch auth failures (typically
    identified via a 401 status code). In the event of failure, tries
    to refresh the token used and then retry the original request.

    Args:
        credentials: _JWTAccessCredentials, the credentials used to identify
                     a service account that uses JWT access tokens.
        http: httplib2.Http, an http object to be used to make
              auth requests.
    """
    orig_request_method = http.request
    inject_credentials(
        credentials, http, refresh_status_codes=refresh_status_codes)
    # The new value of ``http.request`` set by ``inject_credentials``.
    authenticated_request_method = http.request

    # The closure that will replace 'httplib2.Http.request'.
    def new_request(uri, method='GET', body=None, headers=None,
                    redirections=httplib2.DEFAULT_MAX_REDIRECTS,
                    connection_type=None):
        if 'aud' in credentials._kwargs:
            # Preemptively refresh token, this is not done for OAuth2
            if (credentials.access_token is None or
                    credentials.access_token_expired):
                credentials.refresh(None)
            return request(authenticated_request_method, uri,
                           method, body, headers, redirections,
                           connection_type)
        else:
            # If we don't have an 'aud' (audience) claim,
            # create a 1-time token with the uri root as the audience
            headers = _helpers.initialize_headers(headers)
            _helpers.apply_user_agent(headers, credentials.user_agent)
            uri_root = uri.split('?', 1)[0]
            token, unused_expiry = credentials._create_token({'aud': uri_root})

            headers['Authorization'] = 'Bearer ' + token
            return request(orig_request_method, uri, method, body,
                           _helpers.clean_headers(headers),
                           redirections, connection_type)

    # Replace the request method with our own closure.
    http.request = new_request

    # Set credentials as a property of the request method.
    http.request.credentials = credentials


def request(http, uri, method='GET', body=None, headers=None,
            redirections=httplib2.DEFAULT_MAX_REDIRECTS,
            connection_type=None):
    """Make an HTTP request with an HTTP object and arguments.

    Args:
        http: httplib2.Http, an http object to be used to make requests.
        uri: string, The URI to be requested.
        method: string, The HTTP method to use for the request. Defaults
                to 'GET'.
        body: string, The payload / body in HTTP request. By default
              there is no payload.
        headers: dict, Key-value pairs of request headers. By default
                 there are no headers.
        redirections: int, The number of allowed 203 redirects for
                      the request. Defaults to 5.
        connection_type: httplib.HTTPConnection, a subclass to be used for
                         establishing connection. If not set, the type
                         will be determined from the ``uri``.

    Returns:
        tuple, a pair of a httplib2.Response with the status code and other
        headers and the bytes of the content returned.
    """
    # NOTE: Allowing http or http.request is temporary (See Issue 601).
    http_callable = getattr(http, 'request', http)
    return http_callable(uri, method=method, body=body, headers=headers,
                         redirections=redirections,
                         connection_type=connection_type)


_CACHED_HTTP = httplib2.Http(MemoryCache())
