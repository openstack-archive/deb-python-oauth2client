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
_MAX_REFRESH_ATTEMPTS = 2


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
                    connection_type=None, _credential_refresh_attempt=0):

        # Clone and modify the request headers to add the appropriate
        # Authorization header.
        headers = _helpers.initialize_headers(headers)
        _helpers.apply_user_agent(headers, credentials.user_agent)

        credentials._before_request(orig_request_method, uri, headers)
        headers = _helpers.clean_headers(headers)

        body_stream_position = None
        # Check if the body is a file-like stream.
        if all(getattr(body, stream_prop, None) for stream_prop in
               _STREAM_PROPERTIES):
            body_stream_position = body.tell()

        resp, content = request(
            orig_request_method, uri, method, body,
            headers, redirections, connection_type)

        # If the response indicated that the credentials needed to be
        # refreshed, then refresh the credentials and re-attempt the
        # request.
        # A stored token may expire between the time it is retrieved and
        # the time the request is made, so we may need to try twice.
        if (resp.status in refresh_status_codes
                and _credential_refresh_attempt < _MAX_REFRESH_ATTEMPTS):

            _LOGGER.info(
                'Refreshing due to a %s (attempt %s/%s)',
                resp.status, _credential_refresh_attempt + 1,
                _MAX_REFRESH_ATTEMPTS)

            credentials.refresh(orig_request_method)

            # Remove the existing Authorization header, as the credentials
            # may set the header as u'Authorization' but clean_headers set it
            # as b'Authorization'.
            headers.pop(b'Authorization', None)

            if body_stream_position is not None:
                body.seek(body_stream_position)

            return new_request(
                uri, method, body=body, headers=None,
                redirections=redirections, connection_type=connection_type,
                _credential_refresh_attempt=_credential_refresh_attempt+1)

        return resp, content

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
