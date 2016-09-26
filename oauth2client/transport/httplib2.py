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


class _AuthorizedHttp(object):
    """An httplib2.Http-like object that provides credentials to requests.

    A new class is used because you can't create a new OAuth subclass of
    httplib2.Authentication because it never gets passed the absolute URI,
    which is needed for signing. So instead we have to overload 'request'
    and add in the Authorization header and then calls the original
    version of :func:`request`.
    """
    def __init__(self, http, credentials, refresh_status_codes):
        self.http = http
        self.credentials = credentials
        self.refresh_status_codes = refresh_status_codes

    def request(self, uri, method='GET', body=None, headers=None,
                **kwargs):
        """Make an authenticated request, refreshing credentials as needed."""
        _credential_refresh_attempt = kwargs.pop(
            '_credential_refresh_attempt', 0)

        # Clone and modify the request headers to add the appropriate
        # Authorization header.
        headers = _helpers.initialize_headers(headers)
        _helpers.apply_user_agent(headers, self.credentials.user_agent)

        self.credentials._before_request(self.http, uri, headers)
        headers = _helpers.clean_headers(headers)

        body_stream_position = None
        # Check if the body is a file-like stream.
        if all(getattr(body, stream_prop, None) for stream_prop in
               _STREAM_PROPERTIES):
            body_stream_position = body.tell()

        response, content = self.http.request(
            uri, method, body, headers, **kwargs)

        # If the response indicated that the credentials needed to be
        # refreshed, then refresh the credentials and re-attempt the
        # request.
        # A stored token may expire between the time it is retrieved and
        # the time the request is made, so we may need to try twice.
        if (response.status in self.refresh_status_codes
                and _credential_refresh_attempt < _MAX_REFRESH_ATTEMPTS):

            _LOGGER.info(
                'Refreshing due to a %s (attempt %s/%s)',
                response.status, _credential_refresh_attempt + 1,
                _MAX_REFRESH_ATTEMPTS)

            self.credentials.refresh(self.http)

            # Remove the existing Authorization header, as the credentials
            # may set the header as u'Authorization' but clean_headers set it
            # as b'Authorization'.
            headers.pop(b'Authorization', None)

            if body_stream_position is not None:
                body.seek(body_stream_position)

            # To iterate is human, to recurse, divine.
            return self.request(
                uri, method, body=body, headers=None,
                _credential_refresh_attempt=_credential_refresh_attempt + 1,
                **kwargs)

        return response, content


def make_authorized_http(credentials, http, refresh_status_codes):
    """Creates an http object that provides credentials to requests.

    The behavior is transport-specific, but all transports will return a new
    http object that provides credentials to requests and refreshed credentials
    when a response in REFRESH_STATUS_CODES is received.

    Args:
        credentials: An instance of
            :class:`~oauth2client.client.OAuth2Credentials`.
        http: The http object to wrap.
        refresh_status_codes: A sequence of status codes that indicate that
            credentials should be refreshed and the request retried.

    Returns:
        A new http object that provides credentials to requests.
    """
    return _AuthorizedHttp(http, credentials, refresh_status_codes)


class _ResponseWrapper(object):
    """HTTP response value wrapper

    Wraps httplib2's response and response body into an object that
    satisifies the return value indicated by
    :meth:`oauth2client.transport.request`.
    """

    def __init__(self, httplib2_response, data):
        # httplib2's response object acts as a dictionary.
        self.headers = httplib2_response
        self.data = data
        self.status = httplib2_response.status


def request(http, uri, method='GET', body=None, headers=None, **kwargs):
    """Make an HTTP request with an HTTP object and arguments.

    The arguments match :func:`oauth2client.transport.request`. Additional
    arguments are passed through to :meth:`httplib2.Http.request`.

    Returns:
        An instance of :class:`_ResponseWrapper`.
    """
    response, data = http.request(
        uri, method=method, body=body, headers=headers, **kwargs)

    return _ResponseWrapper(response, data)
