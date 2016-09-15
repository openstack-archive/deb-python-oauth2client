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


def inject_credentials(
        http_object, credentials, refresh_status_code=REFRESH_STATUS_CODES):
    """Injects credentials into the given http object."""
    return get_default_transport().inject_credentials(
        http_object, credentials, refresh_status_codes=refresh_status_code)


def inject_assertion_credentials(
        http_object, credentials, refresh_status_code=REFRESH_STATUS_CODES):
    """Injects assertion-style credentials into the given http object."""
    # TODO: Consolidate with inject_credentials.
    return get_default_transport().inject_assertion_credentials(
        http_object, credentials, refresh_status_codes=refresh_status_code)


def request(http_object, uri, method='GET', body=None, headers=None, **kwargs):
    """Makes an HTTP request."""
    return get_default_transport().request(
        http_object, uri, method=method, body=body, headers=headers, **kwargs)
