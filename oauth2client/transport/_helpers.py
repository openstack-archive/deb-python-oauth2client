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

import six

from oauth2client import _helpers


def initialize_headers(headers):
    """Creates a copy of the headers.

    Args:
        headers: dict, request headers to copy.

    Returns:
        dict, the copied headers or a new dictionary if the headers
        were None.
    """
    return {} if headers is None else dict(headers)


def apply_user_agent(headers, user_agent):
    """Adds a user-agent to the headers.

    Args:
        headers: dict, request headers to add / modify user
                 agent within.
        user_agent: str, the user agent to add.

    Returns:
        dict, the original headers passed in, but modified if the
        user agent is not None.
    """
    if user_agent is not None:
        if 'user-agent' in headers:
            headers['user-agent'] = '{} {}'.format(
                _helpers._from_bytes(user_agent), headers['user-agent'])
        else:
            headers['user-agent'] = user_agent

    return headers


def clean_headers(headers):
    """Forces header keys and values to be strings, i.e not unicode.

    The httplib module just concats the header keys and values in a way that
    may make the message header a unicode string, which, if it then tries to
    contatenate to a binary request body may result in a unicode decode error.

    Args:
        headers: dict, A dictionary of headers.

    Returns:
        The same dictionary but with all the keys converted to strings.
    """
    clean = {}
    try:
        for key, value in six.iteritems(headers):
            if not isinstance(key, six.binary_type):
                key = str(key)
            if not isinstance(value, six.binary_type):
                value = str(value)
            clean[_helpers._to_bytes(key)] = _helpers._to_bytes(value)
    except UnicodeEncodeError:
        from oauth2client.client import NonAsciiHeaderError
        raise NonAsciiHeaderError(key, ': ', value)
    return clean
