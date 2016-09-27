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

# The set of available transports, in order of preference.
# WARNING: Every call to transport.request is O(n) on the number of
# transport http object classes. Be cautious when adding new transports
# and try to reduce the number of http object classes to one if at all
# possible.
_TRANSPORTS = ()

try:
    from oauth2client._transport import httplib2
    _TRANSPORTS += (httplib2,)
except ImportError:  # pragma: NO COVER
    httplib2 = None

try:
    from oauth2client._transport import urllib3
    _TRANSPORTS += (urllib3,)
except ImportError:  # pragma: NO COVER
    urllib3 = None

if not _TRANSPORTS:  # pragma: NO COVER
    raise ImportError(
        'No HTTP transports are available for oauth2client. Please install '
        'urllib3 or httplib2.')

# The transports are imported and added in order of preference. The first
# available one is the preferred transport.
# The concept of a preferred transport is only used when an http object is
# explicitly not specified. In that case, we need to use whatever transport
# is available to make the http request.
# This is presently only used by oauth2client.client._detect_gce_environment,
# and great care should be made to prevent other uses of this.
PREFERRED_TRANSPORT = _TRANSPORTS[0]


def get_preferred_http_object(*args, **kwargs):
    """Returns an instance of preferred transport's http object."""
    return PREFERRED_TRANSPORT.get_http_object(*args, **kwargs)


def transport_for_http_object(http_object):
    """Returns the transport module for a given HTTP object.

    Args:
        http_object (Any): The HTTP object.

    Returns:
        module: A transport module.

    Raises:
        ValueError: if no transport can be found for the object.
    """
    for transport in _TRANSPORTS:
        if isinstance(http_object, transport.HTTP_OBJECT_CLASSES):
            return transport
    raise ValueError('No transport found for {}.'.format(http_object))
