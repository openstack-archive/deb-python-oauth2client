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

import httplib2
import pytest
import urllib3

from oauth2client._transport import _transports
import oauth2client._transport.httplib2
import oauth2client._transport.urllib3


def test_get_preferred_http_object():
    assert isinstance(
        _transports.get_preferred_http_object(), httplib2.Http)


def test_transport_for_http_object():
    # Httplib2
    assert (
        _transports.transport_for_http_object(httplib2.Http()) ==
        oauth2client._transport.httplib2)

    # Urllib3
    assert (
        _transports.transport_for_http_object(urllib3.PoolManager()) ==
        oauth2client._transport.urllib3)

    # Unknown
    with pytest.raises(ValueError):
        _transports.transport_for_http_object(object())
