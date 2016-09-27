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

import unittest

import httplib2

import oauth2client._transport.httplib2 as httplib2_transport
from tests.transport import transport_compliance


class TestHttplib2Transport(unittest.TestCase):
    def test_get_http_object(self):
        result = httplib2_transport.get_http_object()
        self.assertIsInstance(result, httplib2.Http)


class TestHttplib2TransportCompliance(
        transport_compliance.TransportComplianceTests):
    transport = httplib2_transport
    exceptions = (httplib2.HttpLib2Error,)
