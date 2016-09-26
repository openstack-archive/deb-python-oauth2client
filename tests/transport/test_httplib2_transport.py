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
import mock

from oauth2client import transport
import oauth2client.transport.httplib2 as httplib2_transport
from tests import http_mock
from tests.transport import test_transport_compliance


class Test_get_http_object(unittest.TestCase):

    @mock.patch.object(httplib2, 'Http', return_value=object())
    def test_it(self, http_klass):
        result = httplib2_transport.get_http_object()
        self.assertEqual(result, http_klass.return_value)
        http_klass.assert_called_once_with()

    @mock.patch.object(httplib2, 'Http', return_value=object())
    def test_with_args(self, http_klass):
        result = httplib2_transport.get_http_object(1, 2, foo='bar')
        self.assertEqual(result, http_klass.return_value)
        http_klass.assert_called_once_with(1, 2, foo='bar')


class Test_make_authorized_http(unittest.TestCase):

    def test_wrap(self):
        credentials = object()
        http = mock.Mock()
        result = httplib2_transport.make_authorized_http(
            credentials, http, transport.REFRESH_STATUS_CODES)
        self.assertNotEqual(result, http)
        self.assertEqual(result.http, http)
        self.assertIs(result.credentials, credentials)


class Test_request(unittest.TestCase):
    def test_it(self):
        uri = 'http://localhost'
        method = 'POST'
        body = 'abc'
        redirections = 3
        mock_result = object()
        headers = {'foo': 'bar'}
        http = http_mock.HttpMock(headers=headers, data=mock_result)

        response = httplib2_transport.request(
            http, uri, method=method, body=body,
            redirections=redirections)
        self.assertEqual(response.headers, headers)
        self.assertIs(response.data, mock_result)
        # Verify mocks.
        self.assertEqual(http.requests, 1)
        self.assertEqual(http.uri, uri)
        self.assertEqual(http.method, method)
        self.assertEqual(http.body, body)
        self.assertIsNone(http.headers)


class TestHttplib2TransportCompliance(
        test_transport_compliance.TransportComplianceTests):
    transport = httplib2_transport
    exceptions = (httplib2.HttpLib2Error,)
