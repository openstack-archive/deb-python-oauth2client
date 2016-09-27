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

import mock
import urllib3
import urllib3.exceptions

import oauth2client._transport.urllib3 as urllib3_transport
from tests.transport import transport_compliance


class TestUrllib3Transport(unittest.TestCase):
    def test_get_http_object(self):
        result = urllib3_transport.get_http_object()
        self.assertIsInstance(result, urllib3.poolmanager.PoolManager)

    def _make_authed_http(self):
        response = mock.Mock()
        response.status = 200
        http = mock.MagicMock()
        http.headers = {'default': 'header'}
        http.urlopen.return_value = response
        credentials = transport_compliance.MockCredentials('token')
        authed_http = urllib3_transport.make_authorized_http(
            http, credentials, ())

        return http, authed_http, response, credentials

    def test_authorized_http_urlopen_headers(self):
        http, authed_http, response, credentials = self._make_authed_http()

        result = authed_http.urlopen('GET', 'http://example.com')

        self.assertEqual(result, response)

        http.urlopen.assert_called_with(
            'GET',
            'http://example.com',
            body=None,
            headers={
                b'user-agent': b'test-credentials',
                b'default': b'header',
                b'authorization': b'Bearer token'})

    def test_authorized_http_proxies(self):
        http, authed_http, _, _ = self._make_authed_http()

        self.assertEqual(authed_http.http, http)
        self.assertEqual(authed_http.headers, http.headers)

        authed_http.headers = {'test': 'header'}
        self.assertEqual(http.headers, {'test': 'header'})

        # Text context manager usage
        with authed_http:
            pass

        self.assertTrue(http.__enter__.called)
        self.assertTrue(http.__exit__.called)

    def test_request_timeout(self):
        http = mock.Mock()

        urllib3_transport.request(http, 'http://example.com')
        assert http.request.called_with(
            'GET', 'http://example.com', body=None, headers=None)

        urllib3_transport.request(http, 'http://example.com', timeout=5)
        assert http.request.called_with(
            'GET', 'http://example.com', body=None, headers=None, timeout=5)


class TestUrllib3TransportCompliance(
        transport_compliance.TransportComplianceTests):
    transport = urllib3_transport
    exceptions = (urllib3.exceptions.HTTPError,)
