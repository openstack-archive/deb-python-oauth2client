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


class TestMemoryCache(unittest.TestCase):

    def test_get_set_delete(self):
        cache = httplib2_transport.MemoryCache()
        self.assertIsNone(cache.get('foo'))
        self.assertIsNone(cache.delete('foo'))
        cache.set('foo', 'bar')
        self.assertEqual('bar', cache.get('foo'))
        cache.delete('foo')
        self.assertIsNone(cache.get('foo'))


class Test_get_cached_http(unittest.TestCase):

    def test_global(self):
        cached_http = httplib2_transport.get_cached_http()
        self.assertIsInstance(cached_http, httplib2.Http)
        self.assertIsInstance(
            cached_http.cache, httplib2_transport.MemoryCache)

    def test_value(self):
        cache = object()
        patch = mock.patch(
            'oauth2client.transport.httplib2.get_cached_http',
            return_value=cache)
        with patch:
            result = httplib2_transport.get_cached_http()
        self.assertIs(result, cache)


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


class Test_inject_credentials(unittest.TestCase):

    def test_wrap(self):
        credentials = object()
        http = mock.Mock()
        http.request = orig_req_method = object()
        result = httplib2_transport.inject_credentials(
            credentials, http, transport.REFRESH_STATUS_CODES)
        self.assertIsNone(result)
        self.assertNotEqual(http.request, orig_req_method)
        self.assertIs(http.request.credentials, credentials)


class Test_request(unittest.TestCase):

    uri = 'http://localhost'
    method = 'POST'
    body = 'abc'
    redirections = 3

    def test_with_request_attr(self):
        mock_result = object()
        headers = {'foo': 'bar'}
        http = http_mock.HttpMock(headers=headers, data=mock_result)

        response, content = httplib2_transport.request(
            http, self.uri, method=self.method, body=self.body,
            redirections=self.redirections)
        self.assertEqual(response, headers)
        self.assertIs(content, mock_result)
        # Verify mocks.
        self.assertEqual(http.requests, 1)
        self.assertEqual(http.uri, self.uri)
        self.assertEqual(http.method, self.method)
        self.assertEqual(http.body, self.body)
        self.assertIsNone(http.headers)

    def test_with_callable_http(self):
        headers = {}
        mock_result = object()
        http = http_mock.HttpMock(headers=headers, data=mock_result)

        result = httplib2_transport.request(
            http, self.uri, method=self.method,
            body=self.body, redirections=self.redirections)
        self.assertEqual(result, (headers, mock_result))
        # Verify mock.
        self.assertEqual(http.requests, 1)
        self.assertEqual(http.uri, self.uri)
        self.assertEqual(http.method, self.method)
        self.assertEqual(http.body, self.body)
        self.assertIsNone(http.headers)
        self.assertEqual(http.redirections, self.redirections)
