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

from oauth2client import client
from oauth2client._transport import _helpers


class Test_initialize_headers(unittest.TestCase):

    def test_null(self):
        result = _helpers.initialize_headers(None)
        self.assertEqual(result, {})

    def test_copy(self):
        headers = {'a': 1, 'b': 2}
        result = _helpers.initialize_headers(headers)
        self.assertEqual(result, headers)
        self.assertIsNot(result, headers)


class Test_apply_user_agent(unittest.TestCase):

    def test_null(self):
        headers = object()
        result = _helpers.apply_user_agent(headers, None)
        self.assertIs(result, headers)

    def test_new_agent(self):
        headers = {}
        user_agent = 'foo'
        result = _helpers.apply_user_agent(headers, user_agent)
        self.assertIs(result, headers)
        self.assertEqual(result, {'user-agent': user_agent})

    def test_append(self):
        orig_agent = 'bar'
        headers = {'user-agent': orig_agent}
        user_agent = 'baz'
        result = _helpers.apply_user_agent(headers, user_agent)
        self.assertIs(result, headers)
        final_agent = user_agent + ' ' + orig_agent
        self.assertEqual(result, {'user-agent': final_agent})


class Test_clean_headers(unittest.TestCase):

    def test_no_modify(self):
        headers = {b'key': b'val'}
        result = _helpers.clean_headers(headers)
        self.assertIsNot(result, headers)
        self.assertEqual(result, headers)

    def test_cast_unicode(self):
        headers = {u'key': u'val'}
        header_bytes = {b'key': b'val'}
        result = _helpers.clean_headers(headers)
        self.assertIsNot(result, headers)
        self.assertEqual(result, header_bytes)

    def test_unicode_failure(self):
        headers = {u'key': u'\u2603'}
        with self.assertRaises(client.NonAsciiHeaderError):
            _helpers.clean_headers(headers)

    def test_cast_object(self):
        headers = {b'key': True}
        header_str = {b'key': b'True'}
        result = _helpers.clean_headers(headers)
        self.assertIsNot(result, headers)
        self.assertEqual(result, header_str)
