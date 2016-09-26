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

import json

import flask
import pytest
from pytest_localserver.http import WSGIServer
from six.moves import http_client


# .invalid will never resolve, see https://tools.ietf.org/html/rfc2606
NXDOMAIN = 'test.invalid'


def test_server_app():
    """A basic WSGI app that exposes methods for testing http requests."""
    app = flask.Flask(__name__)

    @app.route('/basic')
    def index():
        return 'Basic Content', http_client.OK, {'X-Test-Header': 'value'}

    @app.route('/server_error')
    def server_error():
        return 'Error', http_client.INTERNAL_SERVER_ERROR

    @app.route('/authorized')
    def authorized():
        """Echoes the request auth and user agent headers."""
        return flask.jsonify({
            'authorization': flask.request.headers.get('authorization'),
            'user_agent': flask.request.headers.get('user-agent'),
        })

    @app.route('/authorized_refresh')
    def authorized_refresh():
        """Returns UNAUTHORIZED if the request token doesn't contain
        '-new', otherwise returns the auth and user agent headers."""
        authorization = flask.request.headers.get('authorization', '')

        if '-new' not in authorization:
            return 'Not authorized', http_client.UNAUTHORIZED

        return flask.jsonify({
            'authorization': flask.request.headers.get('authorization'),
            'user_agent': flask.request.headers.get('user-agent'),
        })

    return app.wsgi_app


class MockCredentials(object):
    def __init__(self, token):
        self.token = token
        self.user_agent = 'test-credentials'

    def _before_request(self, http, uri, headers):
        headers[b'authorization'] = 'Bearer {}'.format(self.token)

    def refresh(self, http):
        self.token = '{}{}'.format(self.token, '-new')


class TransportComplianceTests(object):
    """Test base class to confirm that a transport satisfies the interface
    expected by oauth2client."""
    transport = None
    exceptions = None

    @pytest.fixture(autouse=True)
    def testserver(self):
        """Provides a test HTTP server that is automatically created before
        a test and destroyed at the end. This server is running the test
        app defined above."""
        server = WSGIServer(application=test_server_app())
        server.start()
        self.server = server
        yield
        server.stop()

    def test_request_basic(self):
        http = self.transport.get_http_object()
        response = self.transport.request(
            http, self.server.url + '/basic')

        assert response.status == http_client.OK
        assert response.headers['x-test-header'] == 'value'
        assert response.data == b'Basic Content'

    def test_request_error(self):
        http = self.transport.get_http_object()
        response = self.transport.request(
            http, self.server.url + '/server_error')

        assert response.status == http_client.INTERNAL_SERVER_ERROR
        assert response.data == b'Error'

    def test_connection_error(self):
        http = self.transport.get_http_object()

        with pytest.raises(self.exceptions):
            self.transport.request(
                http, 'http://{}'.format(NXDOMAIN))

    def test_authorized_http(self):
        credentials = MockCredentials('token')
        http = self.transport.get_http_object()
        authed_http = self.transport.make_authorized_http(
            credentials, http, (http_client.UNAUTHORIZED,))

        # Use transport.request instead of authed_http request because this
        # has to work across multiple transports - the http object is
        # essentially opaque to these tests.
        response = self.transport.request(
            authed_http, self.server.url + '/authorized')

        content = json.loads(response.data.decode('utf-8'))

        assert credentials.token == 'token'
        assert content['authorization'] == 'Bearer token'
        assert content['user_agent'] == credentials.user_agent

    def test_authorized_http_refresh(self):
        credentials = MockCredentials('token')
        http = self.transport.get_http_object()
        authed_http = self.transport.make_authorized_http(
            credentials, http, (http_client.UNAUTHORIZED,))

        # Use transport.request instead of authed_http request because this
        # has to work across multiple transports - the http object is
        # essentially opaque to these tests.
        response = self.transport.request(
            authed_http, self.server.url + '/authorized_refresh')

        content = json.loads(response.data.decode('utf-8'))

        assert credentials.token == 'token-new'
        assert content['authorization'] == 'Bearer token-new'
        assert content['user_agent'] == credentials.user_agent
