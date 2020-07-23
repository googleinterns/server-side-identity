# Copyright 2016 Google LLC
# Modifications: Copyright 2020 Google LLC
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

import datetime
import flask
import pytest
import time

from freezegun import freeze_time
from pytest_localserver.http import WSGIServer
from six.moves import http_client

from gsi.verification import exceptions

# .invalid will never resolve, see https://tools.ietf.org/html/rfc2606
NXDOMAIN = "test.invalid"

_SLEEP_TIME = 5
_MAX_AGE = 10

def sleepless(seconds, frozen_time):
    """
    Function for simulating the time.sleep() method using a freezegun frozen datetime
    Instead of really sleeping, just move frozen time forward
    """
    delta = datetime.timedelta(seconds=seconds)
    frozen_time.tick(delta)


class RequestResponseTests(object):
    @pytest.fixture(scope="module")
    def server(self):
        """Provides a test HTTP server.

        The test server is automatically created before
        a test and destroyed at the end. The server is serving a test
        application that can be used to verify requests.
        """
        app = flask.Flask(__name__)
        app.debug = True

        # pylint: disable=unused-variable
        # (pylint thinks the flask routes are unusued.)
        @app.route("/basic")
        def index():
            header_value = flask.request.headers.get("x-test-header", "value")
            headers = {"X-Test-Header": header_value}
            return "Basic Content", http_client.OK, headers
        
        @app.route("/cache")
        def cached():
            header_value = flask.request.headers.get("x-test-header", "value")
            headers = {"X-Test-Header": header_value, "Time": time.time(), "Cache-Control": "public, max-age={}".format(_MAX_AGE)}
            return "Cache Content", http_client.OK, headers

        @app.route("/server_error")
        def server_error():
            return "Error", http_client.INTERNAL_SERVER_ERROR

        @app.route("/wait")
        def wait():
            time.sleep(_SLEEP_TIME)
            return "Waited"

        # pylint: enable=unused-variable

        server = WSGIServer(application=app.wsgi_app)
        server.start()
        yield server
        server.stop()

    def test_request_basic(self, server):
        request = self.make_request()
        response = request(url=server.url + "/basic", method="GET")

        assert response.status == http_client.OK
        assert response.headers["x-test-header"] == "value"
        assert response.data == b"Basic Content"

    def test_request_with_timeout_success(self, server):
        request = self.make_request()
        response = request(url=server.url + "/basic", method="GET", timeout=2)

        assert response.status == http_client.OK
        assert response.headers["x-test-header"] == "value"
        assert response.data == b"Basic Content"

    def test_request_with_timeout_failure(self, server):
        request = self.make_request()

        with pytest.raises(exceptions.TransportError):
            request(url=server.url + "/wait", method="GET", timeout=1)

    def test_request_headers(self, server):
        request = self.make_request()
        response = request(
            url=server.url + "/basic",
            method="GET",
            headers={"x-test-header": "hello world"},
        )

        assert response.status == http_client.OK
        assert response.headers["x-test-header"] == "hello world"
        assert response.data == b"Basic Content"

    def test_request_error(self, server):
        request = self.make_request()
        response = request(url=server.url + "/server_error", method="GET")

        assert response.status == http_client.INTERNAL_SERVER_ERROR
        assert response.data == b"Error"

    def test_connection_error(self):
        request = self.make_request()
        with pytest.raises(exceptions.TransportError):
            request(url="http://{}".format(NXDOMAIN), method="GET")

    def test_cached_request(self, server, monkeypatch):
        with freeze_time("2000-01-01 00:00:00") as frozen_datetime:
            request = self.make_cached_request()
            response = request(url=server.url + "/cache", method="GET")
            request_time = response.headers.get("Time")
            
            monkeypatch.setattr(time, 'sleep', sleepless)
            time.sleep(_SLEEP_TIME, frozen_datetime)

            new_response = request(url=server.url + "/cache", method="GET")
            new_time = new_response.headers.get("Time")

            assert request_time == new_time, "{} and {} are not equal".format(request_time, new_time)
    
    def test_expired_cached_request(self, server, monkeypatch):
        with freeze_time("2000-01-01 00:00:00") as frozen_datetime:
            request = self.make_cached_request()
            response = request(url=server.url + "/cache", method="GET")
            request_time = response.headers.get("Time")
            
            monkeypatch.setattr(time, 'sleep', sleepless)
            time.sleep(_MAX_AGE + _SLEEP_TIME, frozen_datetime)

            new_response = request(url=server.url + "/cache", method="GET")
            new_time = new_response.headers.get("Time")

            assert request_time != new_time, "{} and {} are equal when they should be different".format(request_time, new_time)
