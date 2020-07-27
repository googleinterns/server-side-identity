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


import unittest.mock as mock
import pytest
import requests

import gsi.transport.request
from tests.transport import compliance


class TestRequestResponse(compliance.RequestResponseTests):
    def make_request(self):
        return gsi.transport.request.Request()
    
    def make_cached_request(self):
        return gsi.transport.request.CacheRequest()

    def test_timeout(self):
        http = mock.create_autospec(requests.Session, instance=True)
        request = gsi.transport.request.Request(http)
        request(url="http://example.com", method="GET", timeout=5)

        assert http.request.call_args[1]["timeout"] == 5

        