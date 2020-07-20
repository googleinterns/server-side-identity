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


import json
import os

import pytest
import unittest.mock as mock

from gsi.verification import exceptions
from gsi import transport
from gsi.verification import verifiers


def make_request(status, data=None):
    response = mock.create_autospec(transport.Response, instance=True)
    response.status = status

    if data is not None:
        response.data = json.dumps(data).encode("utf-8")

    request = mock.create_autospec(transport.Request)
    request.return_value = response
    return request


def test__fetch_certs_success():
    certs = {"1": "cert"}
    request = make_request(200, certs)

    returned_certs = verifiers._fetch_certs(request, mock.sentinel.cert_url)

    request.assert_called_once_with(mock.sentinel.cert_url, method="GET")
    assert returned_certs == certs


def test__fetch_certs_failure():
    request = make_request(404)

    with pytest.raises(exceptions.TransportError):
        verifiers._fetch_certs(request, mock.sentinel.cert_url)

    request.assert_called_once_with(mock.sentinel.cert_url, method="GET")
    
    
def test_Verifier():
    token = mock.sentinel.token
    request = mock.sentinel.request
    client_ids = [mock.sentinel.audience]
    certs_url = mock.sentinel.certs_url
    
    verifier = verifiers.Verifier(
        token,
        request=request,
        client_ids=client_ids,
        certs_url=certs_url,
    )
    
    assert verifier.id_token == token
    assert verifier.request == request
    assert verifier.clients == client_ids
    assert verifier.certs_url == certs_url
    
    
def test_GoogleOauth2Verifier():
    token = mock.sentinel.token
    request = mock.sentinel.request
    client_ids = [mock.sentinel.audience]
    g_suite_hosted_domain = mock.sentinel.g_suite_hosted_domain
    certs_url = verifiers._GOOGLE_OAUTH2_CERTS_URL
    
    verifier = verifiers.GoogleOauth2Verifier(
        token,
        request=request,
        client_ids=client_ids,
        g_suite_hosted_domain=g_suite_hosted_domain,
    )
    
    assert verifier.id_token == token
    assert verifier.request == request
    assert verifier.clients == client_ids
    assert verifier.certs_url == certs_url
    assert verifier.g_suite == g_suite_hosted_domain

    
def test_DecodedToken():
    token = {"key": "value", "key2": "value2"}
    decoded = verifiers.DecodedToken(token)
    
    assert decoded["key"] == "value"
    assert decoded["key2"] == "value2"
    assert decoded["missing key"] is None
    

def test_GoogleDecodedToken():
    decoded_id_token = {"iss": "issuer",
                        "hd": "hosted domain",
                        "name": "Joe Sample",
                        "given_name": "Joe",
                        "family_name": "Sample",
                        "email": "joe.sample@example.com",
                        "picture": "https://example.com/picture",
                        "sub": "000000001",
                        "locale": "en",
                        "aud": "CLIENT_ID",
                        "iat": "issue time",
                        "exp": "expire time",
                        "other key": "other value"}
    
    decoded = verifiers.GoogleDecodedToken(decoded_id_token)
    
    assert decoded.get_token_issuer() == "issuer"
    assert decoded.get_g_suite_hosted_domain() == "hosted domain"
    assert decoded.get_name() == "Joe Sample"
    assert decoded.get_given_name() == "Joe"
    assert decoded.get_family_name() == "Sample"
    assert decoded.get_email() == "joe.sample@example.com"
    assert decoded.get_picture_url() == "https://example.com/picture"
    assert decoded.get_user_identifier() == "000000001"
    assert decoded.get_user_locale() == "en"
    assert decoded.get_audience() == "CLIENT_ID"
    assert decoded.get_token_issue_time() == "issue time"
    assert decoded.get_token_expiration_time() == "expire time"
    assert decoded["other key"] == "other value"
    assert decoded["missing key"] is None


@mock.patch("gsi.verification.jwt.decode", autospec=True)
@mock.patch("gsi.verification.verifiers._fetch_certs", autospec=True)
def test__verify_token_payload(_fetch_certs, decode):
    verifier = verifiers.Verifier(mock.sentinel.token, request=mock.sentinel.request)
    result = verifier._verify_token_payload()

    assert result == decode.return_value
    _fetch_certs.assert_called_once_with(
        mock.sentinel.request, verifiers._GOOGLE_OAUTH2_CERTS_URL
    )
    decode.assert_called_once_with(
        mock.sentinel.token, certs=_fetch_certs.return_value, audience=None
    )


@mock.patch("gsi.verification.jwt.decode", autospec=True)
@mock.patch("gsi.verification.verifiers._fetch_certs", autospec=True)
def test__verify_token_payload_args(_fetch_certs, decode):
    verifier = verifiers.Verifier(
        mock.sentinel.token,
        request=mock.sentinel.request,
        client_ids=[mock.sentinel.audience],
        certs_url=mock.sentinel.certs_url,
    )
    result = verifier._verify_token_payload()

    assert result == decode.return_value
    _fetch_certs.assert_called_once_with(mock.sentinel.request, mock.sentinel.certs_url)
    decode.assert_called_once_with(
        mock.sentinel.token,
        certs=_fetch_certs.return_value,
        audience=[mock.sentinel.audience],
    )


@mock.patch("gsi.verification.jwt.decode", autospec=True)
@mock.patch("gsi.verification.verifiers._fetch_certs", autospec=True)
def test__verify_token_payload_GoogleOauth2Verifier(_fetch_certs, decode):
    verifier = verifiers.GoogleOauth2Verifier(
        mock.sentinel.token, 
        client_ids=[mock.sentinel.audience]
    )
    result = verifier._verify_token_payload()

    assert result == decode.return_value
    _fetch_certs.assert_called_once_with(verifier.request, verifiers._GOOGLE_OAUTH2_CERTS_URL)
    decode.assert_called_once_with(
        mock.sentinel.token,
        audience=[mock.sentinel.audience],
        certs=_fetch_certs.return_value,
    )

    
@mock.patch("gsi.verification.verifiers.Verifier._verify_token_payload", autospec=True)
def test_Verifier_verify_token(_verify_token_payload):
    _verify_token_payload.return_value = {"key": "value"}

    verifier = verifiers.Verifier(
        mock.sentinel.token,
        request=mock.sentinel.request,
        client_ids=[mock.sentinel.audience],
        certs_url=mock.sentinel.certs_url,
    )
    
    result = verifier.verify_token()
    
    assert result["key"] == "value"


@mock.patch("gsi.verification.verifiers.Verifier._verify_token_payload", autospec=True)
def test_GoogleOauth2Verifier_verify_token_valid_iss(_verify_token_payload):
    _verify_token_payload.return_value = {"iss": "accounts.google.com", "key": "value"}

    verifier = verifiers.GoogleOauth2Verifier(
        mock.sentinel.token, 
        client_ids=[mock.sentinel.audience]
    )
    
    result = verifier.verify_token()
    
    assert result["key"] == "value"
    
    
@mock.patch("gsi.verification.verifiers.Verifier._verify_token_payload", autospec=True)
def test_GoogleOauth2Verifier_verify_token_invalid_iss(_verify_token_payload):
    _verify_token_payload.return_value = {"iss": "invalid", "key": "value"}

    verifier = verifiers.GoogleOauth2Verifier(
        mock.sentinel.token, 
        client_ids=[mock.sentinel.audience]
    )
    
    with pytest.raises(exceptions.GoogleVerificationError):
        result = verifier.verify_token()
        


@mock.patch("gsi.verification.verifiers.Verifier._verify_token_payload", autospec=True)
def test_GoogleOauth2Verifier_verify_token_valid_hd(_verify_token_payload):
    _verify_token_payload.return_value = {"iss": "accounts.google.com", "key": "value", "hd": "domain"}

    verifier = verifiers.GoogleOauth2Verifier(
        mock.sentinel.token, 
        client_ids=[mock.sentinel.audience],
        g_suite_hosted_domain="domain"
    )
    
    result = verifier.verify_token()
    
    assert result["key"] == "value"
    
    
@mock.patch("gsi.verification.verifiers.Verifier._verify_token_payload", autospec=True)
def test_GoogleOauth2Verifier_verify_token_invalid_hd(_verify_token_payload):
    _verify_token_payload.return_value = {"iss": "accounts.google.com", "key": "value", "hd": "invalid"}

    verifier = verifiers.GoogleOauth2Verifier(
        mock.sentinel.token, 
        client_ids=[mock.sentinel.audience],
        g_suite_hosted_domain="domain"
    )
    
    with pytest.raises(exceptions.GoogleVerificationError):
        result = verifier.verify_token()

