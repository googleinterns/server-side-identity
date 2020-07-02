import json

from six.moves import http_client

from gsi.transport import request
from gsi.verification import exceptions
from gsi.verification import jwt

# The URL that provides public certificates for verifying ID tokens issued
# by Google's OAuth 2.0 authorization server.
_GOOGLE_OAUTH2_CERTS_URL = 'https://www.googleapis.com/oauth2/v1/certs'

_GOOGLE_ISSUERS = ["accounts.google.com", "https://accounts.google.com"]


def _fetch_certs(request, certs_url):
    """
    Fetches public certificates at the given url.

    Google-style cerificate endpoints return JSON in the format of
    ``{'key id': 'x509 certificate'}``.

    Args:
        request (gsi.transport.Request): The object used to make
            HTTP requests.
        certs_url (str): The certificate endpoint URL.

    Returns:
        Mapping[str, str]: A mapping of public key ID to x.509 certificate
            data.
    """
    response = request(certs_url, method='GET')

    if response.status != http_client.OK:
        raise exceptions.TransportError(
            "Could not fetch certificates at {}".format(certs_url)
        )

    return json.loads(response.data.decode('utf-8'))


class Verifier(object):
    """Verifies an ID token and returns the decoded token."""

    def __init__(self, id_token, client_ids=None, request=request.Request(),
            certs_url=_GOOGLE_OAUTH2_CERTS_URL):
        """
        Args:
            id_token (Union[str, bytes]): The encoded token.
            client_ids (list[str]): List of CLIENT_ID values of all audiences that use this backend. If None,
                then the audience is not verified.
            request (gsi.transport.Request): The object used to make
                HTTP requests.
            certs_url (str): The URL that specifies the certificates to use to
                verify the token. This URL should return JSON in the format of
                ``{'key id': 'x509 certificate'}``.
        """
        self.id_token = id_token
        self.request = request
        self.clients = client_ids
        self.certs_url = certs_url
        self.verified_token = None
        
    def verify_token(self):
        """
        Verifies the stored ID Token and returns a DecodedToken object.

        Returns:
            DecodedToken: The decoded token.
        """
        if self.verified_token:
            return self.verified_token
        
        certs = _fetch_certs(self.request, self.certs_url)
        
        user_info = jwt.decode(id_token, certs=certs, audience=audience)
        if user_info["iss"] not in _GOOGLE_ISSUERS:
            raise exceptions.GoogleVerificationError(
                "Wrong issuer. 'iss' should be one of the following: {}".format(
                    _GOOGLE_ISSUERS
                )
            )
            
        #TODO: implement DecodedToken class
        #decoded = DecodedToken(user_info)
        #self.verified_token = decoded
        #return decoded
        raise NotImplementedError("JWT DecodedToken needs to be implemented")
        

class Oauth2Verifier(Verifier):
    """Verifies an ID Token issued by Google's OAuth 2.0 authorization server"""
    
    def __init__(self, id_token, client_ids=None):
        """
        Args:
            id_token (Union[str, bytes]): The encoded token.
            client_ids (list[str]): List of CLIENT_ID values of all audiences that use this backend. If None,
                then the audience is not verified.
            request (gsi.transport.Request): The object used to make
                HTTP requests.
            certs_url (str): The URL that specifies the certificates to use to
                verify the token. This URL should return JSON in the format of
                ``{'key id': 'x509 certificate'}``.
        """
        Verifier.__init__(id_token, client_ids, request=request.Request(),
                certs_url=_GOOGLE_OAUTH2_CERTS_URL) #uses OAuth2 url
