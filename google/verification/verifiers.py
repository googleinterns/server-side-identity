import json

from six.moves import http_client

#JWT Library
#Exceptions Library

# The URL that provides public certificates for verifying ID tokens issued
# by Google's OAuth 2.0 authorization server.
_GOOGLE_OAUTH2_CERTS_URL = 'https://www.googleapis.com/oauth2/v1/certs'

# The URL that provides public certificates for verifying ID tokens issued
# by Firebase and the Google APIs infrastructure
_GOOGLE_APIS_CERTS_URL = (
    'https://www.googleapis.com/robot/v1/metadata/x509'
    '/securetoken@system.gserviceaccount.com')


def _fetch_certs(request, certs_url):
    """
    Fetches public certificates at the given url.

    Google-style cerificate endpoints return JSON in the format of
    ``{'key id': 'x509 certificate'}``.

    Args:
        request (TODO: (Make new Request class) google.auth.transport.Request): The object used to make
            HTTP requests.
        certs_url (str): The certificate endpoint URL.

    Returns:
        Mapping[str, str]: A mapping of public key ID to x.509 certificate
            data.
    """
    response = request(certs_url, method='GET')

    if response.status != http_client.OK:
        #TODO: Implement custom exceptions
        raise NotImplementedError("Need to implement custom exceptions")

    return json.loads(response.data.decode('utf-8'))


class Verifier(object):
    """Verifies an ID token and returns the decoded token."""

    def __init__(self, id_token, request, client_ids=None,
            certs_url=_GOOGLE_OAUTH2_CERTS_URL):
        """
        Args:
            id_token (Union[str, bytes]): The encoded token.
            request (TODO: (Make new Request class) google.auth.transport.Request): The object used to make
                HTTP requests.
            client_ids (list[str]): List of CLIENT_ID values of all audiences that use this backend. If None,
                then the audience is not verified.
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

        #TODO: implement JWT decode functionality
        #self.verified_token = DecodedToken(self.id_token, certs, self.clients)
        #return DecodedToken(self.id_token, certs, self.clients)
        raise NotImplementedError("JWT DecodedToken needs to be implemented")
        

class Oauth2Verifier(Verifier):
    """Verifies an ID Token issued by Google's OAuth 2.0 authorization server"""
    
    def __init__(self, id_token, request, client_ids=None):
        """
        Args:
            id_token (Union[str, bytes]): The encoded token.
            request (TODO: (Make new Request class)google.auth.transport.Request): The object used to make
                HTTP requests.
            client_ids (list[str]): List of CLIENT_ID values of all audiences that use this backend. If None,
                then the audience is not verified.
            certs_url (str): The URL that specifies the certificates to use to
                verify the token. This URL should return JSON in the format of
                ``{'key id': 'x509 certificate'}``.
        """
        Verifier.__init__(id_token, request, client_ids,
                certs_url=_GOOGLE_OAUTH2_CERTS_URL) #uses OAuth2 url
        

class FirebaseVerifier(Verifier):
    """Verifies an ID Token issued by Firebase Authentication"""

    def __init__(self, id_token, request, client_ids=None):
        """
        Args:
            id_token (Union[str, bytes]): The encoded token.
            request (TODO: (Make new Request class)google.auth.transport.Request): The object used to make
                HTTP requests.
            client_ids (list[str]): List of CLIENT_ID values of all audiences that use this backend. If None,
                then the audience is not verified.
            certs_url (str): The URL that specifies the certificates to use to
                verify the token. This URL should return JSON in the format of
                ``{'key id': 'x509 certificate'}``.
        """
        Verifier.__init__(id_token, request, client_ids,
                certs_url=_GOOGLE_APIS_CERTS_URL) #uses Google APIs url

