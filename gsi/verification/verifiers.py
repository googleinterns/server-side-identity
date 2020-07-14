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
    
    def _verify_token_payload(self):
        """
        Verifies the stored ID Token and returns it's payload in a hashmap form.

        Returns:
            Mapping[str, Any]: The decoded token payload.
        """
        certs = _fetch_certs(self.request, self.certs_url)
        return jwt.decode(self.id_token, certs=certs, audience=self.clients)
        
    def verify_token(self):
        """
        Verifies the stored ID Token and returns a DecodedToken object.

        Returns:
            DecodedToken: The decoded token.
        """        
        user_info = self._verify_token_payload()
        
        decoded = DecodedToken(user_info)
        return decoded
        

class GoogleOauth2Verifier(Verifier):
    """Verifies an ID Token issued by Google's OAuth 2.0 authorization server"""
    
    def __init__(self, id_token, client_ids=None, g_suite_hosted_domain=None, request=request.Request()):
        """
        Args:
            id_token (Union[str, bytes]): The encoded token.
            
            client_ids (list[str]): List of CLIENT_ID values of all audiences that use this backend. If None,
                then the audience is not verified.
            
            g_suite_domain (str): The name of the G Suite domain owned by the client. Used to ensure that the user from the ID
                Token is a member of the domain. If None, this field is not verified
        """
        super().__init__(id_token, client_ids, request=request,
                certs_url=_GOOGLE_OAUTH2_CERTS_URL) #uses OAuth2 url
        
        self.g_suite = g_suite_hosted_domain

        
    def verify_token(self):
        """
        Verifies the stored Google issued ID Token and returns a GoogleDecodedToken object.

        Returns:
            GoogleDecodedToken: The decoded Google issued token.
        """
        user_info = super()._verify_token_payload()
        decoded_token = GoogleDecodedToken(user_info)
        
        if self.g_suite is not None:
            if self.g_suite != decoded_token.get_g_suite_hosted_domain():
                raise exceptions.GoogleVerificationError(
                "Wrong G Suite Domain. 'hd' (hosted domain) should be {}, it but was {}".format(
                    self.g_suite, decoded_token.get_g_suite_hosted_domain())
                )
                
        if decoded_token.get_token_issuer() is None:
            raise exceptions.GoogleVerificationError(
                "The decoded token did not contain an 'iss' issuer field. This token is invalid."
            )
            
        elif decoded_token.get_token_issuer() not in _GOOGLE_ISSUERS:
            raise exceptions.GoogleVerificationError(
                "Wrong issuer. 'iss' (issuer) should be one of the following {}, it but was {}".format(
                    _GOOGLE_ISSUERS, decoded_token.get_token_issuer())
            )
        
        return decoded_token


class DecodedToken(object):
    """
    Holds decoded ID Token information and allows for indexing into the token's key-value pairs
    """
    
    def __init__(self, payload):
        """
        Args:
            payload (Mapping[str, Any]): The decoded token payload.
        """
        self.token = payload
    
    def __getitem__(self, key):
        """
        Args:
            key (str): The key used to index into the token payload.
        
        Returns:
            Any: The value associated with 'key'. If None, then then 'key' was not present in the
                token payload keys.
        """
        try:
            value = self.token[key]
            return value
        except KeyError:
            return None


class GoogleDecodedToken(DecodedToken):
    """
    Holds decoded Google OAuth 2.0 ID Token information and allows for indexing into 
    the token's key-value pairs. Provided getter methods for commonly required user information.
    Proviedes __getitem__ functionality to index key-value pairs not covered by getter methods.
    """
    
    def __init__(self, payload):
        """
        Args:
            payload (Mapping[str, Any]): The decoded token payload.
        """
        super().__init__(payload)
    
    def get_token_issuer(self):
        """
        Returns:
            Any: The issuer of the decoded ID Token. Should be "accounts.google.com" or 
                https://accounts.google.com" if the token was issued by Google OAuth 2.0
        """
        return self['iss']
    
    def get_g_suite_hosted_domain(self):
        """
        Returns:
            Any: The hosted domain of the user from the ID Token.
        """
        return self.token['hd']
    
    def get_name(self):
        """
        Returns:
            Any: The full name of the user from the ID Token.
        """
        return self['name']
    
    def get_given_name(self):
        """
        Returns:
            Any: The first/given name of the user from the ID Token.
        """
        return self['given_name']
    
    def get_family_name(self):
        """
        Returns:
            Any: The last/family name of the user from the ID Token.
        """
        return self['family_name']
    
    def get_email(self):
        """
        Returns:
            Any: The email name of the user from the ID Token.
        """
        return self['email']
    
    def get_picture_url(self):
        """
        Returns:
            Any: The url of the user's Google photo. 
        """
        return self['picture']
    
    def get_user_identifier(self):
        """
        Returns:
            Any: The Goolge-issued unique identifier number of the user. 
        """
        return self['sub']
    
    def get_user_locale(self):
        """
        Returns:
            Any: The locale of the user from the ID Token.
        """
        return self['locale']
    
    def get_audience(self):
        """
        Returns:
            Any: The intended audience of the ID Token (i.e. the CLIENT_ID of the application requesting
                user account access)
        """
        return self['aud']
    
    def get_token_issue_time(self):
        """
        Returns:
            Any: The time at which the ID Token was issued
        """
        return self['iat']
    
    def get_token_expiration_time(self):
        """
        Returns:
            Any: The time at which the ID Token will expire
        """
        return self['exp']
        
    