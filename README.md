# Google Identity Service Server-Side Integration Library

This library contains functionality necessary for the server-side integration of Google Sign In into third party web applications. The core functionality of this library accomplishes ID token verification routines necessary for the sign in of federated accounts in third party applications. This library is owned by Google Identity Service and is in the process of being finalized for public release.

## Download and installation
To download this library to your local machine, execute the following command in a terminal:
~~~
git clone https://github.com/sotremba/server-side-identity.git
~~~

To download the necessary dependencies for this library, cd into the server side identity directory and execute the following command:
~~~
pip install -r requirements.txt
~~~

## Common Use
The most common use for this library will be to verify identity tokens and begin the code logic necessary for proper user sign in through the GIS products. An example of this use case can be seen here:

~~~
from gsi.verification import verifiers
from gsi.verification import exceptions

#receive id_token from login endpoint

CLIENT_APP_IDS = [CLIENT_ID_1, CLIENT_ID_2] #CLIENT IDs of apps using this backend
G_SUITE_DOMAIN = DOMAIN_NAME #G Suite domain name for this app (optional)
verifier = verifiers.GoogleOauth2Verifier(client_ids=CLIENT_APP_IDS,
                                              g_suite_hosted_domain=G_SUITE_DOMAIN) #optional                                             

try:
    decoded_token = verifier.verify_token(id_token)
    #use decoded_token to complete user sign in

except (ValueError, exceptions.GoogleVerificationError):
    #invalid token, prompt user to try again
~~~


### Languages Planned to be Supported
We plan on expanding the collection of libraries to include more languages in the future

### Disclaimer
This is not an officially supported Google product.
