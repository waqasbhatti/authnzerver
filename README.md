This is a small server meant to to help add authentication (authn) and
authorization (authz) to other HTTP servers. It's built using
[Tornado](http://www.tornadoweb.org), [SQLAlchemy](https://www.sqlalchemy.org/),
[cryptography](https://cryptography.io),
[passlib](https://passlib.readthedocs.io/en/stable/),
[argon2-cffi](https://argon2-cffi.readthedocs.io/en/stable/), and
[python-diskcache](http://www.grantjenks.com/docs/diskcache/).

I wrote it to help with the login/logout/signup flows for the
[LCC-Server](https://github.com/waqasbhatti) and extracted much of the code from
there. It builds on the auth bits there and is eventually meant to replace
them. It can do the following things:

- handle user sign-ups, logins and logouts
- handle user email verification, password changes, and editing user properties
- handle access and rate-limit checks for (TBD) arbitrary schemes of user roles,
  permissions, and target objects
- handle API key verification
- (TBD) handle social logins using Twitter, Github, and Google

Authnzerver talks to a frontend server over HTTP. Communications are secured
with symmetric encryption using the [cryptography](https://cryptography.io)
package's [Fernet scheme](https://cryptography.io/en/latest/fernet/), so you'll
need a pre-shared key that both Authnzerver and your frontend server know.

You must provide the pre-shared key as an environmental variable:
`AUTHNZERVER_SECRETKEY` (highly recommended) or point to a file on disk
containing the key using the command-line option:
`--secretfile='/path/to/secret/key/file.txt'`.


## Installation

Authnzerver is [available at PyPI](https://pypi.org/project/authnzerver/). It
can be installed (preferably in a virtualenv) using `pip`:

```bash
(venv) $ pip install authnzerver  # use option --pre for unstable releases
```


## Configuring the server


### Environmental variables (recommended)

TBD.


### Command-line options

TBD.


## Running the server

TBD.


## HTTP API

All requests are composed of a Python dict containing request parameters. This
is encoded to JSON, encrypted with the pre-shared key, base64-encoded, and then
POSTed to the Authnzerver. The response is a base64-encoded string that must be
base64-decoded, decrypted, and deserialized from JSON into a dict.

A request is of the form:

```python
{'request': one of the request names below,
 'body': a dict containing the arguments for the request,
 'reqid': any integer used to keep track of the request flow}
```

A response, when decrypted and deserialized to a dict, is of the form:

```python
{'success': True or False,
 'response': dict containing the response items based on the request,
 'messages': a list of str containing informative/warning/error messages}
```


### Session handling

- `session-new`: Create a new session.
- `session-exists`: Get info about an existing session.
- `session-delete`: Delete a session.
- `session-delete-userid`: Delete all sessions for a user ID.
- `session-setinfo`: Save extra info for an existing session.
- `user-login`: Perform a user login action.
- `user-logout`: Perform a user logout action.
- `user-passcheck`: Perform a user password check.

TBD: parameter details.


### User handling

- `user-new`: Create a new user.
- `user-changepass`: Change an existing user's password.
- `user-delete`: Delete an existing user.
- `user-list`: List all users' or a single user's properties.
- `user-edit`: Edit a user's properties.
- `user-resetpass`: Reset a user's password.
- `user-lock`: Lock out an existing user.

TBD: parameter details.


### Email actions

- `user-signup-email`: Send a verification email to a new user.
- `user-verify-email`: Send a verification email to a user for any sensitive
  operation.
- `user-forgotpass-email`: Send a verification email to a user who forgot their
  password.

TBD: parameter details.


### API key actions

- `apikey-new`: Create a new API key tied to a user ID.
- `apikey-verify`: Verify an API key.

TBD: parameter details.


### Request example

```python
import json
from base64 import b64encode
import random
from cryptography.fernet import Fernet
import requests

FERNET_KEY = "SHARED_SECRET_KEY"

def encrypt_request(request_dict, fernetkey):
    '''
    This encrypts the outgoing request to authnzerver.

    '''

    frn = Fernet(fernetkey)
    json_bytes = json.dumps(request_dict).encode()
    json_encrypted_bytes = frn.encrypt(json_bytes)
    request_base64 = b64encode(json_encrypted_bytes)
    return request_base64


# generate random request ID
reqid = random.randint(0,10000)

# this is the request that will be sent to the authnzerver
req = {'request':request_type,
       'body':request_body,
       'reqid':reqid}

# encrypt the request
encrypted_request = encrypt_request(req, FERNET_KEY)

# send the request and get the response
response = requests.post('http://127.0.0.1:13431',data=encrypted_request)
```


### Response example

```python
import json
from base64 import b64decode
from cryptography.fernet import Fernet, InvalidToken

FERNET_KEY = "SHARED_SECRET_KEY"

def decrypt_response(response_base64, fernetkey):
    '''
    This decrypts the incoming response from authnzerver.

    '''

    frn = Fernet(fernetkey)

    try:

        response_bytes = b64decode(response_base64)
        decrypted = frn.decrypt(response_bytes)
        return json.loads(decrypted)

    except InvalidToken:

        print('invalid response could not be decrypted')
        return None

    except Exception as e:

        print('could not understand incoming response')
        return None


# decrypt the response
decrypted_response_dict = decrypt_response(response,
```


## License

Authnzerver is provided under the MIT License. See the LICENSE file for details.
