This is a small server meant to to help add authentication (authn) and
authorization (authz) to other HTTP servers. It's built on top of the
[Tornado](http://www.tornadoweb.org), [SQLAlchemy](https://www.sqlalchemy.org/),
[PyCA Cryptography](https://cryptography.io),
[passlib](https://passlib.readthedocs.io/en/stable/),
[argon2-cffi](https://argon2-cffi.readthedocs.io/en/stable/), and the
[python-diskcache](http://www.grantjenks.com/docs/diskcache/) packages.

I wrote it to help with the login/logout/signup bits for the
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

Authnzerver is available at PyPI. It can be installed (preferably in a
virtualenv) using `pip`:

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


### Request structure

All requests use `content-type: text/plain; charset=UTF-8`.

TBD.

The following Python code generates a valid request:

```python
from cryptography.fernet import Fernet
import json
from base64 import b64encode
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

### Response structure

All responses are in `content-type: text/plain; charset=UTF-8`.

TBD.

The following code decrypts and interprets a response:


```python
from cryptography.fernet import Fernet, InvalidToken
import json
from base64 import b64decode

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


### Authnzerver API

TBD.


## License

MIT.
