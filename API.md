This page describes the API of the Authnzerver.

All requests are composed of a Python dict containing request parameters. This
is encoded to JSON, encrypted with the pre-shared key, base64-encoded, and then
POSTed to the Authnzerver. The response is a base64-encoded string that must be
base64-decoded, decrypted, and deserialized from JSON into a dict.

A request is of the form:

```
{'request': one of the request names below,
 'body': a dict containing the arguments for the request,
 'reqid': any integer used to keep track of the request flow}
```

A response, when decrypted and deserialized to a dict, is of the form:

```
{'success': True or False,
 'response': dict containing the response items based on the request,
 'messages': a list of str containing informative/warning/error messages}
```

# Session handling

## `session-new`: Create a new session

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `session-exists`: Get info about an existing session

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `session-delete`: Delete a session

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `session-delete-userid`: Delete all sessions for a user ID

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `session-setinfo`: Save extra info for an existing session

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `user-login`: Perform a user login action

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `user-logout`: Perform a user logout action

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `user-passcheck`: Perform a user password check

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires


# User handling

## `user-new`: Create a new user

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `user-changepass`: Change an existing user's password

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `user-delete`: Delete an existing user

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `user-list`: List all users' or a single user's properties

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `user-edit`: Edit a user's properties

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `user-resetpass`: Reset a user's password

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `user-lock`: Lock out an existing user

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires


# Email actions

## `user-signup-email`: Send a verification email to a new user

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `user-verify-email`: Send a verification email to a user for any sensitive operation

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `user-forgotpass-email`: Send a verification email to a user who forgot their password

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires


# API key actions

## `apikey-new`: Create a new API key tied to a user ID

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires

## `apikey-verify`: Verify an API key

Requires the following `body` items in a request:
- `ip_address` (str): the IP address of the client
- `user_agent` (str): the user agent of the client
- `user_id` (int): a user ID associated with the client
- `expires` (int): the number of days after which the token is invalid
- `extra_info_json` (dict): a dict containing arbitrary session associate information

Returns a `response` with the following items:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a datetime in ISO format indicating when the session expires


# Request example

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


# Response example

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
decrypted_response_dict = decrypt_response(response.text, FERNET_KEY)
```
