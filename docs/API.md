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
- `extra_info_json` (dict): a dict containing arbitrary session associated
  information

Returns a `response` with the following items if successful:
- `session_token` (str): a session token suitable for use in a session cookie
- `expires` (str): a UTC datetime in ISO format indicating when the session
  expires

## `session-exists`: Get info about an existing session

Requires the following `body` items in a request:
- `session_token` (str): the session token to check

Returns a `response` with the following items if successful:
- `session_info` (dict): a dict containing session info if it exists,
  None otherwise

## `session-delete`: Delete a session

Requires the following `body` items in a request:
- `session_token` (str): the session token to delete

Returns a `response` with the following items:
- None. Check the `success` item in the returned dict.

## `session-delete-userid`: Delete all sessions for a user ID

Requires the following `body` items in a request:
- `session_token` (str): the current session token
- `user_id` (int): a user ID associated with the client
- `keep_current_session` (bool): whether to keep the currently logged-in session

Returns a `response` with the following items:
- None. Check the `success` item in the returned dict.

## `session-setinfo`: Save extra info for an existing session

Requires the following `body` items in a request:
- `session_token` (str): the session token to update
- `extra_info_json` (dict): a dict containing arbitrary session associated
  information

Returns a `response` with the following items if successful:
- `session_info` (dict): all session related information

## `user-login`: Perform a user login action

Requires the following `body` items in a request:
- `session_token` (str): the session token associated with the `user_id`
- `email` (str): the email address associated with the `user_id`
- `password` (str): the password associated with the `user_id`

Returns a `response` with the following items if successful:
- `user_id` (int): a user ID associated with the logged-in user or None if login
  failed.

## `user-logout`: Perform a user logout action

Requires the following `body` items in a request:
- `user_id` (int): a user ID associated with the logged-in user or None if login
  failed.
- `session_token` (str): the session token associated with the `user_id`

Returns a `response` with the following items if successful:
- `user_id` (int): a user ID associated with the logged-in user or None if
  logout failed.

## `user-passcheck`: Perform a user password check

Requires the following `body` items in a request:
- `session_token` (str): the session token associated with the `user_id`
- `password` (str): the password associated with the `user_id`

Returns a `response` with the following items if successful:
- `user_id` (int): a user ID associated with the logged-in user or None if
  password check failed.


# User handling

## `user-new`: Create a new user

Requires the following `body` items in a request:
- `full_name` (str): the user's full name
- `email` (str): the user's email address
- `password` (str): the user's password

Returns a `response` with the following items if successful:
- `user_email` (str): the user's email address
- `user_id` (int): the user's integer user ID
- `send_verification` (bool): whether or not an email for user signup
  verification should be sent to this user

## `user-changepass`: Change an existing user's password

Requires the following `body` items in a request:
- `user_id` (int): the integer user ID of the user
- `session_token` (str): the current session token of the user
- `full_name` (str): the full name of the user
- `email` (str): the email address of the user
- `current_password` (str): the current password that will be changed
- `new_password` (str): the new password that will be used from now on

Returns a `response` with the following items if successful:
- `user_id` (int): the user ID of the user
- `email` (str): the email address of the user

## `user-delete`: Delete an existing user

Requires the following `body` items in a request:
- `email` (str): the email address of the user
- `user_id` (int): the user ID of the user
- `password` (str): the password of the user to confirm account deletion if the
  user initiates this request themselves. optional if request was initiated by a
  superuser.

Returns a `response` with the following items if successful:
- `user_id` (str): the user ID of the just deleted user
- `email` (str): the email address of the just deleted user

## `user-list`: List all users' or a single user's properties

Requires the following `body` items in a request:
- `user_id` (int): the user ID of the user to look up. If None, will list all
  users.

 Returns a `response` with the following items if successful:
- `user_info` (list of dicts): a list containing all user info as a dict per
  user

## `user-edit`: Edit a user's properties

Requires the following `body` items in a request:
- `user_id` (int): the user ID of the user initiating this request
- `user_role` (str): the role of the user initiating this request
- `session_token` (str): the session token of the user initiating this request
- `target_userid` (int): the user ID that will be the subject of this request
- `update_dict` (dict): the items to update. keys allowed for all users:
  `full_name`, `email`. keys allowed for superusers only: `is_active`,
  `user_role`.

Returns a `response` with the following items if successful:
- `user_info` (dict): dict containing the user's updated information

## `user-resetpass`: Reset a user's password

Requires the following `body` items in a request:
- `email_address` (str): the email address of the user whose password will be
  reset
- `new_password` (str): the new password provided by the user
- `session_token` (str): the session token of the session initiating the request

Returns a `response` with the following items:
- None, check the `success` key to see if the request succeeded.

## `user-lock`: Toggle a lock out for an existing user

Requires the following `body` items in a request:
- `user_id` (int): the user ID initiating this request
- `user_role` (str): the role of the user initiating this request
- `session_token` (str): the session token of the user initiating this request
- `target_userid` (int): the user ID of the subject of this request
- `action` (str): either `unlock` or `lock`

Returns a `response` with the following items if successful:
- `user_info` (dict): a dict with user info related to current lock and account
  status.

This request can only be initiated by users with the `superuser` role.


# Authorization actions

These actions depend on a permissions policy that can be specified when the
authnzerver starts up. This is a JSON file describing the roles, items, actions,
item visibilities, and finally, the appropriate access rules and limits for each
role. An example is the
[default-permissions-model.json](https://github.com/waqasbhatti/authnzerver/blob/master/authnzerver/default-permissions-model.json)
shipped with the authnzerver package. If you don't specify a policy JSON as an
environment variable or as a command line option, this default policy will be
used.

## `user-check-access`: Check if the specified user can access a specified item

Requires the following `body` items in a request:
- `user_id` (int): the user ID of the user attempting access.
- `user_role` (str): the role of the user attempting access.
- `action` (str): the action being checked.
- `target_name` (str): the item that the action is going to be applied to.
- `target_owner` (int): the user ID of the item's owner.
- `target_visibility` (str): the visibility of the item being accessed.
- `target_sharedwith` (str): a CSV list of user IDs that the item is shared
  with.

Returns a `response` with the following items if successful:
- None, check the value of `success`. `True` indicates the access was
  successfully granted, `False` indicates otherwise.

## `user-check-limit`: Check if the specified user is over a specified limit

Requires the following `body` items in a request:
- `user_id` (int): the user ID of the user being checked for limit overage.
- `user_role` (str): the role of the user being checked.
- `limit_name` (str): the name of the limit to be checked.
- `value_to_check` (float, int): the amount to be checked against the limit
  value.

Returns a `response` with the following items if successful:
- None, check the value of `success`. `True` indicates the user is under the
  specified limit, `False` indicates otherwise.


# Email actions

## `user-signup-sendemail`: Send a verification email to a new user

Requires the following `body` items in a request:
- `email_address` (str): the email address of the new user
- `session_token` (str): the session token of the session initiating this
  request
- `created_info` (dict): the dict returned from the `user-new` request
- `server_name` (str): a name associated with the frontend server initiating the
  request (used in the email sent to the user)
- `server_baseurl` (str): the base URL of the frontend server initiating the
  request (used in the email sent to the user).
- `account_verify_url` (str): the URL fragment of the account verification
  endpoint on the frontend server initiating the request (used in the email sent
  to the user).
- `verification_token` (str): a time-stamped verification token generated by the
  frontend (this will be used as the verification token in the email text)
- `verification_expiry` (int): number of seconds after which the verification
  token will expire.

Returns a `response` with the following items if successful:
- `user_id` (int): the user ID of the user the email was sent to
- `email_address` (str): the email address the email was sent to
- `verifyemail_sent_datetime` (str): the UTC datetime the email was sent on in
  ISO format

## `user-forgotpass-sendemail`: Send a verification email to a user who forgot their password

Requires the following `body` items in a request:
- `email_address` (str): the email address of the new user
- `session_token` (str): the session token of the session initiating this
  request
- `created_info` (dict): the dict returned from the `user-new` request
- `server_name` (str): a name associated with the frontend server initiating the
  request (used in the email sent to the user)
- `server_baseurl` (str): the base URL of the frontend server initiating the
  request (used in the email sent to the user).
- `password_forgot_url` (str): the URL fragment of the forgot-password process
  initiation endpoint on the frontend server initiating the request (used in the
  email sent to the user).
- `verification_token` (str): a time-stamped verification token generated by the
  frontend (this will be used as the verification token in the email text)
- `verification_expiry` (int): number of seconds after which the verification
  token will expire.

Returns a `response` with the following items if successful:
- `user_id` (int): the user ID of the user the email was sent to
- `email_address` (str): the email address the email was sent to
- `forgotemail_sent_datetime` (str): the UTC datetime the email was sent on in
  ISO format


# API key actions

## `apikey-new`: Create a new API key tied to a user ID, role, and IP address

Requires the following `body` items in a request:
- `audience` (str): the service this API key is being issued for (usually the
  host name of the frontend server)
- `subject` (list of str): the specific API endpoint(s) this API key is being
  issued for (usually a list of URIs for specific service endpoints)
- `apiversion` (int): the version of the API this key is valid for
- `expires_days` (int): the number of days that the API key will be valid for
- `not_valid_before` (int): the number of seconds after the current UTC time
  required before the API key becomes valid
- `user_id` (int): the user ID of the user that this API key is tied to
- `user_role` (str): the role of the user that this API key is tied to
- `ip_address` (str): the IP address that this API key is tied to
- `session_token` (str): the session token of the user requesting this API key

Returns a `response` with the following items if successful:
- `apikey` (str): the API key information dict dumped to JSON
- `expires` (str): a UTC datetime in ISO format indicating when the API key
  expires

## `apikey-verify`: Verify an API key's user ID, role, expiry, and token

Requires the following `body` items in a request:
- `apikey_dict` (dict): the decrypted and validated API key information dict
  from the frontend.

Returns a `response` with the following items:
- None, check the value of `success` to see if the the API key is valid


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
