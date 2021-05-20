Authnzerver HTTP API
~~~~~~~~~~~~~~~~~~~~

This page describes the API of the Authnzerver.

All requests are composed of a Python dict containing request parameters. This
is encoded to JSON, encrypted with the pre-shared key, base64-encoded, and then
POSTed to the Authnzerver's ``/`` endpoint. The response is a base64-encoded
string that must be base64-decoded, decrypted, and deserialized from JSON into a
dict.

A request is of the form::

  {'request': one of the request names below,
   'body': a dict containing the arguments for the request,
   'reqid': any integer or string (preferably a UUID) used to keep track
            of the request flow,
   'client_ipaddr': the IP address of the frontend server's
                    client to use in rate-limiting}

A response, when decrypted and deserialized to a dict, is of the form::

  {'success': True or False,
   'response': dict containing the response items based on the request,
   'messages': a list of str containing informative/warning/error messages,
   'reqid': returns the same request ID provided to the authnzerver}

If the 'reqid' item in the authnzervr response dict doesn't match what you sent
to the authnzerver, the response from the authnzerver MUST be rejected. A good
way to populate 'reqid' in the authnzerver request dict is to generate one right
at the beginning of the frontend server's HTTP response cycle, so it can remain
the same between several authnzerver action requests. This allows you to track
all authnzerver actions pertaining to a single response processing cycle of the
frontend server.

The 'messages' item contains a list of messages that MAY be shared with a client
of the frontend user to inform them about the state of the action request.

If the requested action failed, a 'failure_response' item will be present in the
response dict. This SHOULD NOT be shared with a client of the frontend server
because it likely contains the exact reason why something went wrong. Use these
only to decide what to do on the frontend server.

If you share the 'failure_reason' item with a client of the frontend user, this
may lead to an information leak when ambiguity is better, e.g. in the case of a
password check, you usually don't want to disclose if the user account doesn't
exist or the password was incorrect, instead responding with something like
"Sorry, that username/password combination didn't work. Please try again."

The sections below describe the various available action request types, how to
construct the ``body`` dict, and what to expect in the ``response`` dict.

Using the API Client
====================

An authnzerver HTTP API client is available in the authnzerver Python package's
:py:mod:`authnzerver.client` module. This contains a class that handles the
encryption/decryption for the request-response cycle and includes
both synchronous and asyncio-compatible request methods.

Example
-------

.. code-block:: python

   import asyncio
   import base64
   import secrets
   import os

   from authnzerver.client import Authnzerver


   # this is the secret key shared between the authnzerver and our client
   # best stored as an environment variable
   SHARED_SECRET_KEY = os.environ.get("AUTHNZERVER_SECRET", None)

   # if you haven't generated a secret key for authnzerver yet,
   # here's how to do it
   SHARED_SECRET_KEY = (
       base64.urlsafe_b64encode(secrets.token_bytes()).decode('utf-8')
   )

   # make a new authnzerver client object
   client = Authnzerver(authnzerver_url="http://localhost:13431",
                        authnzerver_secret=SHARED_SECRET_KEY)

   # fire a synchronous request
   response = client.request("user-new",
                             {"email": "hello@test.org",
                              "password": "super-strong-password",
                              "full_name": "Test User",
                              "client_ipaddr": "1.2.3.4"})

   # check if the request was successful
   print(response.success)

   # look at the response dict
   print(response.response)

   # look at the messages that can be passed on to an end-user
   print(response.messages)

   # look at the failure_reason that should be used internally only
   print(response.failure_reason)

   # look at the headers of the response
   print(response.headers)

   # look at the HTTP status code of the response -- useful for HTTP 401
   # or HTTP 429 responses from the authnzerver
   print(response.status_code)

   #
   # the same request in an asynchronous style -- using asyncio.run
   #

   # a runner function to demonstrate await syntax
   async def run_request():
       return await client.async_request("user-new",
                                         {"email": "hello2@test.org",
                                          "password": "superb-strong-password",
                                          "full_name": "Test User 2",
                                          "client_ipaddr": "1.2.3.4"})
   # execute the asynchronous request
   async_response = asyncio.run(run_request())


Constructing API Requests manually
==================================

Request example
---------------

.. code-block:: python

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
    req = {'request': request_type,
           'body': request_body,
           'reqid': reqid,
           'client_ipaddr': '1.1.1.1'}

    # encrypt the request
    encrypted_request = encrypt_request(req, FERNET_KEY)

    # send the request and get the response
    response = requests.post('http://127.0.0.1:13431', data=encrypted_request)


Response example
----------------

.. code-block:: python

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


Session handling
================

``session-new``: Create a new session
-------------------------------------

Requires the following ``body`` items in a request:

- ``ip_address`` (str): the IP address of the client

- ``user_agent`` (str): the user agent of the client

- ``user_id`` (int): a user ID associated with the client

- ``expires`` (int): the number of days after which the token is invalid

- ``extra_info_json`` (dict): a dict containing arbitrary session associated
  information

Returns a ``response`` with the following items if successful:

- ``session_token`` (str): a session token suitable for use in a session cookie

- ``expires`` (str): a UTC datetime in ISO format indicating when the session
  expires

``session-exists``: Get info about an existing session
------------------------------------------------------

Requires the following ``body`` items in a request:

- ``session_token`` (str): the session token to check

Returns a ``response`` with the following items if successful:

- ``session_info`` (dict): a dict containing session info if it exists, None
  otherwise

``session-delete``: Delete a session
------------------------------------

Requires the following ``body`` items in a request:

- ``session_token`` (str): the session token to delete

Returns a ``response`` with the following items:

- None. Check the ``success`` item in the returned dict.

``session-delete-userid``: Delete all sessions for a user ID
------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``session_token`` (str): the current session token

- ``user_id`` (int): a user ID associated with the client

- ``keep_current_session`` (bool): whether to keep the currently logged-in
  session

Returns a ``response`` with the following items:

- None. Check the ``success`` item in the returned dict.

``user-login``: Perform a user login action
-------------------------------------------

Requires the following ``body`` items in a request:

- ``session_token`` (str): the session token associated with the ``user_id``

- ``email`` (str): the email address associated with the ``user_id``

- ``password`` (str): the password associated with the ``user_id``

Returns a ``response`` with the following items if successful:

- ``user_id`` (int): a user ID associated with the logged-in user or None if
  login failed.
- ``user_role`` (str): the user's role.

``user-logout``: Perform a user logout action
---------------------------------------------

Requires the following ``body`` items in a request:

- ``user_id`` (int): a user ID associated with the logged-in user or None if
  login failed.

- ``session_token`` (str): the session token associated with the ``user_id``

Returns a ``response`` with the following items if successful:

- ``user_id`` (int): a user ID associated with the logged-in user or None if
  logout failed.

``user-passcheck``: Perform a user password check (requires an existing session)
--------------------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``session_token`` (str): the session token associated with the ``user_id``

- ``password`` (str): the password associated with the ``user_id``

Returns a ``response`` with the following items if successful:

- ``user_id`` (int): a user ID associated with the logged-in user or None if
  password check failed.
- ``user_role`` (str): the user's role.

``user-passcheck-nosession``: Perform a user password check (without an existing session)
-----------------------------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``email`` (str): the email address associated with the ``user_id``

- ``password`` (str): the password associated with the ``user_id``

Returns a ``response`` with the following items if successful:

- ``user_id`` (int): a user ID associated with the logged-in user or None if
  password check failed.
- ``user_role`` (str): the user's role.


User handling
=============

``user-new``: Create a new user
-------------------------------

Requires the following ``body`` items in a request:

- ``full_name`` (str): the user's full name

- ``email`` (str): the user's email address

- ``password`` (str): the user's password

Optional parameters are:

- ``extra_info`` (dict): arbitrary key-val items to store for this user. This is
  a good place to store user metadata like their organization, their avatar URL,
  their full address, etc.

- ``verify_retry_wait`` (int, default 6, minimum 1): The amount of time in hours
  the user must wait to retry a failed sign-up attempt. This situation arises if
  the user didn't get to their verification token email in time and it expired,
  or they sent back the incorrect token. The user must then wait for
  *verify_retry_wait* hours before they can try to sign up for an account again
  and get a new verification token via email.

- ``system_id`` (str): A (preferably random) string to use as the unique system
  ID for this user. A system ID is safer to use outside of the
  frontend/authnzerver system (e.g. by Javascript clients) than the ``user_id``
  value, which is an integer primary key. If this is not provided, a UUIDv4 will
  be generated and used for the system ID.

Returns a ``response`` with the following items if successful:

- ``user_email`` (str): the user's email address

- ``user_id`` (int): the user's integer user ID (primary key in the ``users`` DB
  table)

- ``system_id`` (str): the user's system ID

- ``send_verification`` (bool): whether or not an email for user signup
  verification should be sent to this user. If the user has signed up already,
  but has not verified their account email address and *verify_retry_wait*
  hours have not yet passed, ``send_verificiation`` will be False.

``user-delete``: Delete an existing user
----------------------------------------

Requires the following ``body`` items in a request:

- ``email`` (str): the email address of the user

- ``user_id`` (int): the user ID of the user

- ``password`` (str): the password of the user to confirm account deletion if
  the user initiates this request themselves. optional if request was initiated
  by a superuser.

Returns a ``response`` with the following items if successful:

- ``user_id`` (str): the user ID of the just deleted user

- ``email`` (str): the email address of the just deleted user

``user-list``: List all users' or a single user's properties
------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``user_id`` (int): the user ID of the user to look up. If None, will list all
  users.

 Returns a ``response`` with the following items if successful:

- ``user_info`` (list of dicts): a list containing all user info as a dict per
  user. Each dict has the following items of information as dict keys:
  ``user_id``, ``system_id``, ``full_name``, ``email``, ``is_active``,
  ``created_on``, ``user_role``, ``last_login_try``, ``last_login_success``,
  ``extra_info``.

``user-lookup-email``: Look up a user's info given their email address
----------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``email`` (str): the email address of the user to look up.

 Returns a ``response`` with the following items if successful:

- ``user_info`` (dict): a dict with the following items of information for the
  user as dict keys: ``user_id``, ``system_id``, ``full_name``, ``email``,
  ``is_active``, ``created_on``, ``user_role``, ``last_login_try``,
  ``last_login_success``, ``extra_info``.

``user-lookup-match``: Look up users by matching on a property
--------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``by`` (str): the property to look up users by. This must be one of the
  following: ``user_id``, ``system_id``, ``full_name``, ``email``,
  ``is_active``, ``created_on``, ``user_role``, ``last_login_try``,
  ``last_login_success``, ``extra_info``.

- ``match`` (str or dict): the value to match against the stored value of the
  property. If this is a dict, then ``by`` must be equal to ``extra_info``. The
  dict must be of the form ``{'key':'value'}`` to match one of the JSON items in
  the ``extra_info`` column of the ``users`` table.

Returns a ``response`` with the following items if successful:

- ``user_info`` (list): a list of dicts with the following items of information
  for each user as dict keys: ``user_id``, ``system_id``, ``full_name``,
  ``email``, ``is_active``, ``created_on``, ``user_role``, ``last_login_try``,
  ``last_login_success``, ``extra_info``.

``user-edit``: Edit a user's properties
---------------------------------------

Requires the following ``body`` items in a request:

- ``user_id`` (int): the user ID of the user initiating this request

- ``user_role`` (str): the role of the user initiating this request

- ``session_token`` (str): the session token of the user initiating this request

- ``target_userid`` (int): the user ID that will be the subject of this request

- ``update_dict`` (dict): the items to update. Keys that can be updated by all
  authenticated users are: ``full_name``, ``email``. Additional keys that can be
  updated by superusers only are: ``is_active``, ``user_role``.

Returns a ``response`` with the following items if successful:

- ``user_info`` (dict): dict containing the user's updated information

``user-lock``: Toggle a lock out for an existing user
-----------------------------------------------------

Requires the following ``body`` items in a request:

- ``user_id`` (int): the user ID initiating this request

- ``user_role`` (str): the role of the user initiating this request

- ``session_token`` (str): the session token of the user initiating this request

- ``target_userid`` (int): the user ID of the subject of this request

- ``action`` (str): either ``unlock`` or ``lock``

Returns a ``response`` with the following items if successful:

- ``user_info`` (dict): a dict with user info related to current lock and
  account status.

This request can only be initiated by users with the ``superuser`` role.


Password handling
=================

``user-changepass``: Change an existing user's password
-------------------------------------------------------

Requires the following ``body`` items in a request:

- ``user_id`` (int): the integer user ID of the user

- ``session_token`` (str): the current session token of the user

- ``full_name`` (str): the full name of the user

- ``email`` (str): the email address of the user

- ``current_password`` (str): the current password that will be changed

- ``new_password`` (str): the new password that will be used from now on

Returns a ``response`` with the following items if successful:

- ``user_id`` (int): the user ID of the user

- ``email`` (str): the email address of the user

``user-changepass-nosession``: Change an existing user's password (no session required)
---------------------------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``user_id`` (int): the integer user ID of the user

- ``full_name`` (str): the full name of the user

- ``email`` (str): the email address of the user

- ``current_password`` (str): the current password that will be changed

- ``new_password`` (str): the new password that will be used from now on

Returns a ``response`` with the following items if successful:

- ``user_id`` (int): the user ID of the user

- ``email`` (str): the email address of the user


``user-resetpass``: Reset a user's password
-------------------------------------------

Requires the following ``body`` items in a request:

- ``email_address`` (str): the email address of the user whose password will be
  reset

- ``new_password`` (str): the new password provided by the user

- ``session_token`` (str): the session token of the session initiating the
  request

Returns a ``response`` with the following items:

- None, check the ``success`` key to see if the request succeeded.

Note that this API action deletes all of the user's existing sessions to make
them log in again with the new password.

``user-resetpass-nosession``: Reset a user's password (no session required)
---------------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``email_address`` (str): the email address of the user whose password will be
  reset

- ``new_password`` (str): the new password provided by the user

- ``required_active`` (bool): if True, the user's *is_active* column value in
  the DB is required to be True. If False, the user's *is_active* column value
  in the DB is required to be False. Use this to require a specific user
  lock-out state before the password is reset. For example, if you always lock
  out users after their password-reset email token is verified and before
  they've entered a new password, set *required_active* to False.

Returns a ``response`` with the following items:

- None, check the ``success`` key to see if the request succeeded.

``user-validatepass``: Validate the user's password to see if it's insecure
---------------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``password`` (str): the password to validate

- ``email`` (str): the user's email address

- ``full_name`` (str): the user's full name

Optional items include:

- ``min_pass_length`` (int, default: 12): the minimum allowed password length in
  number of characters

- ``max_unsafe_similarity`` (int, default: 30): the maximum allowed string
  similarity (normalized to 100) between the user's password and their email
  address, their name, or the server's domain name.

Returns a ``response`` with the following items:

- ``success`` (bool): whether the password is OK.

- ``messages`` (str): any messages for the end-user that explain why their
  password was rejected if it was.


Authorization actions
=====================

These actions depend on a permissions policy that can be specified when the
authnzerver starts up. This is a JSON file describing the roles, items, actions,
item visibilities, and finally, the appropriate access rules and limits for each
role. An example is the
`default-permissions-model.json <https://github.com/waqasbhatti/authnzerver/blob/master/authnzerver/default-permissions-model.json>`_
shipped with the authnzerver package. If you don't specify a policy JSON as an
environment variable or as a command line option, this default policy will be
used.

``user-check-access``: Check if the specified user can access a specified item
------------------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``user_id`` (int): the user ID of the user attempting access.

- ``user_role`` (str): the role of the user attempting access.

- ``action`` (str): the action being checked.

- ``target_name`` (str): the item that the action is going to be applied to.

- ``target_owner`` (int): the user ID of the item's owner.

- ``target_visibility`` (str): the visibility of the item being accessed.

- ``target_sharedwith`` (str): a CSV list of user IDs that the item is shared
  with.

Returns a ``response`` with the following items if successful:

- None, check the value of ``success``. ``True`` indicates the access was
  successfully granted, ``False`` indicates otherwise.

``user-check-limit``: Check if the specified user is over a specified limit
---------------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``user_id`` (int): the user ID of the user being checked for limit overage.

- ``user_role`` (str): the role of the user being checked.

- ``limit_name`` (str): the name of the limit to be checked.

- ``value_to_check`` (float, int): the amount to be checked against the limit
  value.

Returns a ``response`` with the following items if successful:

- None, check the value of ``success``. ``True`` indicates the user is under the
  specified limit, ``False`` indicates otherwise.


Email actions
=============

``user-sendemail-signup``: Send a verification email to a new user
------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``email_address`` (str): the email address of the new user

- ``session_token`` (str): the session token of the session initiating this
  request

- ``created_info`` (dict): the dict returned from the ``user-new`` request

- ``server_name`` (str): a name associated with the frontend server initiating
  the request (used in the email sent to the user)

- ``server_baseurl`` (str): the base URL of the frontend server initiating the
  request (used in the email sent to the user).

- ``account_verify_url`` (str): the URL fragment of the account verification
  endpoint on the frontend server initiating the request (used in the email sent
  to the user).

- ``verification_token`` (str): a time-stamped verification token generated by
  the frontend (this will be used as the verification token in the email text)

- ``verification_expiry`` (int): number of seconds after which the verification
  token will expire.

Returns a ``response`` with the following items if successful:

- ``user_id`` (int): the user ID of the user the email was sent to

- ``email_address`` (str): the email address the email was sent to

- ``emailverify_sent_datetime`` (str): the UTC datetime the email was sent on in
  ISO format

``user-sendemail-forgotpass``: Send a verification email to a user who forgot their password
--------------------------------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``email_address`` (str): the email address of the new user

- ``session_token`` (str): the session token of the session initiating this
  request

- ``created_info`` (dict): the dict returned from the ``user-new`` request

- ``server_name`` (str): a name associated with the frontend server initiating
  the request (used in the email sent to the user)

- ``server_baseurl`` (str): the base URL of the frontend server initiating the
  request (used in the email sent to the user).

- ``password_forgot_url`` (str): the URL fragment of the forgot-password process
  initiation endpoint on the frontend server initiating the request (used in the
  email sent to the user).

- ``verification_token`` (str): a time-stamped verification token generated by
  the frontend (this will be used as the verification token in the email text)

- ``verification_expiry`` (int): number of seconds after which the verification
  token will expire.

Returns a ``response`` with the following items if successful:

- ``user_id`` (int): the user ID of the user the email was sent to

- ``email_address`` (str): the email address the email was sent to

- ``emailforgotpass_sent_datetime`` (str): the UTC datetime the email was sent on in
  ISO format

``user-set-emailverified``: Set the "verified" flag for a user completing sign-up
---------------------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``email`` (str): the email address of the new user that has completed sign-up
  and the verification token challenge.

Returns a ``response`` with the following items if successful:

- ``user_id`` (int): the user ID of the newly signed-up user the email was sent
  to

- ``user_role`` (str): the user role of the newly signed-up user

- ``is_active`` (bool): True if the user is successfully tagged as verified.

- ``emailverify_sent_datetime`` (str): the UTC datetime the email was sent
  on in ISO format

``user-set-emailsent``: Set the sent datetime for a user sign-up or forgot-pass email
-------------------------------------------------------------------------------------

When some other way of emailing the user, external to authnzerver, is used to
notify them about a signup verification or a forgot-password challenge, use this
API call to set the corresponding time at which the emails were sent. This lets
it do the right thing if someone tries to sign up for an account with the same
email address later.

Requires the following ``body`` items in a request:

- ``email`` (str): the email address of the new user that has completed sign-up
  and the verification token challenge.

- ``email_type`` (str): either "signup" or "forgotpass".

Returns a ``response`` with the following items if successful:

- ``user_id`` (int): the user ID of the newly signed-up user the email was sent
  to

- ``user_role`` (str): the user role of the newly signed-up user

- ``is_active`` (bool): True if the user is successfully tagged as verified.

- ``emailverify_sent_datetime`` (str): the UTC datetime the email was sent
  on in ISO format

- ``emailforgotpass_sent_datetime`` (str): the UTC datetime the email was sent
  on in ISO format


API key actions
===============

``apikey-new``: Create a new API key tied to a user ID, role, and existing user session
---------------------------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``issuer`` (str): the entity that will be designated as the API key issuer

- ``audience`` (str): the service this API key is being issued for (usually the
  host name of the frontend server)

- ``subject`` (list of str or str): the specific API endpoint(s) this API key is
  being issued for (usually a list of URIs for specific service endpoints)

- ``apiversion`` (int): the version of the API this key is valid for

- ``expires_days`` (int): the number of days that the API key will be valid for

- ``not_valid_before`` (int): the number of seconds after the current UTC time
  required before the API key becomes valid

- ``user_id`` (int): the user ID of the user that this API key is tied to

- ``user_role`` (str): the role of the user that this API key is tied to

- ``ip_address`` (str): the IP address that this API key is tied to

- ``user_agent`` (str): the user agent of the user creating the API key

- ``session_token`` (str): the session token of the user requesting this API key

Returns a ``response`` with the following items if successful:

- ``apikey`` (str): the API key information dict dumped to a JSON string

- ``expires`` (str): a UTC datetime in ISO format indicating when the API key
  expires

``apikey-verify``: Verify a session-tied API key's user ID, role, expiry, and token
-----------------------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``apikey_dict`` (dict): the decrypted and validated API key information dict
  from the frontend.

- ``user_id`` (int): the user ID of the user that this API key is tied to

- ``user_role`` (str): the role of the user that this API key is tied to


Returns a ``response`` with the following items:

- None, check the value of ``success`` to see if the API key is valid


``apikey-revoke``: Revoke a previously issued session-tied API key
------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``apikey_dict`` (dict): the decrypted and validated API key information dict
  from the frontend.

- ``user_id`` (int): the user ID of the target user whose API key is being
  revoked

- ``user_role`` (str): the role of the user that this API key is tied to

Returns a ``response`` with the following items:

- None, check the value of ``success`` to see if the API key revocation was
  successful

``apikey-new-nosession``: Create a new API key tied to a user ID, role, and IP address
--------------------------------------------------------------------------------------

See :py:mod:`authnzerver.actions.apikey_nosession` for notes on how to use
no-session API keys.

Requires the following ``body`` items in a request:

- ``issuer`` (str): the entity that will be designated as the API key issuer

- ``audience`` (str): the service this API key is being issued for (usually the
  host name of the frontend server or the API service)

- ``subject`` (list of str or str): the specific API endpoint(s) this API key is
  being issued for (usually a list of URIs for specific service endpoints)

- ``apiversion`` (int): the version of the API this key is valid for

- ``expires_seconds`` (int): the number of seconds that the API key will be
  valid for

- ``not_valid_before`` (int): the number of seconds after the current UTC time
  required before the API key becomes valid

- ``refresh_expires`` (int): the number of seconds that the refresh token will
  be valid for

- ``refresh_nbf`` (int): the number of seconds after the current UTC time
  required before the refresh token become valid

- ``user_id`` (int): the user ID of the user that this API key is tied to

- ``user_role`` (str): the role of the user that this API key is tied to

- ``ip_address`` (str): the IP address that this API key is tied to

Returns a ``response`` with the following items if successful:

- ``apikey`` (str): the API key information dict dumped to a JSON string

- ``expires`` (str): a UTC datetime in ISO format indicating when the API key
  expires

- ``refresh_token`` (str): a refresh token to use when asking for a refreshed
  API key

- ``refresh_token_expires`` (str): a UTC datetime in ISO format indicating when
  the refresh token expires


``apikey-verify-nosession``: Verify a no-session API key's user ID, role, expiry, and token
-------------------------------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``apikey_dict`` (dict): the decrypted and validated API key information dict
  from the frontend.

- ``user_id`` (int): the user ID of the user that this API key is tied to

- ``user_role`` (str): the role of the user that this API key is tied to


Returns a ``response`` with the following items:

- None, check the value of ``success`` to see if the API key is valid


``apikey-revoke-nosession``: Revoke a previously issued no-session API key
--------------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``apikey_dict`` (dict): the decrypted and validated API key information dict
  from the frontend.

- ``user_id`` (int): the user ID of the target user whose API key is being
  revoked

- ``user_role`` (str): the role of the user that this API key is tied to

Returns a ``response`` with the following items:

- None, check the value of ``success`` to see if the API key revocation was
  successful

``apikey-revokeall-nosession``: Revoke all previously issued no-session API keys
--------------------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``apikey_dict`` (dict): the decrypted and validated API key information dict
  from the frontend. A valid and unexpired API no-session is required to
  validate the all-keys revocation request.

- ``user_id`` (int): the user ID of the target user whose API key is being
  revoked

- ``user_role`` (str): the role of the user that this API key is tied to

Returns a ``response`` with the following items:

- None, check the value of ``success`` to see if the API key revocation was
  successful

``apikey-refresh-nosession``: Refresh a previously issued no-session API key
----------------------------------------------------------------------------

Requires the following ``body`` items in a request:

- ``apikey_dict`` (dict): the decrypted and validated API key information dict
  from the frontend.

- ``user_id`` (int): the user ID of the target user whose API key is being
  revoked

- ``user_role`` (str): the role of the user that this API key is tied to

- ``refresh_token`` (str): the refresh token of this API key

- ``ip_address`` (str): the current IP address of the user

- ``expires_seconds`` (int): the number of seconds that the API key will be
  valid for

- ``not_valid_before`` (int): the number of seconds after the current UTC time
  required before the API key becomes valid

- ``refresh_expires`` (int): the number of seconds that the refresh token will
  be valid for

- ``refresh_nbf`` (int): the number of seconds after the current UTC time
  required before the refresh token become valid

Returns a ``response`` with the following items:

- ``apikey`` (str): the API key information dict dumped to a JSON string

- ``expires`` (str): a UTC datetime in ISO format indicating when the API key
  expires

- ``refresh_token`` (str): a new refresh token to use when asking for a
  refreshed API key

- ``refresh_token_expires`` (str): a UTC datetime in ISO format indicating when
  the refresh token expires


Internal actions
================

These are actions that are meant only for internal use of a frontend
server. Invoking these actions MUST NOT accept any direct end-user input or pass
it on to the authnzerver because no permissions are checked.

``internal-user-edit``: Edit a user's information
-------------------------------------------------

Requires the following ``body`` items in a request:

- ``target_userid`` (int): the user ID to update

- ``update_dict`` (dict): a dict containing arbitrary user associated
  information to edit existing values in the columns of the users table.

  The ``update_dict`` cannot contain the following fields: user_id, system_id,
  password, emailverify_sent_datetime, emailforgotpass_sent_datetime,
  emailchangepass_sent_datetime, last_login_success, last_login_try,
  failed_login_tries, created_on. These are tracked in other action functions
  and should not be changed directly. This helps keep the user database
  consistent.

  If ``extra_info`` is one of the items in ``update_dict``, the ``extra_info``
  JSON field in the database will be updated with the dict in
  ``update_dict['extra_info']``. To delete an item from the database
  ``extra_info`` JSON field, pass in the special value of ``"__delete__"`` in
  ``update_dict['extra_info']`` for that item.

Returns a ``response`` with the following items if successful:

- ``user_info`` (dict): all user information with the updates included.

``internal-session-edit``: Edit an existing user session
--------------------------------------------------------

Requires the following ``body`` items in a request:

- ``target_session_token`` (str): the session token to update

- ``update_dict`` (dict): a dict containing arbitrary session associated
  information to add to, edit existing items, or delete items from the
  ``extra_info_json`` column of the sessions table. The ``extra_info_json``
  field in the database will be updated with the info in ``update_dict``. To
  delete an item from ``extra_info_json``, pass in the special value of
  ``"__delete__"`` in ``update_dict`` for that item.

Returns a ``response`` with the following items if successful:

- ``session_info`` (dict): all session related information with the updates
  included.

``internal-user-lock``: Lock/unlock a user
------------------------------------------

Requires the following ``body`` items in a request:

- ``target_userid`` (int): the user ID to lock/unlock
- ``action`` (str): the action to perform, one of: {'unlock','lock'}

Returns a ``response`` with the following items if successful:

- ``user_info`` (dict): user information including the current state of the
  ``is_active`` database column

``internal-user-delete``: Delete a user
----------------------------------------

Requires the following ``body`` items in a request:

- ``target_userid`` (int): the user ID to delete

Returns a ``response`` with the following items if successful:

- ``user_id`` (int): user ID of the user that was deleted
  ``is_active`` database column
