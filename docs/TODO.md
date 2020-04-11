## TODO for v0.1

### Password handling

- [x] Add list of [10k most common
  passwords](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt),
  load into memory as a set and check against this for all user creation events.
- [x] [ASVS] "Verify that the application terminates all other active sessions
      after a successful password change, and that this is effective across the
      application, federated login (if present), and any relying parties."

### Request tracking and logging

- [x] Log all the auth events. Make sure PII (session tokens, passwords, user
      names, emails) never makes it into the logs.
- [x] Add request IDs received from the POST into all of the logging messages
  produced by the backend functions.
- [x] Put the request ID received from the POST into a cache and see if it is
  received again. If it is, drop the message.
- [x] Return the request ID from the backend to the handler, and then from there
  back to the client. Our own authnzerver frontend basehandler should check if
  it received the correct request ID it sent.
- [x] Track invalid login requests and password checks in the cache, and then
  apply exponential timeout to them to slow them down. This should be done in
  the handler with asyncio.sleep so the timeout is enforced on the authnzerver
  end.

### Misc

- [x] Add actions/access.py and hook up handler to delegate access control
  decisions to the authnzerver.
- [x] Add email server settings to the env config bits.
- [x] Do autosetup correctly. check if the DB is empty, create the required
  tables if necessary.
- [x] Add `test_auth_permissions.py` to check delegation of permissions via the
      payload API.
- [x] Try to at least conform to OWASP ASVS Level 2.
- [x] Look at NIST 800-162 (ABAC) to see if we can improve the permissions model.
- [x] Remove numpy from requirements (change frontendbase and `test_auth_timing`)


## TODO for vNEXT

### Frontend bits

- [ ] Add a full frontend listening as an /auth endpoint, this will include a
  Bootstrap UI for login, logout, etc. Change the existing / endpoint to make
  sure it only listens to specified IP address ranges, and then maybe rename it
  to /authb to signify backend auth requests.
- [x] We'll also need to ship Bootstrap and Tornado templates and copy these
  over to the basedir for the user to change if required.
- [ ] Handle CORS and cookie domains correctly: this requires adding
  `AUTHNZRV_FRONTEND_COOKIEDOMAIN`, `AUTHNZRV_FRONTEND_COOKIEPATH`
  env vars to allow the frontend to authorize other servers, and possibly
  also other headers for CORS (need to figure this bit out).
- [ ] [ASVS] "Verify that cookie-based session tokens use "__Host-" prefix (see
  references) to provide session cookie confidentiality." -> figure out why this
  doesn't work currently.
- [ ] [ASVS] "Verify that users are able to view and log out of any or all
  currently active sessions and devices." -> Probably tie in to the user event
  log below.
- [x] Add timeouts to any frontend requests to authnzerver.
- [x] Lock user accounts after 10 (configurable) attempts for 1 hour (also
  configurable).
- [ ] Send an email to the user indicating a large volume of failed attempts.
- [ ] Add admin UI (or just move the index page to this if superusers log in).
- [ ] Wire up the change-password and delete-user links on the index page.
- [ ] Add edit-user bits on the index page.

### User event log

- [ ] Add a user event log. This will require a separate table in the auth DB
      and a module in the actions subpackage. Call the log function on any event
      that the user does and store in the log. The user can then view their own
      events and the admin users can do the same for any user.

### 2FA

- [ ] 2FA using pyotp probably (look up what PyPI uses).
- [ ] Add WebAuthn using Duo's python web authn library (look up what PyPI uses).

### OAuth and Federation

- [ ] Add OAuth2 client and OpenID Connect clients with the various callback URL
  bits. Check against Google, Twitter, Github, Auth0.
- [ ] Look into getting the user database, roles, and limits from a directory
      service like AD or FreeIPA.

### Group handling

- [ ] Implement user groups and sharing of items between group members.
- [ ] We need a Groups table in the DB, that has the following columns: `id`,
      `system_id`, `group_name`, `group_role` (foreign key into the Roles
      table), maybe also a `group_owner` column (foreign key into the Users
      table).
- [ ] We also need a UserGroups table that maps between `user_ids` and
      `group_ids` so that users can be part of multiple different groups (this
      is a many-to-many relation).
- [ ] Add APIs for groups: 'group-new', 'group-add-user', 'group-del-user',
      'group-delete', 'group-edit' (superuser only or group-owner only).
- [ ] Add groups as items in the permissions policy and fill in the bits.

### Documentation

- [ ] Document the permissions model JSON and the allowed bits and required
      roles and actions.
- [ ] Document the environment variables and how to launch the server and the
      frontend.
- [ ] Add Sphinx-able docstrings everywhere.

### Misc

- [ ] Think about changing the permissions model so `allowed_actions_for_owned`
  is further scoped by the owned items (e.g. maybe authenticated users shouldn't
  be able to delete datasets even if they own them).
- [ ] Maybe memlock pages for secure holding of secrets in memory? (how would
      this even work in Python?)
- [ ] Maybe add a `change_role` action and figure out how this would work.
- [ ] Docker container.
- [ ] Add `test_api_*.py` for all of the HTTP API request types. Use
      `test_server.py` as a prototype.
- [x] Add Sphinx docs for all the modules and make a readthedocs website.
- [x] For `confload.py`, add the ability to load an item from a URL in either
      text or JSON form.
- [x] Make confvars.py loadable from the command line options so we can change
      how the config variables are loaded. Copy over confvars.py and
      default-permissions-model.json to the server's basedir on autosetup.
- [ ] Add a /auth/health handler for responding to health-checkers for frontend
      and /health for the backend.
- [ ] Definitely move to the PyNACL scheme below for public/private keys. Add a
      /auth/keys handler that returns the current public keys for the server in
      JSON format. Each key will have a key-id, a not-before, and an expiry
      date. Set up a periodic handler to update the private/public keys every
      couple of days (store them in the DB probably). Look at JWK
      openid-configuration URLs and pointers to cert endpoints.
- [x] Figure out some way to test email sending.
- [ ] Add geoip and ASN lookups (deal with Maxmind's new API thing). Then allow
      rate-limiting by ASN or GeoIP region. Add backend APIs probably:
      'user-geoip-check', 'user-asn-check', 'user-iprange-check' (for IP range
      rate-limits)


## JWK notes

The key list is returned as JSON, e.g. from the IETF RFC:

```json
 {"keys":
       [
         {"kty":"EC",
          "crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "use":"enc",
          "kid":"1"},

         {"kty":"RSA",
          "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
     4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
     tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
     QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
     SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
     w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }
```

We'll reuse the JWK format, but we'll use our own key type (probably "X25519"
and "Ed25519") and use "x" for the public key indicator, something like:

```json
{"kty":"OKP","crv":"X25519","kid":"Bob"
 "x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}
```

That's from here: https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-06

We'll need two Curve25519 keys: one for encryption and one for signing.


## PyNACL notes

```python
In [1]: import nacl.utils

In [2]: from nacl.public import PrivateKey, Box

In [3]: secret_key_authnzerver = PrivateKey.generate()

In [4]: public_key_authnzerver = secret_key_authnzerver.public_key

In [5]: secret_key_frontend = PrivateKey.generate()

In [6]: public_key_frontend = secret_key_frontend.public_key

In [7]: frontend_to_authnzerver_box = Box(secret_key_frontend, public_key_authnzerver)

In [8]: message = b'Hello there, authnzerver!'

In [9]: encrypted_frontend_to_authnzerver_msg = frontend_to_authnzerver_box.encrypt(message)

In [10]: encrypted_frontend_to_authnzerver_msg
Out[10]: b"\xa8z\x18\x0e K\xcb\x03m\xa7\xbe$\x80\xb6\x80k\xc0\xdd\x08\xebP\x16\xecI\xca\xa0-\x92\x9bA1\x0b\xd6v\xda\x90\x04\x9c\xb9K',\x9a\x9c\xe5$P\xbd\xc5\x01x\x84d\x18\xf9f=\x82e\xe9\xf9\x8b\x05D\xe7"

In [11]: authnzerver_to_frontendbox = Box(secret_key_authnzerver, public_key_frontend)

In [12]: authnzerver_to_frontendbox.decrypt(encrypted_frontend_to_authnzerver_msg)
Out[12]: b'Hello there, authnzerver!'

In [13]: import nacl.encoding

In [14]: encrypted_frontend_to_authnzerver_msg = frontend_to_authnzerver_box.encrypt(message,encoder=nacl.encoding.URLSafeBase64Encoder)

In [15]: encrypted_frontend_to_authnzerver_msg
Out[15]: b'nI95xbBakTstLR_aGU4pqz7-FbEhXfMDFVTqMYjrTPVbGSxItx5mbZPE-0IJR1ARSww4wJlIgB-0I-iJ0D-5DSE='

In [16]: authnzerver_to_frontendbox.decrypt(encrypted_frontend_to_authnzerver_msg, encoder=nacl.encoding.URLSafeBase64Encoder)
Out[16]: b'Hello there, authnzerver!'
```
