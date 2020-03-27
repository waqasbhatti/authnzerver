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


## TODO for v0.2

### Frontend bits

- [ ] Add a full frontend listening as an /authf endpoint, this will include a
  Bootstrap UI for login, logout, etc. Change the existing /auth endpoint to
  make sure it only listens to specified IP address ranges, and then rename it
  to /authb to signify backend auth requests. We'll also need to ship Bootstrap
  and Tornado templates and copy these over to the basedir for the user to
  change if required.
- [ ] [ASVS] "Verify that cookie-based session tokens use "__Host-" prefix (see
      references) to provide session cookie confidentiality."
- [ ] [ASVS] "Verify that users are able to view and log out of any or all
      currently active sessions and devices."
- [ ] Add timeouts to any frontend requests to authnzerver.
- [ ] Lock user accounts after 10 attempts for two hours. Send an email to the
      user indicating a large volume of failed attempts.

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

### Misc

- [ ] Think about changing the permissions model so `allowed_actions_for_owned`
  is further scoped by the owned items (e.g. maybe authenticated users shouldn't
  be able to delete datasets even if they own them).
- [ ] Maybe memlock pages for secure holding of secrets in memory? (how would
      this even work in Python?)
- [ ] Maybe add a `change_role` action and figure out how this would work.
- [ ] Docker container.
- [ ] Possibly move from shared key to public/private key to secure
  frontend-authnzerver communications. Probably use PyNACL for this (see
  below). Also see: https://stackoverflow.com/a/59835994 for AES-GCM shared-key
  alternative to Fernet shared-key.


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
