This is a small server built using [Tornado](http://www.tornadoweb.org),
[SQLAlchemy](https://www.sqlalchemy.org/), [PyCA
Cryptography](https://cryptography.io),
[passlib](https://passlib.readthedocs.io/en/stable/),
[argon2-cffi](https://argon2-cffi.readthedocs.io/en/stable/), and the
[python-diskcache](http://www.grantjenks.com/docs/diskcache/) packages to help
add authentication (authn) and authorization (authz) to other HTTP servers.

I wrote it to help with the login/logout/signup bits for the
[LCC-Server](https://github.com/waqasbhatti). It builds on the auth bits there
and is eventually meant to replace them. It can do the following things:

- handle user sign-ups, logins and logouts
- handle user email verification, password changes, and editing profiles
- handle access and rate-limit checks for arbitrary schemes of user roles,
  permissions, and target objects
- handle API key verification
- handle social logins using Twitter, Github, and Google

## Installation

TBD.

## Starting the server

TBD.

## HTTP API

Authnzerver talks to a frontend server over HTTP. Communications are secured
with symmetric encryption using the Python
[cryptography](https://cryptography.io) package's Fernet scheme, so you'll need
a pre-shared key that both Authnzerver and your frontend server know.

### Request structure

TBD.

### Response structure

TBD.

### API

TBD.

## License

MIT.
