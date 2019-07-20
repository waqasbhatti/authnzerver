[![Build Status](https://ci.wbhatti.org/buildStatus/icon?job=authnzerver)](https://ci.wbhatti.org/job/authnzerver)

This is a small server meant to help add authentication (authn) and
authorization (authz) to other HTTP servers. It's built using
[Tornado](http://www.tornadoweb.org), [SQLAlchemy](https://www.sqlalchemy.org/),
[cryptography](https://cryptography.io),
[argon2-cffi](https://argon2-cffi.readthedocs.io/en/stable/),
[python-diskcache](http://www.grantjenks.com/docs/diskcache/), and
[uvloop](https://github.com/MagicStack/uvloop).

I wrote it to help with the login/logout/signup flows for the
[LCC-Server](https://github.com/waqasbhatti/lcc-server) and extracted much of
the code from there. It builds on the auth bits there and is eventually meant to
replace them. It can do the following things:

- handle user sign-ups, logins, and logouts
- handle user email verification, password changes, and editing user properties
- handle API key issuance, verification, and rate-limits

TODO items include:

- handling access and rate-limit checks for arbitrary schemes of user roles,
  permissions, and target objects. There is a [built-in
  scheme](https://github.com/waqasbhatti/authnzerver/blob/29d382099e8d9d5645bc3faec256d6a6f802247b/authnzerver/permissions.py#L17)
  of permissions and user roles, originally from the LCC-Server where this code
  was extracted from, but it may not be useful for general purposes.
- handling social logins using Twitter, Github, and Google.

Authnzerver talks to a frontend server over HTTP. Communications are secured
with symmetric encryption using the [cryptography](https://cryptography.io)
package's [Fernet scheme](https://cryptography.io/en/latest/fernet/), so you'll
need a pre-shared key that both Authnzerver and your frontend server know.


## Installation

Authnzerver is [available at PyPI](https://pypi.org/project/authnzerver/), but
is very much a work in progress at the moment. Don't install it (or trust it)
until it has reached v0.1.

With that said, it can be installed (preferably in a virtualenv) using `pip`:

```bash
(venv) $ pip install authnzerver

# use pip install authnzerver --pre for unstable releases
```


## Running the server

There is a single executable that will be in your `$PATH` if you have a
virtualenv activated and the package installed: `authnzrv`.

`authnzrv --help` will list all the options available:

```
--authdb            An SQLAlchemy database URL to indicate where
                    the local authentication DB is. This should
                    be in the form discussed at: https://docs.sq
                    lalchemy.org/en/latest/core/engines.html#dat
                    abase-urls
--autosetup         If this is True, will automatically generate
                    an SQLite authentication database in the
                    basedir if there isn't one present and the
                    value of the authdb option is also None.
                    (default True)
--backgroundworkers number of background workers to use
                    (default 4)
--basedir           The base directory containing secret files
                    and the auth DB if --autosetup was used.
--cachedir          Path to the cache directory used by the
                    authnzerver.
--debugmode         start up in debug mode if set to 1. (default
                    0)
--envfile           Path to a file containing environ variables
                    for testing/development.
--port              Run on the given port. (default 13431)
--secret            Path to the file containing the secret key.
                    This is relative to the path given in the
                    basedir option.
--serve             Bind to given address and serve content.
                    (default 127.0.0.1)
--sessionexpiry     This sets the session-expiry time in days.
                    (default 30)
```

There's an example systemd `.service` file available in the `deploy` directory
to run this server automatically on startup.


## Configuring the server

Use the following environmental variables to configure the server.

```
# listen address and port settings
AUTHNZERVER_PORT={{ authnzerver_listenport }}
AUTHNZERVER_LISTEN={{ authnzerver_listenaddr }}

# cache and base directory locations
AUTHNZERVER_CACHEDIR={{ authnzerver_cachedir }}
AUTHNZERVER_BASEDIR={{ authnzerver_basedir }}

# secret token and authentication DB URL
AUTHNZERVER_SECRET={{ authnzerver_secretkey }}
AUTHNZERVER_AUTHDB={{ authnzerver_authdb }}

# session expiry time in days
AUTHNZERVER_SESSIONEXPIRY={{ authnzerver_sessionexpiry }}

# email settings for sending emails to users
AUTHNZERVER_EMAILSENDER={{ authnzerver_emailsender }}
AUTHNZERVER_EMAILSERVER={{ authnzerver_emailserver }}
AUTHNZERVER_EMAILPORT={{ authnzerver_emailport }}
AUTHNZERVER_EMAILUSER={{ authnzerver_emailuser }}
AUTHNZERVER_EMAILPASS={{ authnzerver_emailpass }}
```

You can also provide all of these at once using an environment file. This is not
recommended for production but is useful for development. If you go this route,
use the `--envfile` option to point to an appropriate environment file.

At a minimum, you must provide:

- a pre-shared key as an environmental variable: `AUTHNZERVER_SECRETKEY`.
- an SQLAlchemy [database
  URL](https://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls)
  indicating where the server should store authentication information. Provide
  this either in the `AUTHNZERVER_AUTHDB` environmental variable or the
  `--authdb` option to the executable.

If neither of these are provided, and the command-line option `--autosetup` is
True (by default), the server will prompt you for admin credentials during the
first start up, generate a pre-shared secret key and initialize an SQLite
authentication database in the directory pointed to by the `--basedir`
command-line option.


## HTTP API and example frontend client

See [API.md](https://github.com/waqasbhatti/authnzerver/blob/master/docs/API.md) for
details.

If you'll be using this with a Tornado based server, there is an example
frontend client BaseHandler class available in
[frontendbase.py](https://github.com/waqasbhatti/authnzerver/blob/master/authnzerver/frontendbase.py).

See the [docstring for the initialize function](https://github.com/waqasbhatti/authnzerver/blob/518a9d396910feaa9dae5c8eb31330b186919c9e/authnzerver/frontendbase.py#L155) for details on how to pass
settings bits to the BaseHandler.

You can use the `BaseHandler` class like so:

```python
from authnzerver.frontendbase import BaseHandler

class MyFrontendHandler(BaseHandler):

    async def post(self):
        """This is an auth-enabled POST handler."""

        # check if we have the required 'Authorization'
        # bearer token value provided as an API key
        if not self.keycheck['status'] == 'ok':

            self.set_status(403)
            retdict = {
                'status':'failed',
                'result':None,
                'message':"Sorry, you don't have access."
            }
            self.write(retdict)
            raise tornado.web.Finish()

        # do other stuff here if all is well
```


## License

Authnzerver is provided under the MIT License. See the LICENSE file for details.
