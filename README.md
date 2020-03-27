[![Build
Status](https://ci.wbhatti.org/buildStatus/icon?job=authnzerver)](https://ci.wbhatti.org/job/authnzerver) [![Documentation Status](https://readthedocs.org/projects/authnzerver/badge/?version=latest)](https://authnzerver.readthedocs.io/en/latest/?badge=latest)

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

- Handle user sign-ups, logins, logouts, and locks/unlocks.
- Handle user email verification, password changes, forgotten password
  processes, and editing user properties.
- Handle API key issuance and verification.
- Handle access and rate-limit checks for arbitrary schemes of user roles,
  permissions, and target items. There is a [default
  scheme](https://github.com/waqasbhatti/authnzerver/blob/master/authnzerver/default-permissions-model.json)
  of permissions and user roles, originally from the LCC-Server where this code
  was extracted from. Another permissions policy can be specified as JSON.

See
[TODO.md](https://github.com/waqasbhatti/authnzerver/blob/master/docs/TODO.md) for
features that are planned for the future. See
[CHANGELOG.md](https://github.com/waqasbhatti/authnzerver/blob/master/CHANGELOG.md)
for a version history.

Authnzerver talks to a frontend server over HTTP. Communications are secured
with symmetric encryption using the [cryptography](https://cryptography.io)
package's [Fernet scheme](https://cryptography.io/en/latest/fernet/), so you'll
need a pre-shared key that both Authnzerver and your frontend server know.

See [API.md](https://github.com/waqasbhatti/authnzerver/blob/master/docs/API.md)
for details on the HTTP API. Also see the (in-progress) [Python module
documentation](https://authnzerver.readthedocs.io/en/latest/).

## Installation

Authnzerver is [available at PyPI](https://pypi.org/project/authnzerver/), but
is very much a work in progress at the moment. Maybe hold off on installing it
until we've reached v0.2 (beta).

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
--authdb         An SQLAlchemy database URL to indicate where
                 the local authentication DB is. This should
                 be in the form discussed at: https://docs.sq
                 lalchemy.org/en/latest/core/engines.html#dat
                 abase-urls
--autosetup      If this is True, will automatically generate
                 an SQLite authentication database in the
                 basedir if there isn't one present and the
                 value of the authdb option is also None.
                 (default False)
--basedir        The base directory containing secret files
                 and the auth DB. (default os.getcwd())
--cachedir       Path to the cache directory to be used.
                 (default /tmp/authnzerver-cache)
--debugmode      If 1, will enable an /echo endpoint for
                 debugging purposes. (default False)
--emailpass      The password to use for login to the email
                 server.
--emailport      The SMTP port of the email server to use.
                 (default 25)
--emailsender    The account name and email address that the
                 authnzerver will send from. (default
                 Authnzerver <authnzerver@localhost>)
--emailserver    The address of the email server to use.
                 (default localhost)
--emailuser      The username to use for login to the email
                 server. (default getpass.getuser())
--envfile        Path to a file containing environ variables
                 for testing/development.
--listen         Bind to this address and serve content.
                 (default 127.0.0.1)
--permissions    The JSON file containing the permissions
                 model the server will enforce. (default
                 install-dir/authnzerver/authnzerver/
                 default-permissions-model.json)
--piisalt        A random value used as a salt when SHA256
                 hashing personally identifiable information
                 (PII), such as user IDs and session tokens,
                 etc. for authnzerver logs.
--port           Run the server on this TCP port. (default
                 13431)
--secret         The shared secret key used to secure
                 communications between authnzerver and any
                 frontend servers.
--sessionexpiry  This sets the session-expiry time in days.
                 (default 30)
--workers        The number of background workers to use when
                 processing requests. (default 4)
```

There's an example systemd `.service` file available in the `deploy` directory
to run this server automatically on startup.


## Configuring the server

Use the following environmental variables to configure the server. Defaults are
noted below where appropriate.

```
# listen address, port settings, and workers
AUTHNZERVER_PORT=13141
AUTHNZERVER_LISTEN=127.0.0.1
AUTHNZERVER_WORKERS=4

# cache and base directory locations
AUTHNZERVER_CACHEDIR=/tmp/authnzerver-cache
AUTHNZERVER_BASEDIR=directory where the server is started

# secret token, PII salt, and authentication DB URL
AUTHNZERVER_SECRET=
AUTHNZERVER_PIISALT=
AUTHNZERVER_AUTHDB=

# session expiry time in days
AUTHNZERVER_SESSIONEXPIRY=30

# permissions model JSON
AUTHNZERVER_PERMISSIONS=path/to/default-permissions-model.json

# email settings for sending emails to users
AUTHNZERVER_EMAILSENDER=Authnzerver <authnzerver@localhost>
AUTHNZERVER_EMAILSERVER=localhost
AUTHNZERVER_EMAILPORT=25
AUTHNZERVER_EMAILUSER=user running the authnzrv executable
AUTHNZERVER_EMAILPASS=''
```

You can also provide all of these at once using an environment file. This is not
recommended for production but is useful for development. If you go this route,
use the `--envfile` option to point to an appropriate environment file.

At a minimum, you must provide:

- a random pre-shared secret key as an environmental variable:
  `AUTHNZERVER_SECRETKEY`.
- a random salt value for hashing personally identifiable information in the
  authnzerver logs as an environmental variable: `AUTHNZERVER_PIISALT`.
- an SQLAlchemy [database
  URL](https://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls)
  indicating where the server should store authentication information as an
  environmental variable: `AUTHNZERVER_AUTHDB`.

If none of these are provided, and the command-line option
`--autosetup=True`, the server will prompt you for admin credentials during
start up, generate the pre-shared secret key and random salt, and initialize an
authentication database at the SQLAlchemy URL you provide. Autogenerated
defaults for these values can be used by hitting Enter at all the prompts.


## License

Authnzerver is provided under the MIT License. See the LICENSE file for details.
