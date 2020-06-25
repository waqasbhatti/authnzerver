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
  was extracted from. A custom permissions policy can be specified as JSON.

See
[TODO.md](https://github.com/waqasbhatti/authnzerver/blob/master/docs/TODO.md) for
features that are planned for the future. See
[CHANGELOG.md](https://github.com/waqasbhatti/authnzerver/blob/master/CHANGELOG.md)
for a version history.

Authnzerver talks to a frontend server over HTTP. Communications are secured
with symmetric encryption using the [cryptography](https://cryptography.io)
package's [Fernet scheme](https://cryptography.io/en/latest/fernet/), so you'll
need a pre-shared key that both Authnzerver and your frontend server know.

See [the HTTP API docs](https://authnzerver.readthedocs.io/en/latest/api.html)
for details on how to call Authnzerver from a frontend service.

More docs will be available at Authnzerver's (in-progress) [Read The
Docs](https://authnzerver.readthedocs.io/en/latest/) site.


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

### Running with Docker

There's a [Docker container for
authnzerver](https://hub.docker.com/r/waqasbhatti/authnzerver) available on
Docker Hub. To use this, follow the steps below:

1. Pull the container. The command below pulls the master branch version for
 now; stable versions will be added to Docker Hub later:

```
docker pull waqasbhatti/authnzerver:latest
```

2. Run the autosetup to set up a base directory, the auth DB, and the
envfile. The commands below set up an empty base directory on your Docker host,
mount it into the container as a volume, then tell authnzerver to use it for its
base directory.

```bash
mkdir authnzerver-basedir
cd authnzerver-basedir
docker run -v $(PWD):/home/authnzerver/basedir \
  --rm -it waqasbhatti/authnzerver:latest \
  --autosetup --basedir=/home/authnzerver/basedir
```

This will start an interactive session where you can set your auth DB and
initial admin credentials:

```
[W 200625 17:42:21 autosetup:105] Enter a valid SQLAlchemy database URL to use for the auth DB.
If you leave this blank and hit Enter, an SQLite auth DB
will be created in the base directory: /home/authnzerver/basedir
Auth DB URL [default: auto generated]:
[W 200625 17:42:23 autosetup:116] Enter the path to the permissions policy JSON file to use.
If you leave this blank and hit Enter, the default permissions
policy JSON shipped with authnzerver will be used: /home/authnzerver/authnzerver/default-permissions-model.json
Permission JSON path [default: included permissions JSON]:
[W 200625 17:42:25 autosetup:134] No existing authentication DB was found, making a new SQLite DB in authnzerver basedir: /home/authnzerver/basedir/.authdb.sqlite

Admin email address [default: authnzerver@localhost]:
Admin password [default: randomly generated]:
[W 200625 17:42:27 autosetup:214] Generated random admin password, credentials written to: /home/authnzerver/basedir/.authnzerver-admin-credentials

[I 200625 17:42:27 autosetup:220] Generating server secret tokens...
[I 200625 17:42:27 autosetup:236] Generating server PII random salt...
[I 200625 17:42:27 autosetup:252] Copying default-permissions-model.json to basedir: /home/authnzerver/basedir
[I 200625 17:42:27 autosetup:260] Copying confvars.py to basedir: /home/authnzerver/basedir
[I 200625 17:42:27 autosetup:271] Generating an envfile: /home/authnzerver/basedir/.env
[W 200625 17:42:27 main:216] Auto-setup complete, exiting...
[W 200625 17:42:27 main:219] Environment variables needed for the authnzerver to start have been written to:

    /home/authnzerver/basedir/.env

    Edit this file as appropriate or add these environment variables to the shell environment.
[W 200625 17:42:27 main:226] To run the authnzerver with this env file, your selected auth DB, and the auto-setup generated secrets files in your selected authnzerver basedir, start authnzerver with the following command:

    authnzrv --basedir="/home/authnzerver/basedir" --confvars="/home/authnzerver/basedir/confvars.py" --envfile="/home/authnzerver/basedir/.env"
```

4. Edit the `.env` file that was created in your Docker host's authnzerver base
   directory. In particular, you want to set `AUTHNZERVER_LISTEN` variable to
   `0.0.0.0` for running authnzerver as a Docker container.

5. Start up authnzerver, using the command-line hints provided in autosetup:

```bash
docker run -v $(PWD):/home/authnzerver/basedir \
  --rm -it waqasbhatti/authnzerver:latest \
  --basedir="/home/authnzerver/basedir" \
  --confvars="/home/authnzerver/basedir/confvars.py" \
  --envfile="/home/authnzerver/basedir/.env"
```

If you do not want to use the envfile (e.g. in production), add the variables in
it to your environment (e.g. in docker-compose) before launching the container,
then use:

```
docker run -v $(PWD):/home/authnzerver/basedir \
  --rm -it waqasbhatti/authnzerver:latest \
  --basedir="/home/authnzerver/basedir" \
  --confvars="/home/authnzerver/basedir/confvars.py"
```

In either case, launching the authnzerver container will look something like:

```
[W 200625 17:47:19 confload:568] Config item: "AUTHNZERVER_EMAILPASS" is invalid/missing, using provided default.
[W 200625 17:47:19 confload:568] Config item: "AUTHNZERVER_TLSCERT_FILE" is invalid/missing, using provided default.
[W 200625 17:47:19 confload:568] Config item: "AUTHNZERVER_TLSCERT_KEY" is invalid/missing, using provided default.
[I 200625 17:47:19 main:262] The server's base directory is: /home/authnzerver
[I 200625 17:47:19 main:265] The server's cache directory is: /tmp/authnzerver-cache
[I 200625 17:47:19 main:271] Session token expiry is set to: 30 days
[I 200625 17:47:19 main:354] Removed 0 stale items from authnzerver cache.
[I 200625 17:47:19 main:382] Auth DB is already set up at the provided database URL.
[W 200625 17:47:19 session:934] No sessions older than 2020-05-26T17:47:19.633377Z found to delete.
[I 200625 17:47:19 main:440] Starting authnzerver. Listening on http://0.0.0.0:13431.
[I 200625 17:47:19 main:442] The server is starting with TLS disabled.
[I 200625 17:47:19 main:444] Background worker processes: 4. IOLoop in use: uvloop.
```

### Running locally

There is a single executable that will be in your `$PATH` if you have a
virtualenv activated and the package installed: `authnzrv`.

`authnzrv --help` will list all the options available.

There's an example systemd `.service` file available in the `deploy` directory
to run this server automatically on startup.


## Configuring the server

Use the following environmental variables to configure the server. Defaults are
noted below where appropriate.

```
# listen address, port settings, and workers
AUTHNZERVER_PORT=13431
AUTHNZERVER_LISTEN=127.0.0.1
AUTHNZERVER_WORKERS=4

# cache and base directory locations
AUTHNZERVER_CACHEDIR=/tmp/authnzerver-cache
AUTHNZERVER_BASEDIR=directory where the server is started

# secret token, PII salt, and authentication DB URL
AUTHNZERVER_SECRET=
AUTHNZERVER_PIISALT=
AUTHNZERVER_AUTHDB=

# session settings
AUTHNZERVER_SESSIONEXPIRY=30
AUTHNZERVER_USERLOCKTRIES=10
AUTHNZERVER_USERLOCKTIME=3600

# permissions model JSON
AUTHNZERVER_PERMISSIONS=path/to/default-permissions-model.json

# email settings for sending emails to users
AUTHNZERVER_EMAILSENDER=Authnzerver <authnzerver@localhost>
AUTHNZERVER_EMAILSERVER=localhost
AUTHNZERVER_EMAILPORT=25
AUTHNZERVER_EMAILUSER=user running the authnzrv executable
AUTHNZERVER_EMAILPASS=''

# TLS certificate settings
AUTHNZERVER_TLSCERT_FILE=
AUTHNZERVER_TLSCERT_KEY=
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
`--autosetup`, the server will prompt you for admin credentials during
start up, generate the pre-shared secret key and random salt, and initialize an
authentication database at the SQLAlchemy URL you provide. Autogenerated
defaults for these values can be used by hitting Enter at all the prompts.


## License

Authnzerver is provided under the MIT License. See the LICENSE file for details.
