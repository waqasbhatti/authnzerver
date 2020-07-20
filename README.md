[![Build
Status](https://ci.wbhatti.org/buildStatus/icon?job=authnzerver)](https://ci.wbhatti.org/job/authnzerver) [![Documentation Status](https://readthedocs.org/projects/authnzerver/badge/?version=latest)](https://authnzerver.readthedocs.io/en/latest/?badge=latest)

This is a small server meant to help add authentication (authn) and
authorization (authz) to other HTTP servers. It's built using
[Tornado](http://www.tornadoweb.org), [SQLAlchemy](https://www.sqlalchemy.org/),
[cryptography](https://cryptography.io),
[argon2-cffi](https://argon2-cffi.readthedocs.io/en/stable/),
[python-diskcache](http://www.grantjenks.com/docs/diskcache/),
[sortedcontainers](http://www.grantjenks.com/docs/sortedcontainers/index.html),
and [uvloop](https://github.com/MagicStack/uvloop).

I wrote it to help with the login/logout/signup flows for the [Light Curve
Collection Server](https://github.com/waqasbhatti/lcc-server) and extracted much
of the code from there. It builds on the auth bits there and is eventually meant
to replace them. It can do the following things:

- Handle user sign-ups, logins, logouts, and locks/unlocks.
- Handle user email verification, password changes, forgotten password
  processes, and editing user properties.
- Handle API key issuance and verification.
- Handle access and rate-limit checks for arbitrary schemes of user roles,
  permissions, and target items. There is a [default
  scheme](https://github.com/waqasbhatti/authnzerver/blob/master/authnzerver/default-permissions-model.json)
  of permissions and user roles, originally from the LCC-Server where this code
  was extracted from. A custom permissions policy can be specified as JSON.

Authnzerver talks to a frontend server over HTTP. Communications are secured
with symmetric encryption using the [cryptography](https://cryptography.io)
package's [Fernet scheme](https://cryptography.io/en/latest/fernet/), so you'll
need a pre-shared key that both Authnzerver and your frontend server know.

See [the HTTP API docs](https://authnzerver.readthedocs.io/en/latest/api.html)
for details on how to call Authnzerver from a frontend service.

See
[TODO.md](https://github.com/waqasbhatti/authnzerver/blob/master/docs/TODO.md) for
features that are planned for the future. See
[CHANGELOG.md](https://github.com/waqasbhatti/authnzerver/blob/master/CHANGELOG.md)
for a version history.

More docs are available at Authnzerver's (in-progress) [Read The
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

There's also a [Docker container for
authnzerver](https://hub.docker.com/r/waqasbhatti/authnzerver) available on
Docker Hub. The command below pulls the master branch version for now; stable
versions will be added to Docker Hub later:

```
docker pull waqasbhatti/authnzerver:latest
```

## Running the server

[See the docs](https://authnzerver.readthedocs.io/en/latest/running.html) on how
to configure the server with environment variables or command-line options, and
run it either as a Docker container or as script executable from the Python
package.

### Quick start

If you have authnzerver installed as a Python package in an activated virtualenv:

```bash
authnzrv --autosetup --basedir=$(PWD)
```

If you're running it as a Docker container:

```bash
docker run -p 13431:13431 -v $(PWD):/home/authnzerver/basedir \
  --rm -it waqasbhatti/authnzerver:latest \
  --autosetup --basedir=/home/authnzerver/basedir
```

## License

Authnzerver is provided under the MIT License. See the LICENSE file for details.
