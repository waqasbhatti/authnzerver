Running the server
~~~~~~~~~~~~~~~~~~

This page describes how to configure and launch the server.

Configuring the authnzerver
===========================

The server is configurable via either environment variables or command-line
options. You can also specify *how* to load these items if special handling is
required. See the `Retrieving configuration items`_ section below for details.

To set a command line option, use ``--option=value``.

To use environment variables for configuration, add them to the shell
environment before the server starts, or add them to an ``.env`` file and
provide its location with ``--envfile`` command-line parameter.

At a minimum, you must provide:

- a random pre-shared secret key as an environmental variable:
  ``AUTHNZERVER_SECRETKEY`` or as a command-line option: ``--secret``.

- a random salt value for hashing personally identifiable information in the
  authnzerver logs as an environmental variable: ``AUTHNZERVER_PIISALT`` or as a
  command-line option: ``--piisalt``.

- an SQLAlchemy database URL to indicate where the local authentication DB
  is. This should be in the form discussed in the `SQLAlchemy docs
  <https://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls>`_ as
  an environmental variable: ``AUTHNZERVER_AUTHDB`` or as a command-line option:
  ``--authdb``.

If none of these required items are set, the authnzerver will not start.

To set up these required items in an interactive manner, provide a single
command-line option ``--autosetup``. The server will prompt you for admin
credentials during start up, generate the pre-shared secret key and random salt,
and initialize an authentication database at the SQLAlchemy URL you
provide. Autogenerated defaults for these values can be used by hitting Enter at
all the prompts.

.. note:: If you'd like to use PostgreSQL with authnzerver, make sure to also
   install the `psycopg2 <https://pypi.org/project/psycopg2/>`_ package so
   SQLAlchemy can talk to the database. Similarly, for MariaDB or MySQL, install
   a MySQL compatible package, for example, `PyMySQL
   <https://pypi.org/project/PyMySQL/>`_. Both of these packages are already
   included in the authnzerver Docker container, but are optional when
   authnzerver is installed as a Python package.


Setting the administrator password
==================================

Authnzerver sets up an account with a role of **superuser** when it first
initializes its authentication database. If you use ``--autosetup``, you will be
asked for an email address and password to use for this account.

If you start the server directly, giving it all the required environment
variables to do so (``AUTHNZERVER_SECRETKEY``, ``AUTHNZERVER_PIISALT``, and
``AUTHNZERVER_AUTHDB``), you will not be asked for admin account credentials. To
provide these credentials in this case, use two more environment variables:
``AUTHNZERVER_ADMIN_EMAIL``, and ``AUTHNZERVER_ADMIN_PASSWORD``.

If these admin user credentials are not provided, a default admin user email
address and random password will be generated and written to a file called
``.authnzerver-admin-credentials`` in server's base directory (by default: the
directory where it starts from).

.. warning:: If you're running Authnzerver as a Docker container, the generated
   admin credentials file will be in the ``/home/authnzerver/basedir`` directory
   inside the container. Make sure to copy this file over to your host machine
   if you want to save it, since the container filesystem is ephemeral.


List of all configuration items
===============================

cmdline: ``--allowedhosts``, env: ``AUTHNZERVER_ALLOWEDHOSTS``
--------------------------------------------------------------

The allowed HTTP request header "Host" values that the server will respond
to. Separate values with semicolons. Specifying these helps prevent
DNS-rebinding attacks. (*default:* ``'localhost;127.0.0.1'``)

cmdline: None, env: ``AUTHNZERVER_ADMIN_EMAIL``
-----------------------------------------------

The email address to use for the auto-generated admin user with a role of
**superuser** upon first startup of the server. If this is not provided, and you
did not use ``--autosetup`` as a command line argument either, a default email
address will be generated and used.

cmdline: None, env: ``AUTHNZERVER_ADMIN_PASSWORD``
--------------------------------------------------

The password to use for the auto-generated admin user with a role of
**superuser** upon first startup of the server. If this is not provided, and you
did not use ``--autosetup`` as a command line argument either, a random password
will be generated and used.

cmdline: ``--authdb``, env: ``AUTHNZERVER_AUTHDB``
--------------------------------------------------

An SQLAlchemy database URL to indicate where the local authentication DB
is. This should be in the form discussed in the `SQLAlchemy docs
<https://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls>`_.

cmdline: ``--autosetup``, env: None
-----------------------------------

If this is True, will automatically generate an SQLite authentication database
in the basedir, copy over ``default-permissions-model.json`` and ``confvars.py``
to the basedir for easy customization, and finally, generate the communications
secret file and the PII salt file. (*default:* False).

cmdline: ``--basedir``, env: ``AUTHNZERVER_BASEDIR``
----------------------------------------------------

The base directory containing secret files and the auth DB. (*default:*
directory the server is launched in)

cmdline: ``--confvars``, env: None
----------------------------------

Path to the file containing the configuration variables needed by the server and
how to load them. (*default:* the ``confvars.py`` file shipped with authnzerver)

cmdline: ``--debugmode``, env: ``AUTHNZERVER_DEBUGMODE``
--------------------------------------------------------

If set to ``1``, will enable an ``/echo`` endpoint for debugging
purposes. (*default:* 0)

cmdline: ``--emailpass``, env: ``AUTHNZERVER_EMAILPASS``
--------------------------------------------------------

The password to use for login to the email server.

cmdline: ``--emailport``, env: ``AUTHNZERVER_EMAILPORT``
--------------------------------------------------------

The SMTP port of the email server to use. (*default:* 25)

cmdline: ``--emailsender``, env: ``AUTHNZERVER_EMAILSENDER``
------------------------------------------------------------

The account name and email address that the authnzerver will send
from. (*default:* ``Authnzerver <authnzerver@localhost>``)

cmdline: ``--emailserver``, env: ``AUTHNZERVER_EMAILSERVER``
------------------------------------------------------------

The address of the email server to use. (*default:* ``localhost``)

cmdline: ``--emailuser``, env: ``AUTHNZERVER_EMAILUSER``
--------------------------------------------------------

The username to use for login to the email server. (*default*: user running the
authnzrv executable)

cmdline: ``--envfile``, env: None
---------------------------------

Path to a file containing environ variables for testing/development.

cmdline: ``--listen``, env: ``AUTHNZERVER_LISTEN``
--------------------------------------------------

Bind to this address and serve content. (*default:* ``127.0.0.1``)

cmdline: ``--passpolicy``, env: ``AUTHNZERVER_PASSPOLICY``
----------------------------------------------------------

This sets the password policy enforced by the server. This includes:

1. the minimum number of characters required in the password

2. the maximum allowed string similarity (out of 100) between the password and
   unsafe items like the server's domain name, the user's own email address, or
   their full name

3. the maximum number of times any single character can appear in the password
   as a fraction of the total number of characters in the password

4. the minimum number of matches required against the `Have I Been Pwned
   <https://haveibeenpwned.com/Passwords>`_ compromised passwords database.

This parameter is specified as key:value pairs separated by a
semicolon. (*default:* ``min_pass_length:12; max_unsafe_similarity:50;
max_char_frequency:0.3; min_pwned_matches:25``)

cmdline: ``--ratelimits``, env: ``AUTHNZERVER_RATELIMITS``
----------------------------------------------------------

This sets the rate limit policy for authnzerver actions. This parameter is
specified as key:value pairs separated by a semicolon. Specify values for all
actions (tied to the IP address of the frontend server's client) in the
``ipaddr`` key, user-tied actions (based on email/user_id/IP address) in the
``user`` key, session-tied actions (based on session_token/IP address) in the
``session`` key, and apikey-tied actions (based on session_token/IP address) in
the ``apikey`` key. The ``burst`` key indicates how many requests will be
allowed to come in before rate-limits start being enforced.

All values are in units of max requests allowed per minute. Set this parameter
to the string 'none' to turn off rate-limiting entirely.

(*default:* ``ipaddr:720; user:480; session:600; apikey:720; burst:150``).

Some individual API actions are more aggressively rate-limited per IP address by
the authnzerver. Currently, these include (all values in requests/minute)::

  AGGRESSIVE_RATE_LIMITS = {
    "user-new": 5,
    "user-login": 10,
    "user-logout": 10,
    "user-edit": 10,
    "user-resetpass": 5,
    "user-changepass": 5,
    "user-sendemail-signup": 2,      # also rate-limited per email address
    "user-sendemail-forgotpass": 2,  # also rate-limited per email address
    "user-set-emailsent": 2,         # also rate-limited per email address
    "apikey-new": 30,
    "apikey-new-nosession": 30,
    "apikey-refresh-nosession": 30,
  }

You may also override the rate-limit for an individual API action by specifying
it as a key-value pair in this configuration variable. For example, to set a
custom rate limit of 20 requests/minute for the ``user-login`` action, add
``user-login:20`` to the ``ratelimits`` configuration variable string.

cmdline: ``--permissions``, env: ``AUTHNZERVER_PERMISSIONS``
------------------------------------------------------------

The JSON file containing the permissions model the server will
enforce. (*default:* the permissions model JSON shipped with authnzerver)

cmdline: ``--piisalt``, env: ``AUTHNZERVER_PIISALT``
----------------------------------------------------

A random value used as a salt when SHA256 hashing personally identifiable
information (PII), such as user IDs and session tokens, etc. for authnzerver
logs.

cmdline: ``--port``, env: ``PORT`` or ``AUTHNZERVER_PORT``
----------------------------------------------------------

Run the server on this TCP port. (*default:* 13431)

cmdline: ``--secret``, env: ``AUTHNZERVER_SECRET``
--------------------------------------------------

The shared secret key used to secure communications between authnzerver and any
frontend servers.

cmdline: ``--sessionexpiry``, env: ``AUTHNZERVER_SESSIONEXPIRY``
----------------------------------------------------------------

This sets the session-expiry time in days. (*default:* 30)

cmdline: ``--tlscertfile``, env: ``AUTHNZERVER_TLSCERTFILE``
------------------------------------------------------------

The TLS certificate to use. If this is provided along with the certificate key
in the ``--tlscertkey`` option, the server will start in TLS-enabled mode.

cmdline: ``--tlscertkey``, env: ``AUTHNZERVER_TLSCERTKEY``
----------------------------------------------------------

The TLS certificate's key to use. If this is provided along with the certificate
in the ``--tlscertfile`` option, the server will start in TLS-enabled mode.

cmdline: ``--userlocktime``, env: ``AUTHNZERVER_USERLOCKTIME``
--------------------------------------------------------------

This sets the lockout time in seconds for failed user logins that exceed the
maximum number of failed login tries. (*default:* 3600)

cmdline: ``--userlocktries``, env: ``AUTHNZERVER_USERLOCKTRIES``
----------------------------------------------------------------

This sets the maximum number of failed logins per user that triggers a temporary
lock on their account. (*default:* 10)

cmdline: ``--workers``, env: ``AUTHNZERVER_WORKERS``
----------------------------------------------------

The number of background workers to use when processing requests. (*default:* 4)


Retrieving configuration items
==============================

The ``confvars.py`` file contains all the configuration items required by the
authnzerver and also defines how to retrieve them. If you run ``--autosetup``,
this file will be copied to the base directory you specify. Running the
authnzerver with a ``--confvars=/path/to/authnzerver/basedir/confvars.py`` can
be used to override the default config retrieval methods used by authnzerver.

**YOU MUST NOT STORE ANY SECRETS IN THIS FILE**. It only defines which variables
in the environment or command-line parameters to use when retrieving secrets and
other config items, as well as methods of retrieving them.

Let's walk through some examples of customizing retrieval of a config parameter:
the secret shared key that secures communications between authnzerver and a
frontend webserver.

Open up the ``confvars.py`` file in your authnzerver base directory. Here's the
``secret`` entry in the main CONF dict::

    'secret':{
        'env':'%s_SECRET' % ENVPREFIX,
        'cmdline':'secret',
        'type':str,
        'default':None,
        'help':('The shared secret key used to secure '
                'communications between authnzerver and any frontend servers.'),
        'readable_from_file':'string',
        'postprocess_value':None,
    }

This means the server will look at an environmental variable called
``AUTHNZERVER_SECRET``, falling back to the value provided in the ``--secret``
command line option. The ``readable_from_file`` key tells the server how to
handle the value it retrieved from either of these two sources.

To indicate that the retrieved value is to be used directly, set
``"readable_from_file" = False``.

To indicate that the retrieved value can either be: (i) used directly or, (ii)
may be a path to a file and the actual value of the ``secret`` item is a string
to be read from that file, set ``"readable_from_file" = "string"``.

To indicate that the retrieved value is a URL and the authnzerver must fetch the
actual secret from this URL, set::

    "readable_from_file" = ("http",
                            {'method':'get',
                             'headers':{header dict},
                             'data':{param dict},
                             'timeout':5.0},
                             'string')

Finally, you can also tell the server to fetch a JSON and pick out a key in the
JSON. See the docstring for :py:func:`authnzerver.confload.get_conf_item` for
more details on the various ways to retrieve the actual item pointed to by the
config variable key.

To make this example more concrete, if the authnzerver ``secret`` was stored as
a `GCP Secrets Manager
<https://cloud.google.com/secret-manager/docs/creating-and-accessing-secrets#access_a_secret_version>`_
item, you'd set some environmental variables like so::

    GCP_SECMAN_URL=https://secretmanager.googleapis.com/v1/projects/abcproj/secrets/abc/versions/z:access
    GCP_AUTH_TOKEN=some-secret-token

Then change the ``secret`` dict item in CONF dict below to::

    'secret':{
        'env':'GCP_SECMAN_URL',
        'cmdline':'secret',
        'type':str,
        'default':None,
        'help':('The shared secret key used to secure '
                'communications between authnzerver and any frontend servers.'),
        'readable_from_file':see below,
        'postprocess_value':'custom_decode.py::custom_b64decode',
    }

The ``readable_from_file`` key would be set to something like::

    "readable_from_file" = ("http",
                            {"method":"get",
                             "headers":{"Authorization":"Bearer [[GCP_AUTH_TOKEN]]",
                                        "Content-Type":"application/json",
                                        "x-goog-user-project": "abcproj"},
                             "data":None,
                             "timeout":5.0},
                            'json',
                            "payload.data")

This would then load the authnzerver ``secret`` directly from the Secrets
Manager.

Notice that we used a path to a Python module and function for the
``postprocess_value`` key. This is because GCP's Secrets Manager base-64 encodes
the data you put into it and we need to post-process the value we get back from
the stored item's URL. This module looks like::

    import base64

    def custom_b64decode(input):
        return base64.b64decode(input.encode('utf-8')).decode('utf-8')

The function above will base-64 decode the value returned from the Secrets
Manager and finally give us the ``secret`` value we need.


Launching the authnzerver
=========================

Running the executable from the Python package
----------------------------------------------

After you've installed the ``authnzerver`` package from PyPI (preferably in an
already-activated virtualenv), there will be an ``authnzrv`` executable in your
path.

``authnzrv --help`` will list all options available. See the section above for
details on configuring the server with either environment variables or
command-line options.

If you want to run authnzerver as a systemd service, there's an example `systemd
service file available
<https://github.com/waqasbhatti/authnzerver/blob/master/deploy/authnzerver.service>`_,
along with `an environment conf file
<https://github.com/waqasbhatti/authnzerver/blob/master/deploy/authnzerver-environ.conf>`_
that can be used to set it up.

Running with Docker and docker-compose
--------------------------------------

See below for an example docker-compose.yml snippet to include authnzerver as a
service.

.. code-block:: yaml

    volumes:
      authnzerver_basedir:

    services:
      authnzerver:
        image: waqasbhatti/authnzerver:latest
        expose: [13431]
        volumes:
          - authnzerver_basedir:/home/authnzerver/basedir
        # optional health check
        healthcheck:
          test: ["CMD-SHELL", "curl --silent --fail http://localhost:13431/health || exit 1"]
          interval: 10s
          timeout: 5s
          retries: 3
        environment:
          AUTHNZERVER_ALLOWEDHOSTS: authnzerver;localhost
          AUTHNZERVER_AUTHDB: "sqlite:////home/authnzerver/basedir/.authdb.sqlite"
          AUTHNZERVER_BASEDIR: "/home/authnzerver/basedir"
          AUTHNZERVER_DEBUGMODE: 0
          AUTHNZERVER_LISTEN: "0.0.0.0"
          AUTHNZERVER_PORT: 13431
          AUTHNZERVER_SECRET:
          AUTHNZERVER_PIISALT:
          AUTHNZERVER_SESSIONEXPIRY: 30
          AUTHNZERVER_USERLOCKTRIES: 10
          AUTHNZERVER_USERLOCKTIME: 3600
          AUTHNZERVER_PASSPOLICY: "min_pass_length:12;max_unsafe_similarity:50;max_char_frequency:0.3;min_pwned_matches:25"
          AUTHNZERVER_WORKERS: 4
          AUTHNZERVER_EMAILSERVER: "localhost"
          AUTHNZERVER_EMAILPORT: 25
          AUTHNZERVER_EMAILUSER: "authnzerver"
          AUTHNZERVER_EMAILPASS:
          AUTHNZERVER_EMAILSENDER: "Authnzerver <authnzerver@localhost>"
          AUTHNZERVER_TLSCERTFILE:
          AUTHNZERVER_TLSCERTKEY:
          AUTHNZERVER_RATELIMITS: "ipaddr:720; user:480; session:600; apikey:720; burst:150"

Some things to note about the snippet:

First, we're using an SQLite auth DB in the mounted authnzerver base
directory. Another database can be specified here by using the appropriate
`SQLAlchemy database URL
<https://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls>`_. On
every start up, the authnzerver will recreate its database tables only if these
don't exist already.

.. note:: For an example docker-compose file using PostgreSQL as the auth
          database, see `example-docker-compose-postgres.yml <https://github.com/waqasbhatti/authnzerver/blob/master/deploy/example-docker-compose-postgres.yml>`_ in the
          authnzerver Github repository.

Next, the required ``AUTHNZERVER_SECRET`` and ``AUTHNZERVER_PIISALT``
environment variables are passed in from the host environment. Set these in your
docker-compose ``.env`` file or in another manner as appropriate.  Make sure to
use strong random values here, for example:

.. code-block:: bash

    python3 -c "import secrets, base64; [print('AUTHNZERVER_%s=\"%s\"' % (x, base64.urlsafe_b64encode(secrets.token_bytes()).decode('utf-8'))) for x in ('SECRET','PIISALT')]"

Note that we're setting the listen address for the authnzerver to ``0.0.0.0`` so
it can listen to requests on its container's external network interface.

Finally, we're setting the ``AUTHNZERVER_ALLOWEDHOSTS`` environment variable to
include the DNS name of the container service generated by docker-compose:
``authnzerver``, as well as ``localhost``. The former allows requests from
within the docker-compose network (i.e. other containers relying on authnzerver)
to work correctly by using ``http://authnzerver:13431`` as the URL for the
authnzerver. The latter lets the Docker and docker-compose health checks work
correctly since these use cURL installed inside the container itself to ping the
server periodically.

Running with Docker in development mode with auto-setup
-------------------------------------------------------

First, pull the container from Docker Hub:

.. code-block:: bash

   docker pull waqasbhatti/authnzerver:latest

Run it with the ``--autosetup`` option to set up a base directory, the auth DB,
and the envfile. The commands below set up an empty base directory on your
Docker host, mount it into the container as a volume, then tell authnzerver to
use it for its base directory.

.. code-block:: bash

   mkdir authnzerver-basedir
   cd authnzerver-basedir
   docker run -p 13431:13431 -v $(PWD):/home/authnzerver/basedir \
     --rm -it waqasbhatti/authnzerver:latest \
     --autosetup --basedir=/home/authnzerver/basedir

This will start an interactive session where you can set your auth DB and
initial admin credentials::

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

Edit the ``.env`` file that was created in your Docker host's authnzerver base
directory. In particular, you want to set ``AUTHNZERVER_LISTEN`` variable to
``0.0.0.0`` for running authnzerver as a Docker container.

Start up authnzerver, using the command-line hints provided in autosetup:

.. code-block:: bash

   docker run -p 13431:13431 -v $(PWD):/home/authnzerver/basedir \
     --rm -it waqasbhatti/authnzerver:latest \
     --confvars="/home/authnzerver/basedir/confvars.py" \
     --envfile="/home/authnzerver/basedir/.env"

If you do not want to use the envfile (e.g. in production), add the variables in
it to your environment (e.g. in docker-compose) before launching the container,
then use:

.. code-block:: bash

   docker run -p 13431:13431 -v $(PWD):/home/authnzerver/basedir \
     --rm -it waqasbhatti/authnzerver:latest \
     --confvars="/home/authnzerver/basedir/confvars.py"
