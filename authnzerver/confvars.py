# -*- coding: utf-8 -*-
# main.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""Contains the configuration variables that define how the server operates.

The CONF dict in this file describes how to load these variables from the
environment or command-line options.

You can change this file as needed. It will be copied over to the authnzerver's
base directory when ``authnzrv --autosetup`` is run and you can tell authnzerver
to use it like so:  ``authnzrv --confvars /path/to/basedir/confvars.py``.

You MUST NOT store any actual secrets in this file; just define how to get to
them.

For example, look at the ``secret`` dict entry below in CONF::

    'secret': {
        'env': '%s_SECRET' % ENVPREFIX,
        'cmdline': 'secret',
        'type': str,
        'default': None,
        'help': ('The shared secret key used to secure '
                'communications between authnzerver and any frontend servers.'),
        'readable_from_file': 'string',
        'postprocess_value': None,
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
                            {'method': 'get',
                             'headers': {header dict},
                             'data': {param dict},
                             'timeout': 5.0},
                             'string')

Finally, you can also tell the server to fetch a JSON and pick out a key in the
JSON. See the docstring for : py: func: `authnzerver.confload.get_conf_item` for
more details on the various ways to retrieve the actual item pointed to by the
config variable key.

To make this example more concrete, if the authnzerver ``secret`` was stored as
a `GCP Secrets Manager
<https://cloud.google.com/secret-manager/docs/creating-and-accessing-secrets#access_a_secret_version>`_
item, you'd set some environmental variables like so::

    GCP_SECMAN_URL=https://secretmanager.googleapis.com/v1/projects/abcproj/secrets/abc/versions/z:access
    GCP_AUTH_TOKEN=some-secret-token

Then change the ``secret`` dict item in CONF dict below to::

    'secret': {
        'env': 'GCP_SECMAN_URL',
        'cmdline': 'secret',
        'type': str,
        'default': None,
        'help': ('The shared secret key used to secure '
                'communications between authnzerver and any frontend servers.'),
        'readable_from_file': see below,
        'postprocess_value': 'custom_decode.py:: custom_b64decode',
    }

The ``readable_from_file`` key would be set to something like::

    "readable_from_file" = ("http",
                            {"method": "get",
                             "headers": {
                                 "Authorization": "Bearer [[GCP_AUTH_TOKEN]]",
                                 "Content-Type": "application/json",
                                 "x-goog-user-project": "abcproj"
                             },
                             "data": None,
                             "timeout": 5.0},
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

"""

import getpass
import os.path

######################
## USEFUL CONSTANTS ##
######################

this_dir = os.path.abspath(os.path.dirname(__file__))
default_permissions_file = os.path.abspath(
    os.path.join(this_dir, "default-permissions-model.json")
)
currentuser = getpass.getuser()

ENVPREFIX = "AUTHNZERVER"


###############
## MAIN CONF ##
###############

CONF = {
    "allowedhosts": {
        "env": "%s_ALLOWEDHOSTS" % ENVPREFIX,
        "cmdline": "allowedhosts",
        "type": str,
        "default": "localhost;127.0.0.1",
        "help": (
            'The allowed HTTP request header "Host" values '
            "that the server will respond to. "
            "Separate values with semicolons. Specifying "
            "these explicitly helps prevent DNS-rebinding attacks."
        ),
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "authdb": {
        "env": "%s_AUTHDB" % ENVPREFIX,
        "cmdline": "authdb",
        "type": str,
        "default": None,
        "help": (
            "An SQLAlchemy database URL to indicate where "
            "the local authentication DB is. "
            "This should be in the form discussed at: "
            "https://docs.sqlalchemy.org/en/latest"
            "/core/engines.html#database-urls"
        ),
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "basedir": {
        "env": "%s_BASEDIR" % ENVPREFIX,
        "cmdline": "basedir",
        "type": str,
        "default": os.getcwd(),
        "help": "The base directory containing secret files and the auth DB.",
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "debugmode": {
        "env": "%s_DEBUGMODE" % ENVPREFIX,
        "cmdline": "debugmode",
        "type": int,
        "default": 0,
        "help": (
            "If 1, will enable an " "/echo endpoint for debugging purposes."
        ),
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "listen": {
        "env": "%s_LISTEN" % ENVPREFIX,
        "cmdline": "listen",
        "type": str,
        "default": "127.0.0.1",
        "help": "Bind to this address and serve content.",
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "permissions": {
        "env": "%s_PERMISSIONS" % ENVPREFIX,
        "cmdline": "permissions",
        "type": str,
        "default": default_permissions_file,
        "help": (
            "The JSON file containing the permissions "
            "model the server will enforce."
        ),
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "port": {
        "env": ["PORT", "%s_PORT" % ENVPREFIX],
        "cmdline": "port",
        "type": int,
        "default": 13431,
        "help": "Run the server on this TCP port.",
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "secret": {
        "env": "%s_SECRET" % ENVPREFIX,
        "cmdline": "secret",
        "type": str,
        "default": None,
        "help": (
            "The shared secret key used to secure "
            "communications between authnzerver and any frontend servers."
        ),
        "readable_from_file": "string",
        "postprocess_value": None,
    },
    "piisalt": {
        "env": "%s_PIISALT" % ENVPREFIX,
        "cmdline": "piisalt",
        "type": str,
        "default": None,
        "help": (
            "A random value used as a salt when hashing personally "
            "identifiable information (PII), such as user IDs and "
            "session tokens, etc. for display and request correlation in "
            "the authnzerver logs. "
            "NOTE: if this is set to 'none', "
            "PII hashing is disabled and all IP addresses, "
            "emails, etc. in the authnzerver logs will be "
            "shown in plaintext."
        ),
        "readable_from_file": "string",
        "postprocess_value": None,
    },
    "sessionexpiry": {
        "env": "%s_SESSIONEXPIRY" % ENVPREFIX,
        "cmdline": "sessionexpiry",
        "type": int,
        "default": 30,
        "help": "This sets the session-expiry time in days.",
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "userlocktries": {
        "env": "%s_USERLOCKTRIES" % ENVPREFIX,
        "cmdline": "userlocktries",
        "type": int,
        "default": 10,
        "help": (
            "This sets the maximum number of failed logins per user "
            "that triggers a temporary lock on their account."
        ),
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "userlocktime": {
        "env": "%s_USERLOCKTIME" % ENVPREFIX,
        "cmdline": "userlocktime",
        "type": int,
        "default": 3600,
        "help": (
            "This sets the lockout time in seconds for failed user logins "
            "that exceed the maximum number of failed login tries."
        ),
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "passpolicy": {
        "env": "%s_PASSPOLICY" % ENVPREFIX,
        "cmdline": "passpolicy",
        "type": str,
        "default": (
            "min_pass_length:12; max_unsafe_similarity:50; "
            "max_char_frequency:0.3; min_pwned_matches:25"
        ),
        "help": (
            "This sets the minimum password length; "
            "the maximum allowed similarity (out of 100) "
            "between the password and unsafe items like the "
            "server's domain name, the user's own email address, "
            "or their full name; the maximum number of times a "
            "character can appear in the password as a "
            "fraction of the total number of characters in the password; "
            "and the minimum number of matches required against "
            "compromised passwords in the haveibeenpwned.com database."
        ),
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "ratelimits": {
        "env": "%s_RATELIMITS" % ENVPREFIX,
        "cmdline": "ratelimits",
        "type": str,
        "default": "ipaddr:720; user:480; session:600; apikey:720; burst:150",
        "help": (
            "This sets the rate limit policy for authnzerver actions. "
            "You can specify key-value pairs (semi-colon separated) for: "
            "all actions per IP address (of the frontend server client), "
            "user-tied actions (based on email/user_id/IP address), "
            "session-tied actions (based on session token/IP address), "
            "and apikey-tied actions (based on session token/IP address). "
            "The values are in units of max requests allowed per minute. "
            "The burst value indicates how many requests will be "
            "allowed to come in before rate-limits start being enforced. "
            "Set this to 'none' to turn off rate-limiting entirely. "
            "You can also override rate and burst limits for "
            "individual authnzerver API actions by specifying their names "
            "and the limit to use. "
            "For example, to set a max burst and limit of "
            "5 requests per minute for the "
            "API action 'user-new', add 'user-new:5' to the string here."
        ),
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "workers": {
        "env": "%s_WORKERS" % ENVPREFIX,
        "cmdline": "workers",
        "type": int,
        "default": 4,
        "help": (
            "The number of background workers "
            "to use when processing requests."
        ),
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "emailserver": {
        "env": "%s_EMAILSERVER" % ENVPREFIX,
        "cmdline": "emailserver",
        "type": str,
        "default": "localhost",
        "help": "The address of the email server to use.",
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "emailport": {
        "env": "%s_EMAILPORT" % ENVPREFIX,
        "cmdline": "emailport",
        "type": int,
        "default": 25,
        "help": "The SMTP port of the email server to use.",
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "emailuser": {
        "env": "%s_EMAILUSER" % ENVPREFIX,
        "cmdline": "emailuser",
        "type": str,
        "default": currentuser,
        "help": "The username to use for login to the email server.",
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "emailpass": {
        "env": "%s_EMAILPASS" % ENVPREFIX,
        "cmdline": "emailpass",
        "type": str,
        "default": "",
        "help": "The password to use for login to the email server.",
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "emailsender": {
        "env": "%s_EMAILSENDER" % ENVPREFIX,
        "cmdline": "emailsender",
        "type": str,
        "default": "Authnzerver <authnzerver@localhost>",
        "help": (
            "The account name and email address that the "
            "authnzerver will send from."
        ),
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "tls_cert_file": {
        "env": "%s_TLSCERTFILE" % ENVPREFIX,
        "cmdline": "tlscertfile",
        "type": str,
        "default": "",
        "help": (
            "The TLS certificate to use. If this is provided along "
            "with the certificate key in the --tlscertkey option, "
            "the server will start in TLS-enabled mode."
        ),
        "readable_from_file": False,
        "postprocess_value": None,
    },
    "tls_cert_key": {
        "env": "%s_TLSCERTKEY" % ENVPREFIX,
        "cmdline": "tlscertkey",
        "type": str,
        "default": "",
        "help": (
            "The TLS certificate's key to use. If this is provided along "
            "with the certificate in the --tlscertfile option, "
            "the server will start in TLS-enabled mode."
        ),
        "readable_from_file": False,
        "postprocess_value": None,
    },
}
