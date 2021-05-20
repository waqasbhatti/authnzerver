#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# main.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""
This is the main file for the authnzerver, a simple authorization and
authentication server backed by SQLite, SQLAlchemy, and Tornado.

"""

#############
## LOGGING ##
#############

import logging

# setup a logger
LOGMOD = __name__


#############
## IMPORTS ##
#############

import os
import os.path
import socket
import sys
import signal
import time
import re
from functools import partial
from concurrent.futures import ProcessPoolExecutor
import random

from sqlalchemy.exc import IntegrityError

from . import dictcache


#####################
## TORNADO IMPORTS ##
#####################

try:
    import asyncio
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    IOLOOP_SPEC = 'uvloop'
except Exception:
    HAVE_UVLOOP = False
    IOLOOP_SPEC = 'asyncio'

import tornado.ioloop
import tornado.httpserver
import tornado.web
import tornado.options
from tornado.options import define, options
import multiprocessing as mp


#######################
## UTILITY FUNCTIONS ##
#######################

def _handle_mainproc_sigterm(signum, sigframe):
    """
    raises a KeyboardInterrupt for a SIGTERM so we can exit cleanly.

    """

    raise KeyboardInterrupt


def _setup_auth_worker(authdb_path,
                       fernet_secret,
                       permissions_json,
                       public_suffix_list):
    """This stores secrets and the auth DB path in the worker loop's context.

    The worker will then open the DB and set up its Fernet instance by itself.

    """

    # unregister interrupt signals so they don't get to the workers
    # and the executor can kill them cleanly (hopefully)
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    currproc = mp.current_process()
    currproc.name = 'Authnzrv-Worker-' + currproc.name

    currproc.auth_db_path = authdb_path
    currproc.fernet_secret = fernet_secret
    currproc.permissions_json = permissions_json
    currproc.public_suffix_list = public_suffix_list


########################################################
## CONFIG FROM ENVIRON, COMMAND LINE, AND SUBSTITUTES ##
########################################################

from .modtools import object_from_string
from .confvars import CONF

# this is the module path
modpath = os.path.abspath(os.path.dirname(__file__))

# load all of the conf vars as command-line options
for cv in CONF:
    define(CONF[cv]['cmdline'],
           default=CONF[cv]['default'],
           help=CONF[cv]['help'],
           type=CONF[cv]['type'])

#
# extra config options provided only as command-line parameters
#

# the path to an env file containing environment variables
define('envfile',
       default=None,
       help=('Path to a file containing environ variables '
             'for testing/development.'),
       type=str)

# the path to the confvar file
define('confvars',
       default=os.path.join(modpath, 'confvars.py'),
       help=('Path to the file containing the configuration '
             'variables needed by the server and how to load them.'),
       type=str)

# whether to make a new authdb if none exists
define('autosetup',
       default=False,
       help=("If this is True, will automatically generate an SQLite "
             "authentication database in the basedir, "
             "copy over default-permissions-model.json and "
             "confvars.py to the basedir for easy customization, and finally, "
             "generate the communications secret file and the PII salt file."),
       type=bool)


##########
## MAIN ##
##########

def main():
    """
    This is the main function.

    """

    # parse the command line
    tornado.options.parse_command_line()
    DEBUG = True if options.debugmode == 1 else False

    # get a logger
    LOGGER = logging.getLogger(__name__)
    if DEBUG:
        LOGGER.setLevel(logging.DEBUG)
    else:
        LOGGER.setLevel(logging.INFO)

    ###################
    ## LOCAL IMPORTS ##
    ###################

    from .autosetup import autogen_secrets_authdb
    from .confload import load_config
    from . import authdb as authdb_module
    from .validators import get_public_suffix_list

    ##############
    ## HANDLERS ##
    ##############

    from .handlers import AuthHandler
    from .healthcheck import HealthCheckHandler
    from . import actions

    ###################
    ## SET UP CONFIG ##
    ###################

    #
    # handle autosetup
    #

    # if autosetup is set, we'll generate the secret and auth DB, then exit
    # immediately
    if options.autosetup:

        authdb_path, creds, secret_file, salt_file, env_file = (
            autogen_secrets_authdb(
                options.basedir,
                interactive=True,
            )
        )

        LOGGER.warning(
            "Auto-setup complete, exiting..."
        )
        LOGGER.warning(
            "Environment variables needed for the authnzerver to start "
            "have been written to:\n\n%s\n\n"
            "Edit this file as appropriate or add these "
            "environment variables to the shell environment." %
            os.path.abspath(env_file)
        )
        LOGGER.warning(
            "To run the authnzerver with this env file, "
            "your selected auth DB, and the auto-setup generated "
            "secrets files in your selected authnzerver basedir, "
            "start authnzerver with the following command:\n\n%s\n" %
            ("authnzrv --basedir=\"%s\" --confvars=\"%s\" --envfile=\"%s\"" %
             (os.path.abspath(options.basedir),
              os.path.join(os.path.abspath(options.basedir),
                           'confvars.py'),
              os.path.abspath(env_file)))
        )
        sys.exit(0)

    # otherwise, we'll assume that all is well, and we'll proceed to load the
    # config from an envfile, command line args, or the environment.

    try:

        # update the conf dict with that loaded from confvars.py
        LOCAL_CONF = object_from_string(
            "%s::CONF" % options.confvars
        )
        CONF.update(LOCAL_CONF)

        loaded_config = load_config(CONF,
                                    options,
                                    envfile=options.envfile)

    except Exception:

        LOGGER.error("One or more config variables could not be set "
                     "from the environment, an envfile, or the command "
                     "line options. Exiting...")
        raise

    maxworkers = loaded_config.workers
    basedir = loaded_config.basedir
    LOGGER.info("The server's base directory is: %s" % os.path.abspath(basedir))

    port = loaded_config.port
    listen = loaded_config.listen
    sessionexpiry = loaded_config.sessionexpiry
    LOGGER.info('Session token expiry is set to: %s days' % sessionexpiry)

    # get the public suffix list for spam-checking full names of users
    public_suffix_list = get_public_suffix_list()

    #
    # set up the authdb, secret, and permissions model
    #
    auth_database_url = loaded_config.authdb
    secret = loaded_config.secret
    permissions = loaded_config.permissions

    ############################
    # SPIN UP WORKER PROCESSES #
    ############################

    #
    # this is the background executor we'll pass over to the handler
    #
    executor = ProcessPoolExecutor(
        max_workers=maxworkers,
        initializer=_setup_auth_worker,
        initargs=(auth_database_url, secret, permissions, public_suffix_list),
    )

    #
    # NOTE: we've switched to the usual concurrent.futures instead of our own
    # bundled version in external.futures
    #
    # NOTE: from Python 3.9+, ProcessPoolExecutor processes are spawned on
    # demand. we now map a sleep call to all processes so all of them are
    # ready at server start.
    #
    sleep_times = [random.random()/2.0 for x in range(maxworkers)]
    executor.map(time.sleep, sleep_times)

    # handle SIGTERM so we exit cleanly
    signal.signal(signal.SIGTERM, _handle_mainproc_sigterm)

    ##########################
    ## SET UP ALLOWED HOSTS ##
    ##########################

    # empty set to start with
    allowed_hosts = set({})

    # get any additional hosts to allow from the config
    config_allowed_hosts = loaded_config.allowedhosts.split(';')
    for h in config_allowed_hosts:
        if len(h.strip()) > 0:
            allowed_hosts.add(re.escape(h.strip()))

    allowed_hosts_regex = r"(%s)" % '|'.join(allowed_hosts)
    loaded_config.allowed_hosts_regex = re.compile(allowed_hosts_regex)
    LOGGER.info("Allowed host regex for incoming HTTP requests is: '%s'" %
                allowed_hosts_regex)

    ########################
    ## SET UP RATE LIMITS ##
    ########################

    # can disable rate limiting by passing none to the ratelimits conf item
    if loaded_config.ratelimits.strip().casefold() == 'none':
        loaded_config.ratelimits = False
        LOGGER.warning(
            "HTTP request rate-limiting "
            "has been disabled by setting 'none' for "
            "AUTHNZERVER_RATELIMITS or --ratelimits."
        )

    else:
        ratelimits = [x.strip().replace(' ', '').split(':')
                      for x in loaded_config.ratelimits.split(';')]
        ratelimits = {x[0]: int(x[1]) for x in ratelimits}
        loaded_config.ratelimits = ratelimits
        LOGGER.info(
            "HTTP request rate-limiting (requests/minute) "
            "config set to: %s" %
            ratelimits
        )

    ###########################################
    ## SET UP CACHE OBJECT FOR RATE-LIMITING ##
    ###########################################

    # initialize the cache
    cacheobj = dictcache.DictCache()

    ###################
    ## HANDLER SETUP ##
    ###################

    # we only have one actual endpoint, the other one is for testing
    handlers = [
        (r'/', AuthHandler,
         {'config': loaded_config,
          'cacheobj': cacheobj,
          'executor': executor,
          'failed_passchecks': {}}),
        (r'/health', HealthCheckHandler,
         {'config': loaded_config,
          'executor': executor,
          'cacheobj': cacheobj}),
    ]

    if DEBUG:
        # put in the echo handler for debugging
        from .debughandler import EchoHandler
        handlers.append(
            (r'/echo', EchoHandler,
             {'authdb': auth_database_url,
              'fernet_secret': secret,
              'executor': executor})
        )

    #############################
    ## SET UP TLS IF REQUESTED ##
    #############################

    if loaded_config.tls_cert_file and loaded_config.tls_cert_key:

        import ssl
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(loaded_config.tls_cert_file,
                                keyfile=loaded_config.tls_cert_key)
        ssl_ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        loaded_config.tls_enabled = True

    else:

        ssl_ctx = None
        loaded_config.tls_enabled = False

    ########################
    ## APPLICATION SET UP ##
    ########################

    app = tornado.web.Application(
        debug=DEBUG,
        autoreload=False,  # this sometimes breaks Executors so disable it
    )

    # try to guard against the DNS rebinding attack
    # http://www.tornadoweb.org/en/stable/guide/security.html#dns-rebinding
    app.add_handlers(allowed_hosts_regex, handlers)

    # start up the HTTP server and our application
    http_server = tornado.httpserver.HTTPServer(app, ssl_options=ssl_ctx)

    ##################
    ## CHECK THE DB ##
    ##################

    # check the authdb is set up with the correct tables
    # running these after the DB is already set up doesn't do anything
    if 'sqlite:///' in auth_database_url:

        sqlite_authdb_filepath = auth_database_url.replace('sqlite:///', '')

        LOGGER.info("Checking SQLite auth DB: %s..." % sqlite_authdb_filepath)
        authdb_module.create_sqlite_authdb(
            sqlite_authdb_filepath
        )
    else:
        LOGGER.info("Checking auth DB at provided auth DB URL...")
        authdb_module.create_authdb(
            auth_database_url
        )

    # do the initial inserts again, just to be sure
    # running these again won't do anything if they're set up already
    try:

        # get the admin email and password from the env if provided
        env_admin_email = os.environ.get("AUTHNZERVER_ADMIN_EMAIL", None)
        env_admin_pass = os.environ.get("AUTHNZERVER_ADMIN_PASSWORD", None)

        admin_user, admin_pass = authdb_module.initial_authdb_inserts(
            auth_database_url,
            permissions_json=permissions,
            superuser_email=env_admin_email,
            superuser_pass=env_admin_pass
        )
        LOGGER.warning("Auth DB at the provided URL was not previously "
                       "set up for use with authnzerver and has "
                       "been (re)initialized.")

        if env_admin_email and env_admin_pass:
            LOGGER.warning(
                "Admin user email and password were set using the "
                "provided environment variables."
            )

        creds = os.path.join(basedir,
                             '.authnzerver-admin-credentials')
        if os.path.exists(creds):
            LOGGER.warning("Admin credentials file already exists. "
                           "Writing to a new file...")
            creds = os.path.join(basedir,
                                 '.authnzerver-admin-credentials-%s'
                                 % int(time.time()))
        with open(creds, 'w') as outfd:
            outfd.write('%s %s\n' % (admin_user, admin_pass))
            os.chmod(creds, 0o100400)

        LOGGER.warning('Generated admin user '
                       'credentials were written to: %s\n' %
                       creds)

    except IntegrityError:

        LOGGER.info(
            "Auth DB is already set up "
            "at the provided database URL."
        )

    except Exception:
        LOGGER.error("Could not open the authentication "
                     "database at the provided URL.")
        raise

    # set up periodic session-killer function and kill old sessions
    session_killer = partial(actions.auth_kill_old_sessions,
                             session_expiry_days=sessionexpiry,
                             override_authdb_path=auth_database_url)
    session_killer()

    ######################
    ## start the server ##
    ######################

    try:
        http_server.listen(port, listen)
    except socket.error:
        LOGGER.error("Listen address TCP port: '%s:%s' is already "
                     "in use by another process, "
                     "bailing out..." % (listen, port))
        sys.exit(1)

    # start the IOLoop and begin serving requests
    loop = tornado.ioloop.IOLoop.current()

    try:

        # add our periodic callback for the session-killer
        # runs daily
        periodic_session_kill = tornado.ioloop.PeriodicCallback(
            session_killer,
            86400000.0,
            jitter=0.1,
        )
        periodic_session_kill.start()

        LOGGER.info(
            "Starting authnzerver. "
            "Listening on htt%s://%s:%s." %
            ("ps" if loaded_config.tls_enabled else "p",
             listen,
             port)
        )
        LOGGER.info("The server is starting with TLS %s." %
                    ('enabled' if loaded_config.tls_enabled else 'disabled'))
        LOGGER.info('Background worker processes: %s. IOLoop in use: %s.' %
                    (maxworkers, IOLOOP_SPEC))

        # start the IOLoop
        loop.start()

    except KeyboardInterrupt:

        LOGGER.warning('Received Ctrl-C: shutting down...')

        # stop the server
        http_server.stop()
        LOGGER.info('HTTP server shut down.')

        # close down the processpool
        executor.shutdown()
        time.sleep(2)
        LOGGER.info('Worker processes shut down.')

        # stop the loop
        loop.stop()
        LOGGER.info('IOLoop shut down.')


# run the server
if __name__ == '__main__':
    main()
