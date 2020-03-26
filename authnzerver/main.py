#!/usr/bin/env python
# -*- coding: utf-8 -*-
# main.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''
This is the main file for the authnzerver, a simple authorization and
authentication server backed by SQLite, SQLAlchemy, and Tornado.

'''

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
from datetime import datetime
from functools import partial


# setup signal trapping on SIGINT
def _recv_sigint(signum, stack):
    '''
    handler function to receive and process a SIGINT

    '''
    raise KeyboardInterrupt


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

def _setup_auth_worker(authdb_path,
                       fernet_secret,
                       permissions_json):
    '''This stores secrets and the auth DB path in the worker loop's context.

    The worker will then open the DB and set up its Fernet instance by itself.

    '''
    # unregister interrupt signals so they don't get to the worker
    # and the executor can kill them cleanly (hopefully)
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    currproc = mp.current_process()
    currproc.auth_db_path = authdb_path
    currproc.fernet_secret = fernet_secret
    currproc.permissions_json = permissions_json


def _close_authentication_database():

    '''This is used to close the authentication database when the worker loop
    exits.

    '''

    currproc = mp.current_process()
    if getattr(currproc, 'authdb_meta', None):
        del currproc.authdb_meta

    if getattr(currproc, 'authdb_conn', None):
        currproc.authdb_conn.close()
        del currproc.authdb_conn

    if getattr(currproc, 'authdb_engine', None):
        currproc.authdb_engine.dispose()
        del currproc.authdb_engine

    print('Shutting down database engine in process: %s' % currproc.name,
          file=sys.stdout)


########################################################
## CONFIG FROM ENVIRON, COMMAND LINE, AND SUBSTITUTES ##
########################################################

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

# whether to make a new authdb if none exists
define('autosetup',
       default=False,
       help=("If this is True, will automatically generate an SQLite "
             "authentication database in the basedir if there isn't one "
             "present and the value of the authdb option is also None."),
       type=bool)


##########
## MAIN ##
##########

def main():
    '''
    This is the main function.

    '''

    # parse the command line
    options.parse_command_line()
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

    from .external.futures37.process import ProcessPoolExecutor
    from .autosetup import autogen_secrets_authdb
    from .confload import load_config

    ##############
    ## HANDLERS ##
    ##############

    from .handlers import AuthHandler, EchoHandler
    from . import cache
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

        authdb_path, creds, secret_file, salt_file = autogen_secrets_authdb(
            options.basedir,
            interactive=True
        )
        LOGGER.warning("Auto-setup complete, exiting...")
        LOGGER.warning("To start the authnzerver with these parameters, call "
                       "authnzrv again with the appropriate values set "
                       "for the auth DB and the secret key in either the "
                       "command line options or as environment variables.")
        sys.exit(0)

    # otherwise, we'll assume that all is well, and we'll proceed to load the
    # config from an envfile, command line args, or the environment.

    try:

        loaded_config = load_config(CONF,
                                    options,
                                    envfile=options.envfile)

    except ValueError:

        LOGGER.error("One or more config variables could not be set "
                     "from the environment, an envfile, or the command "
                     "line options. Exiting...")
        raise

    maxworkers = loaded_config.workers
    basedir = loaded_config.basedir
    LOGGER.info("The server's base directory is: %s" % os.path.abspath(basedir))

    cachedir = loaded_config.cachedir
    LOGGER.info("The server's cache directory is: %s" %
                os.path.abspath(cachedir))

    port = loaded_config.port
    listen = loaded_config.listen
    sessionexpiry = loaded_config.sessionexpiry
    LOGGER.info('Session token expiry is set to: %s days' % sessionexpiry)

    #
    # set up the authdb, secret, and permissions model
    #
    authdb = loaded_config.authdb
    secret = loaded_config.secret
    permissions = loaded_config.permissions

    #
    # this is the background executor we'll pass over to the handler
    #
    executor = ProcessPoolExecutor(
        max_workers=maxworkers,
        initializer=_setup_auth_worker,
        initargs=(authdb, secret, permissions),
        finalizer=_close_authentication_database
    )

    ###################
    ## HANDLER SETUP ##
    ###################

    # we only have one actual endpoint, the other one is for testing
    handlers = [
        (r'/', AuthHandler,
         {'config':loaded_config,
          'executor':executor,
          'reqid_cache':set(),
          'failed_passchecks':{}}),
    ]

    if DEBUG:
        # put in the echo handler for debugging
        handlers.append(
            (r'/echo', EchoHandler,
             {'authdb':authdb,
              'fernet_secret':secret,
              'executor':executor})
        )

    ########################
    ## APPLICATION SET UP ##
    ########################

    app = tornado.web.Application(
        debug=DEBUG,
        autoreload=False,  # this sometimes breaks Executors so disable it
    )

    # try to guard against the DNS rebinding attack
    # http://www.tornadoweb.org/en/stable/guide/security.html#dns-rebinding
    app.add_handlers(r'(localhost|127\.0\.0\.1)',
                     handlers)

    # start up the HTTP server and our application
    http_server = tornado.httpserver.HTTPServer(app)

    ######################################################
    ## CLEAR THE CACHE AND REAP OLD SESSIONS ON STARTUP ##
    ######################################################

    removed_items = cache.cache_flush(
        cache_dirname=cachedir
    )
    LOGGER.info('Removed %s stale items from authnzerver cache.' %
                removed_items)

    session_killer = partial(actions.auth_kill_old_sessions,
                             session_expiry_days=sessionexpiry,
                             override_authdb_path=authdb)

    # run once at start up
    session_killer()

    ######################
    ## start the server ##
    ######################

    # register the signal callbacks
    signal.signal(signal.SIGINT, _recv_sigint)
    signal.signal(signal.SIGTERM, _recv_sigint)

    # make sure the port we're going to listen on is ok
    # inspired by how Jupyter notebook does this
    portok = False
    serverport = port
    maxtries = 10
    thistry = 0
    while not portok and thistry < maxtries:
        try:
            http_server.listen(serverport, listen)
            portok = True
        except socket.error:
            LOGGER.warning('%s:%s is already in use, trying port %s' %
                           (listen, serverport, serverport + 1))
            serverport = serverport + 1

    if not portok:
        LOGGER.error('Could not find a free port after %s tries, giving up' %
                     maxtries)
        sys.exit(1)

    # start the IOLoop and begin serving requests
    try:

        loop = tornado.ioloop.IOLoop.current()

        # add our periodic callback for the session-killer
        # runs daily
        periodic_session_kill = tornado.ioloop.PeriodicCallback(
            session_killer,
            86400000.0,
            jitter=0.1,
        )
        periodic_session_kill.start()

        LOGGER.info('Starting authnzerver. Listening on http://%s:%s.' %
                    (listen, serverport))
        LOGGER.info('Background worker processes: %s. IOLoop in use: %s.' %
                    (maxworkers, IOLOOP_SPEC))

        # start the IOLoop
        loop.start()

    except KeyboardInterrupt:

        LOGGER.info('Received Ctrl-C: shutting down...')

        # close down the processpool
        executor.shutdown()
        time.sleep(2)

        tornado.ioloop.IOLoop.instance().stop()

        currproc = mp.current_process()
        if getattr(currproc, 'authdb_meta', None):
            del currproc.authdb_meta

        if getattr(currproc, 'connection', None):
            currproc.authdb_conn.close()
            del currproc.authdb_conn

        if getattr(currproc, 'authdb_engine', None):
            currproc.authdb_engine.dispose()
            del currproc.authdb_engine

        print('Shutting down database engine in process: %s' % currproc.name,
              file=sys.stdout)


# run the server
if __name__ == '__main__':
    main()
