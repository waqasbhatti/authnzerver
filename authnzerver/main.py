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
except Exception as e:
    HAVE_UVLOOP = False
    IOLOOP_SPEC = 'asyncio'

import tornado.ioloop
import tornado.httpserver
import tornado.web
import tornado.options
from tornado.options import define, options
import multiprocessing as mp

########################################
### APPLICATION COMMAND-LINE OPTIONS ###
########################################

modpath = os.path.abspath(os.path.dirname(__file__))

#
# BASE DIRECTORY AND CACHE PATH
#

# basedir is the directory at the root where this server stores its auth DB and
# looks for secret keys.
define('basedir',
       default=os.getcwd(),
       help=('The base directory containing secret files and the auth DB.'),
       type=str)

# the path to the cache directory used to enforce API limits
define('cachedir',
       default='/tmp/authnzerver-cache',
       help=('Path to the cache directory used by the authnzerver.'),
       type=str)

#
# START UP OPTIONS
#

# the port to serve on
define('port',
       default=13431,
       help='Run on the given port.',
       type=int)

# the address to listen on
define('serve',
       default='127.0.0.1',
       help='Bind to given address and serve content.',
       type=str)

# whether to run in debugmode or not
define('debugmode',
       default=0,
       help='start up in debug mode if set to 1.',
       type=int)

# number of background threads in the pool executor
define('backgroundworkers',
       default=4,
       help=('number of background workers to use '),
       type=int)


#
# AUTH DB PATH
#

# whether to make a new authdb if none exists
define('autosetup',
       default=True,
       help=("If this is True, will automatically generate an SQLite "
             "authentication database in the basedir if there isn't one "
             "present and the value of the authdb option is also None."),
       type=bool)


# the path to the authentication DB
define('authdb',
       default=None,
       help=('An SQLAlchemy database URL to indicate where '
             'the local authentication DB is. '
             'This should be in the form discussed at: '
             'https://docs.sqlalchemy.org/en/latest'
             '/core/engines.html#database-urls'),
       type=str)

#
# SECRET KEYS AND SESSIONS
#

# alternatively, the file to get the secret key that secures HTTP communications
# between the authnzerver and any other processes.
define('secret',
       default=None,
       help=('Path to the file containing the secret key. '
             'This is relative to the path given in the basedir option.'),
       type=str)

# this defines how long a session is supposed to last
define('sessionexpiry',
       default=30,
       help=('This sets the session-expiry time in days.'),
       type=int)


#########################################
## CONFIG FROM ENVIRON AND SUBSTITUTES ##
#########################################

CONF = {
    'port':{
        'env':'AUTHNZERVER_PORT',
        'cmdline':'port',
        'type':int,
        'default':13431,
    },
    'listen':{
        'env':'AUTHNZERVER_LISTEN',
        'cmdline':'serve',
        'type':str,
        'default':'127.0.0.1',
    },
    'basedir':{
        'env':'AUTHNZERVER_BASEDIR',
        'cmdline':'basedir',
        'type':str,
        'default':os.getcwd(),
    },
    'cachedir':{
        'env':'AUTHNZERVER_CACHEDIR',
        'cmdline':'cachedir',
        'type':str,
        'default':'/tmp/authnzerver-cache',
    },
    'authdb':{
        'env':'AUTHNZERVER_AUTHDB',
        'cmdline':'authdb',
        'type':str,
        'default':None,
    },
    'secret':{
        'env':'AUTHNZERVER_SECRET',
        'cmdline':'secret',
        'type':str,
        'default':None,
    },
    'sessionexpiry':{
        'env':'AUTHNZERVER_SESSIONEXPIRY',
        'cmdline':'sessionexpiry',
        'type':int,
        'default':30,
    },

}


#######################
## UTILITY FUNCTIONS ##
#######################

def _setup_auth_worker(authdb_path,
                       fernet_secret):
    '''This stores secrets and the auth DB path in the worker loop's context.

    The worker will then open the DB and set up its Fernet instance by itself.

    '''
    # unregister interrupt signals so they don't get to the worker
    # and the executor can kill them cleanly (hopefully)
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    currproc = mp.current_process()
    currproc.auth_db_path = authdb_path
    currproc.fernet_secret = fernet_secret



def _close_authentication_database():

    '''This is used to close the authentication database when the worker loop
    exits.

    '''

    currproc = mp.current_process()
    if getattr(currproc, 'table_meta', None):
        del currproc.table_meta

    if getattr(currproc, 'connection', None):
        currproc.connection.close()
        del currproc.connection

    if getattr(currproc, 'engine', None):
        currproc.engine.dispose()
        del currproc.engine

    print('Shutting down database engine in process: %s' % currproc.name,
          file=sys.stdout)


##########
## MAIN ##
##########

def main():
    '''
    This is the main function.

    '''

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

    from .external.futures37.process import ProcessPoolExecutor
    from .secrets import get_secret, autogen_secrets_authdb


    ##############
    ## HANDLERS ##
    ##############

    from .handlers import AuthHandler, EchoHandler
    from . import cache
    from . import actions


    ###################
    ## SET UP CONFIG ##
    ###################

    maxworkers = options.backgroundworkers

    basedir = get_secret(CONF['basedir']['env'],
                         vartype=CONF['basedir']['type'],
                         default=CONF['basedir']['default'],
                         from_options_object=options,
                         options_object_attr=CONF['basedir']['cmdline'],
                         secret_file_read=False,
                         basedir=None)
    LOGGER.info("The server's base directory is: %s" % os.path.abspath(basedir))

    cachedir = get_secret(CONF['cachedir']['env'],
                          vartype=CONF['cachedir']['type'],
                          default=CONF['cachedir']['default'],
                          from_options_object=options,
                          options_object_attr=CONF['cachedir']['cmdline'],
                          secret_file_read=False,
                          basedir=basedir)
    LOGGER.info("The server's cache directory is: %s" %
                os.path.abspath(cachedir))

    port = get_secret(CONF['port']['env'],
                      vartype=CONF['port']['type'],
                      default=CONF['port']['default'],
                      from_options_object=options,
                      options_object_attr=CONF['port']['cmdline'],
                      secret_file_read=False,
                      basedir=basedir)

    listen = get_secret(CONF['listen']['env'],
                        vartype=CONF['listen']['type'],
                        default=CONF['listen']['default'],
                        from_options_object=options,
                        options_object_attr=CONF['listen']['cmdline'],
                        secret_file_read=False,
                        basedir=basedir)

    sessionexpiry = get_secret(
        CONF['sessionexpiry']['env'],
        vartype=CONF['sessionexpiry']['type'],
        default=CONF['sessionexpiry']['default'],
        from_options_object=options,
        options_object_attr=CONF['sessionexpiry']['cmdline'],
        secret_file_read=False,
        basedir=basedir
    )
    LOGGER.info('Session cookie expiry is set to: %s days' % sessionexpiry)


    #
    # set up the authdb and secret
    #

    try:
        authdb = get_secret(CONF['authdb']['env'],
                            vartype=CONF['authdb']['type'],
                            default=CONF['authdb']['default'],
                            from_options_object=options,
                            options_object_attr=CONF['authdb']['cmdline'],
                            secret_file_read=False,
                            basedir=basedir)
    except Exception as e:
        authdb = None

    try:
        secret = get_secret(CONF['secret']['env'],
                            vartype=CONF['secret']['type'],
                            default=CONF['secret']['default'],
                            from_options_object=options,
                            options_object_attr=CONF['secret']['cmdline'],
                            secret_file_read=True,
                            basedir=basedir)
    except Exception as e:
        secret = None

    # authdb and secret not provided but basedir was auto-setup in the past
    if ((not authdb) and
        (not secret) and
        (os.path.exists(os.path.join(basedir,'authnzerver-autosetup-done')))):

        authdb = 'sqlite:///%s' % os.path.abspath(
            os.path.join(basedir, '.authdb.sqlite')
        )
        with open(os.path.join(basedir, '.authnzerver-secret-key'),'r') as infd:
            secret = infd.read().strip('\n')

    # authdb and secret not provided and this is a completely new run
    elif ((not authdb) and
          (not secret) and
          (options.autosetup is True) and
          (not os.path.exists(os.path.join(basedir,
                                           'authnzerver-autosetup-done')))):

        authdb_path, admin_credentials, secret_file = autogen_secrets_authdb(
            options.basedir
        )

        authdb = 'sqlite:///%s' % authdb_path
        with open(secret_file,'r') as infd:
            secret = infd.read().strip('\n')

        with open(os.path.join(basedir,
                               'authnzerver-autosetup-done'),'w') as outfd:

            outfd.write('auto-setup run on: %sZ\n' % datetime.utcnow())
            outfd.write('authdb path: %s\n' % authdb_path)
            outfd.write('secret file: %s\n' % secret_file)


    # otherwise, we need authdb and secret from the user
    elif (((not authdb) or (not secret)) and
          (not os.path.exists(os.path.join(basedir,
                                           'authnzerver-autosetup-done')))):

        raise ValueError(
            "Can't find either an existing authentication DB or\n"
            "the secret token and the `autosetup` option was set to False.\n"
            "Please provide a valid SQLAlchemy DB connection string in the\n"
            "`%s` environ var or `%s` command-line option,\n"
            "and make sure you have set the `%s` environ var or\n"
            "the `%s` command-line option." %
            (CONF['authdb']['env'], CONF['authdb']['cmdline'],
             CONF['secret']['env'], CONF['secret']['cmdline'])
        )


    #
    # this is the background executor we'll pass over to the handler
    #
    executor = ProcessPoolExecutor(
        max_workers=maxworkers,
        initializer=_setup_auth_worker,
        initargs=(authdb, secret),
        finalizer=_close_authentication_database
    )

    # we only have one actual endpoint, the other one is for testing
    handlers = [
        (r'/', AuthHandler,
         {'authdb':authdb,
          'fernet_secret':secret,
          'executor':executor}),
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
        except socket.error as e:
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
        if getattr(currproc, 'table_meta', None):
            del currproc.table_meta

        if getattr(currproc, 'connection', None):
            currproc.connection.close()
            del currproc.connection

        if getattr(currproc, 'engine', None):
            currproc.engine.dispose()
            del currproc.engine

        print('Shutting down database engine in process: %s' % currproc.name,
              file=sys.stdout)


# run the server
if __name__ == '__main__':
    main()
