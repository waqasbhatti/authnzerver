#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# main.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''
This is the main file for the authnzerver frontend.

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
import shutil

from cryptography.fernet import Fernet


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


########################################################
## CONFIG FROM ENVIRON, COMMAND LINE, AND SUBSTITUTES ##
########################################################

from .modtools import object_from_string
from .frontend_confvars import CONF

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
       default=os.path.join(modpath,'frontend_confvars.py'),
       help=('Path to the file containing the configuration '
             'variables needed by the server and how to load them.'),
       type=str)

# sets whether to copy over the static and template directories over to the
# basedir.  we'll check in the basedir first for these, and if found, will use
# them. if not found, we'll fall back to the static and templates directories as
# distributed in the authnzerver package.
define('autosetup',
       default=False,
       help=("If this is True, will automatically generate a "
             "random session cookie signing key, and copy over the "
             "Tornado templates/ and the JS+CSS static/ subdirectories "
             "from the installed package to the frontend's base directory. "
             "This makes it easy to customize the frontend's "
             "look and operation."),
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

    # get a logger
    LOGGER = logging.getLogger(__name__)
    LOGGER.setLevel(logging.INFO)

    ###################
    ## LOCAL IMPORTS ##
    ###################

    from .external.futures37.process import ProcessPoolExecutor
    from .confload import load_config

    ##############
    ## HANDLERS ##
    ##############

    from .basehandler import PageNotFoundHandler
    from . import baseuimodules
    from .sessionhandlers import (
        LoginHandler,
        LogoutHandler,
    )
    from .userhandlers import (
        NewUserHandler,
        VerifyUserHandler,
        DeleteUserHandler,
    )
    from .passwordhandlers import (
        ForgotPasswordStep1Handler,
        ForgotPasswordStep2Handler,
        ChangePasswordHandler,
    )

    ###################
    ## SET UP CONFIG ##
    ###################

    #
    # handle autosetup
    #

    # if autosetup is set, we'll copy over the static and templates directories,
    # then exit
    if options.autosetup:

        # templates directory
        LOGGER.warning("Copying Tornado templates shipped with "
                       "authnzerver to basedir: %s" %
                       options.basedir)
        try:
            shutil.copytree(os.path.join(modpath, 'templates'),
                            options.basedir)
        except Exception:
            LOGGER.warning("Not overwriting existing templates/ directory.")

        # static directory
        LOGGER.warning("Copying static/ directory shipped with "
                       "authnzerver to basedir: %s" %
                       options.basedir)
        try:
            shutil.copytree(os.path.join(modpath, 'static'),
                            options.basedir)
        except Exception:
            LOGGER.warning("Not overwriting existing static/ directory.")

        # frontend_confvars.py
        LOGGER.warning("Copying frontend_confvars.py to basedir: %s" %
                       options.basedir)
        shutil.copy(os.path.join(modpath,'frontend_confvars.py'),
                    options.basedir)

        # generate the session cookie secret
        LOGGER.info('Generating frontend session cookie signing secret key...')
        cookie_secret = Fernet.generate_key()
        cookie_secret_file = os.path.join(options.basedir,
                                          '.authnzrv-frontend-cookiesecret')

        if os.path.exists(cookie_secret_file):

            LOGGER.warning("Frontend cookie secret file already "
                           "exists. Not overwriting...")

        else:

            with open(cookie_secret_file,'wb') as outfd:
                outfd.write(cookie_secret)
            os.chmod(cookie_secret_file, 0o100400)

        LOGGER.warning("Auto-setup complete, exiting...")
        LOGGER.warning("To start the authnzerver frontend, call "
                       "authnzrv-frontend again with the "
                       "appropriate values set for the authnzerver URL, "
                       "the authnzerver key, the session cookie secret key, "
                       "and the PII salt in "
                       "either the command line options or "
                       "as environment variables.")
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
    LOGGER.info("The frontend server's base directory is: %s" %
                os.path.abspath(basedir))

    cachedir = loaded_config.cache_dir
    LOGGER.info("The frontend server's cache directory is: %s" %
                os.path.abspath(cachedir))

    port = loaded_config.port
    listen = loaded_config.listen
    sessionexpiry = loaded_config.session_expiry_days
    LOGGER.info('Session token expiry is set to: %s days' % sessionexpiry)

    baseurl = loaded_config.base_url
    LOGGER.info('Frontend base URL is set to: %s' % baseurl)

    ###################################
    ## EXECUTOR FOR BACKGROUND TASKS ##
    ###################################

    executor = ProcessPoolExecutor(
        max_workers=maxworkers,
    )

    ###################
    ## HANDLER SETUP ##
    ###################

    # we only have one actual endpoint, the other one is for testing
    handlers = [
        (rf'{baseurl}/login', LoginHandler,
         {'conf':loaded_config, 'executor':executor}),
        (rf'{baseurl}/logout', LogoutHandler,
         {'conf':loaded_config, 'executor':executor}),
        (rf'{baseurl}/users/new', NewUserHandler,
         {'conf':loaded_config, 'executor':executor}),
        (rf'{baseurl}/users/verify', VerifyUserHandler,
         {'conf':loaded_config, 'executor':executor}),
        (rf'{baseurl}/users/delete', DeleteUserHandler,
         {'conf':loaded_config, 'executor':executor}),
        (rf'{baseurl}/password/forgot-step1', ForgotPasswordStep1Handler,
         {'conf':loaded_config, 'executor':executor}),
        (rf'{baseurl}/password/forgot-step2', ForgotPasswordStep2Handler,
         {'conf':loaded_config, 'executor':executor}),
        (rf'{baseurl}/password/change', ChangePasswordHandler,
         {'conf':loaded_config, 'executor':executor}),
    ]

    ########################
    ## APPLICATION SET UP ##
    ########################

    # figure out the static path
    if os.path.exists(os.path.join(basedir, 'static')):
        static_dir = os.path.join(basedir,'static')
    else:
        static_dir = os.path.join(modpath, 'static')

    if os.path.exists(os.path.join(basedir, 'templates')):
        templates_dir = os.path.join(basedir,'templates')
    else:
        templates_dir = os.path.join(modpath, 'templates')

    app = tornado.web.Application(
        autoreload=False,  # this sometimes breaks Executors so disable it
        ui_modules=baseuimodules,
        static_path=static_dir,
        handlers=handlers,
        template_path=templates_dir,
        static_url_prefix=f'{baseurl}/static/',
        compress_response=True,
        cookie_secret=loaded_config.session_cookie_secret,
        xsrf_cookies=True,
        xsrf_cookie_kwargs={'samesite':'Lax'},
        default_handler_class=PageNotFoundHandler,
        default_handler_args={'conf':loaded_config, 'executor':executor},
    )

    # start up the HTTP server and our application
    http_server = tornado.httpserver.HTTPServer(app, xheaders=True)

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

        LOGGER.info('Starting authnzerver frontend. '
                    'Listening on http://%s:%s.' %
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


# run the server
if __name__ == '__main__':
    main()
