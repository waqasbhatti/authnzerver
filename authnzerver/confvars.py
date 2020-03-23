#!/usr/bin/env python
# -*- coding: utf-8 -*-
# main.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''
This contains the configuration variables that define how the server operates.

'''

import os
import os.path
import getpass

######################
## USEFUL CONSTANTS ##
######################

this_dir = os.path.abspath(os.path.dirname(__file__))
default_permissions_file = os.path.abspath(
    os.path.join(this_dir,
                 'default-permissions-model.json')
)
currentuser = getpass.getuser()

ENVPREFIX = 'AUTHNZERVER'


###############
## MAIN CONF ##
###############

CONF = {
    'authdb':{
        'env':'%s_AUTHDB' % ENVPREFIX,
        'cmdline':'authdb',
        'type':str,
        'default':None,
        'help':('An SQLAlchemy database URL to indicate where '
                'the local authentication DB is. '
                'This should be in the form discussed at: '
                'https://docs.sqlalchemy.org/en/latest'
                '/core/engines.html#database-urls'),
        'readable_from_file':False,
    },
    'basedir':{
        'env':'%s_BASEDIR' % ENVPREFIX,
        'cmdline':'basedir',
        'type':str,
        'default':os.getcwd(),
        'help':('The base directory containing secret files and the auth DB.'),
        'readable_from_file':False,
    },
    'cachedir':{
        'env':'%s_CACHEDIR' % ENVPREFIX,
        'cmdline':'cachedir',
        'type':str,
        'default':'/tmp/authnzerver-cache',
        'help':('Path to the cache directory to be used.'),
        'readable_from_file':False,
    },
    'debugmode':{
        'env':'%s_DEBUGMODE' % ENVPREFIX,
        'cmdline':'debugmode',
        'type':int,
        'default':False,
        'help':('If 1, will enable an '
                '/echo endpoint for debugging purposes.'),
        'readable_from_file':False,
    },
    'listen':{
        'env':'%s_LISTEN' % ENVPREFIX,
        'cmdline':'listen',
        'type':str,
        'default':'127.0.0.1',
        'help':('Bind to this address and serve content.'),
        'readable_from_file':False,
    },
    'permissions':{
        'env':'%s_PERMISSIONS' % ENVPREFIX,
        'cmdline':'permissions',
        'type':str,
        'default':default_permissions_file,
        'help':('The JSON file containing the permissions '
                'model the server will enforce.'),
        'readable_from_file':False,
    },
    'port':{
        'env':'%s_PORT' % ENVPREFIX,
        'cmdline':'port',
        'type':int,
        'default':13431,
        'help':('Run the server on this TCP port.'),
        'readable_from_file':False,
    },
    'secret':{
        'env':'%s_SECRET' % ENVPREFIX,
        'cmdline':'secret',
        'type':str,
        'default':None,
        'help':('The shared secret key used to secure '
                'communications between authnzerver and any frontend servers.'),
        'readable_from_file':'string',
    },
    'piisalt':{
        'env':'%s_PIISALT' % ENVPREFIX,
        'cmdline':'piisalt',
        'type':str,
        'default':None,
        'help':('A random value used as a salt when SHA256 hashing personally '
                'identifiable information (PII), such as user IDs and '
                'session tokens, etc. for authnzerver logs.'),
        'readable_from_file':'string',
    },
    'sessionexpiry':{
        'env':'%s_SESSIONEXPIRY' % ENVPREFIX,
        'cmdline':'sessionexpiry',
        'type':int,
        'default':30,
        'help':('This sets the session-expiry time in days.'),
        'readable_from_file':False,
    },
    'workers':{
        'env':'%s_WORKERS' % ENVPREFIX,
        'cmdline':'workers',
        'type':int,
        'default':4,
        'help':('The number of background workers '
                'to use when processing requests.'),
        'readable_from_file':False,
    },
    'emailserver':{
        'env':'%s_EMAILSERVER' % ENVPREFIX,
        'cmdline':'emailserver',
        'type':str,
        'default':'localhost',
        'help':('The address of the email server to use.'),
        'readable_from_file':False,
    },
    'emailport':{
        'env':'%s_EMAILPORT' % ENVPREFIX,
        'cmdline':'emailport',
        'type':int,
        'default':25,
        'help':('The SMTP port of the email server to use.'),
        'readable_from_file':False,
    },
    'emailuser':{
        'env':'%s_EMAILUSER' % ENVPREFIX,
        'cmdline':'emailuser',
        'type':str,
        'default':currentuser,
        'help':('The username to use for login to the email server.'),
        'readable_from_file':False,
    },
    'emailpass':{
        'env':'%s_EMAILPASS' % ENVPREFIX,
        'cmdline':'emailpass',
        'type':str,
        'default':'',
        'help':('The password to use for login to the email server.'),
        'readable_from_file':False,
    },
    'emailsender':{
        'env':'%s_EMAILSENDER' % ENVPREFIX,
        'cmdline':'emailsender',
        'type':str,
        'default':'Authnzerver <authnzerver@localhost>',
        'help':('The account name and email address that the '
                'authnzerver will send from.'),
        'readable_from_file':False,
    },
}
