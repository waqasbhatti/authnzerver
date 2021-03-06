# -*- coding: utf-8 -*-
# confvars.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Apr 2020
# License: MIT - see the LICENSE file for the full text.

'''Contains the configuration variables that define how the frontend works.

Similar to the backend's confvars.py file, The CONF dict in this file describes
how to load config variables for the authnzerver frontend from the environment
or command-line options. See the docs for :py:mod:`authnzerver.confvars` for
instructions on how to modify this file.

Repeating the warning from the backend's confvars.py file:

You MUST NOT store any actual secrets in this file; just define how to get to
them.

'''

import os

######################
## USEFUL CONSTANTS ##
######################

ENVPREFIX = 'AUTHNZRV_FRONTEND'


###############
## MAIN CONF ##
###############

CONF = {
    # NOTE: the frontend shares this environment variable with the authnzerver
    # backend instance
    'basedir':{
        'env':'AUTHNZERVER_BASEDIR',
        'cmdline':'basedir',
        'type':str,
        'default':os.getcwd(),
        'help':('The base directory containing the '
                'static/ and templates/ directories for the frontend'),
        'readable_from_file':False,
        'postprocess_value':None,
    },
    'baseurl':{
        'env':'AUTHNZERVER_BASEURL',
        'cmdline':'baseurl',
        'type':str,
        'default':'/auth',
        'help':("The base URL that the frontend will respond to. "
                "All other frontend URLs will be relative to this path."),
        'readable_from_file':False,
        'postprocess_value':None,
    },
    # NOTE: the frontend shares this environment variable with the authnzerver
    # backend instance
    'cache_dir':{
        'env':'AUTHNZERVER_CACHEDIR',
        'cmdline':'cachedir',
        'type':str,
        'default':'/tmp/authnzerver-cache',
        'help':('Path to the cache directory to be used.'),
        'readable_from_file':False,
        'postprocess_value':None,
    },
    'listen':{
        'env':'%s_LISTEN' % ENVPREFIX,
        'cmdline':'listen',
        'type':str,
        'default':'127.0.0.1',
        'help':('Bind to this address and serve content.'),
        'readable_from_file':False,
        'postprocess_value':None,
    },
    'listen_domain':{
        'env':'%s_LISTENDOMAIN' % ENVPREFIX,
        'cmdline':'listendomain',
        'type':str,
        'default':'localhost',
        'help':("Sets the domain name to which the server expects "
                "the 'Host' HTML header to be set to for incoming requests. "
                "This prevents DNS-rebinding attacks. "),
        'readable_from_file':False,
        'postprocess_value':None,
    },
    'port':{
        'env':'%s_PORT' % ENVPREFIX,
        'cmdline':'port',
        'type':int,
        'default':13441,
        'help':('Run the server on this TCP port.'),
        'readable_from_file':False,
        'postprocess_value':None,
    },
    # NOTE: the frontend shares this environment variable with the authnzerver
    # backend instance
    'authnzerver_key':{
        'env':'AUTHNZERVER_SECRET',
        'cmdline':'secret',
        'type':str,
        'default':None,
        'help':('The shared secret key used to secure '
                'communications between this server and the authnzerver.'),
        'readable_from_file':'string',
        'postprocess_value':None,
    },
    'authnzerver_url':{
        'env':'%s_AUTHNZRV_URL' % ENVPREFIX,
        'cmdline':'authnzerverurl',
        'type':str,
        'default':None,
        'help':('The URL and port where the '
                'authnzerver is listening for connections.'),
        'readable_from_file':False,
        'postprocess_value':None,
    },
    # NOTE: the frontend shares this environment variable with the authnzerver
    # backend instance
    'pii_salt':{
        'env':'AUTHNZERVER_PIISALT',
        'cmdline':'piisalt',
        'type':str,
        'default':None,
        'help':('A random value used as a salt when SHA256 hashing personally '
                'identifiable information (PII), such as user IDs and '
                'session tokens, etc. for logs.'),
        'readable_from_file':'string',
        'postprocess_value':None,
    },
    # NOTE: the frontend shares this environment variable with the authnzerver
    # backend instance
    'session_expiry_days':{
        'env':'AUTHNZERVER_SESSIONEXPIRY',
        'cmdline':'sessionexpiry',
        'type':int,
        'default':30,
        'help':('This sets the session-expiry time in days.'),
        'readable_from_file':False,
        'postprocess_value':None,
    },
    'api_key_expiry':{
        'env':'%s_APIKEYEXPIRY' % ENVPREFIX,
        'cmdline':'apikeyexpiry',
        'type':int,
        'default':30,
        'help':('This sets the API key expiry time in days.'),
        'readable_from_file':False,
        'postprocess_value':None,
    },
    'session_cookie_name':{
        'env':'%s_SESSIONCOOKIENAME' % ENVPREFIX,
        'cmdline':'sessioncookiename',
        'type':str,
        'default':'authnzrv-frontend-session',
        'help':('This sets the name of the session cookie that will be used.'),
        'readable_from_file':False,
        'postprocess_value':None,
    },
    'session_cookie_secure':{
        'env':'%s_SESSIONCOOKIESECURE' % ENVPREFIX,
        'cmdline':'sessioncookiesecure',
        'type':bool,
        'default':True,
        'help':('This indicates if the session '
                'cookies should be marked as "Secure".'),
        'readable_from_file':False,
        'postprocess_value':None,
    },
    'session_cookie_secret':{
        'env':'%s_SESSIONCOOKIESECRET' % ENVPREFIX,
        'cmdline':'sessioncookiesecret',
        'type':str,
        'default':None,
        'help':('This is the session cookie signing secret key.'),
        'readable_from_file':'string',
        'postprocess_value':None,
    },
    'tls_cert_file':{
        'env':'%s_TLSCERT_FILE' % ENVPREFIX,
        'cmdline':'tlscertfile',
        'type':str,
        'default':'',
        'help':('The TLS certificate to use. If this is provided along '
                'with the certificate key in the --tlscertkey option, '
                'the server will start in TLS-enabled mode.'),
        'readable_from_file':False,
        'postprocess_value':None,
    },
    'tls_cert_key':{
        'env':'%s_TLSCERT_KEY' % ENVPREFIX,
        'cmdline':'tlscertkey',
        'type':str,
        'default':'',
        'help':("The TLS certificate's key to use. If this is provided along "
                "with the certificate in the --tlscertfile option, "
                "the server will start in TLS-enabled mode."),
        'readable_from_file':False,
        'postprocess_value':None,
    },
    'workers':{
        'env':'%s_WORKERS' % ENVPREFIX,
        'cmdline':'workers',
        'type':int,
        'default':4,
        'help':('The number of background workers '
                'to use when processing requests.'),
        'readable_from_file':False,
        'postprocess_value':None,
    },
}
