#!/usr/bin/env python
# -*- coding: utf-8 -*-
# secrets.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''
This contains functions to handle secrets.

'''

#############
## LOGGING ##
#############

import logging

# get a logger
LOGGER = logging.getLogger(__name__)


#############
## IMPORTS ##
#############

import os
import os.path


###############################
## SECRET HANDLING FUNCTIONS ##
###############################

def get_secret(secret_environvar,
               vartype=str,
               default=None,
               from_options_object=None,
               options_object_attr=None,
               secret_file_read=False,
               basedir=None):
    """This loads a secret from the environment or command-line options.

    The order of precedence is:

    1. environment variable
    2. command-line option

    Parameters
    ----------

    secret_environvar : str
        The environmental variable to get the secret from.

    vartype : Python type object: float, str, int, etc.
        The type to use to coerce the input variable to a specific Python type.

    default: Any
        The default value of the secret.

    from_options_object : Tornado options object
        If the environment variable isn't defined, the next place this function
        will try to get the secret value from is a passed in `Tornado options
        <http://www.tornadoweb.org/en/stable/options.html>`_ object, which
        parses command-line options.

    options_object_attr : str
        This is the attribute to look up in the options object for the value of
        the secret.

    secret_file_read : bool
        If this is True, will open the file pointed to by the secret and read it
        in as text, returning the secret within. If this is False, will only
        check if the file exists and return the absolute path to it.

    basedir : str
        The directory where the server will do its work. This is used to fill in
        '{{basedir}}' template values in any secret. By default, this is the
        current working directory.

    Returns
    -------

    Any
        The value of the secret.

    """

    if not basedir:
        basedir = os.getcwd()

    #
    # 1. check the environment variable
    #
    if secret_environvar is not None and secret_environvar in os.environ:

        secret = os.environ[secret_environvar]

        if len(secret.strip()) == 0 and default is None:

            raise EnvironmentError(
                'Secret from environment is either empty or not valid '
                'and no default was provided.'
            )

        elif len(secret.strip()) == 0 and default is not None:

            LOGGER.info(
                'Specified environment variable is invalid, '
                'using provided default.'
            )

            secret = default

            # handle special substitutions
            if isinstance(secret, str) and '{{basedir}}' in secret:
                secret = secret.replace('{{basedir}}',basedir)

            # if this is a file name to be read, read it
            if secret_file_read:
                with open(secret,'r') as infd:
                    secret = infd.read().strip('\n')
                    secret = vartype(secret)

            return secret

        # if all is well, return the secret
        # handle special substitutions
        if isinstance(secret, str) and '{{basedir}}' in secret:
            secret = secret.replace('{{basedir}}',basedir)

        # if this is a file name to be read, read it
        if secret_file_read:
            with open(secret,'r') as infd:
                secret = infd.read().strip('\n')

        return vartype(secret)


    #
    # 2. check the command-line options
    #
    elif ((secret_environvar is None or secret_environvar not in os.environ) and
          (from_options_object is not None) and
          (options_object_attr is not None)):

        secret = getattr(from_options_object, options_object_attr)

        if not secret and not default:

            raise ValueError(
                "Secret from command line options is empty or not valid and no"
                "default was provided."
            )

        elif not secret and default is not None:

            LOGGER.info(
                'Specified command-line option is invalid, '
                'using provided default.'
            )

            secret = default

            # handle special substitutions
            if isinstance(secret, str) and '{{basedir}}' in secret:
                secret = secret.replace('{{basedir}}',basedir)

            # if this is a file name to be read, read it
            if secret_file_read:
                with open(secret,'r') as infd:
                    secret = infd.read().strip('\n')
                    secret = vartype(secret)

            return secret

        # if all is well, handle the default case
        # handle special substitutions
        if isinstance(secret, str) and '{{basedir}}' in secret:
            secret = secret.replace('{{basedir}}',basedir)

        # if this is a file name to be read, read it
        if secret_file_read:
            with open(secret,'r') as infd:
                secret = infd.read().strip('\n')

        return secret


    #
    # if nothing worked, complain
    #
    else:

        raise IOError(
            'Could not load secret from the environment or '
            'command-line options.'
        )



def autogen_secrets_authdb(basedir):
    '''This automatically generates secrets files and an authentication DB.

    Run this only once on the first start of an authnzerver.

    Parameters
    ----------

    basedir : str
        The base directory of the authnzerver.
        - The authentication database will be written to a file called
          ``.authdb.sqlite`` in this directory.
        - The secret token to authenticate HTTP communications between the
          authnzerver and a frontend server will be written to a file called
          ``.authnzerver-secret-key`` in this directory.
        - Credentials for a superuser that can be used to edit various
          authnzerver options, and users will be written to
          ``.authnzerver-admin-credentials`` in this directory.

    Returns
    -------

    (authdb_path, creds, secret_file) : tuple of str
        The names of the files written by this function will be returned as a
        tuple of strings.

    '''

    import getpass
    from .authdb import create_sqlite_auth_db, initial_authdb_inserts
    from cryptography.fernet import Fernet

    # create our authentication database if it doesn't exist
    authdb_path = os.path.join(basedir, '.authdb.sqlite')

    LOGGER.warning('No existing authentication DB was found, '
                   'making a new one in authnzerver basedir: %s'
                   % authdb_path)

    # generate the initial DB
    create_sqlite_auth_db(authdb_path, echo=False, returnconn=False)

    # ask the user for their email address and password the default
    # email address will be used for the superuser if the email address
    # is None, we'll use the user's UNIX ID@localhost if the password is
    # None, a random one will be generated

    try:
        userid = '%s@localhost' % getpass.getuser()
    except Exception as e:
        userid = 'serveradmin@localhost'

    inp_userid = input(
        '\nAdmin email address [default: %s]: ' %
        userid
    )
    if inp_userid and len(inp_userid.strip()) > 0:
        userid = inp_userid

    inp_pass = getpass.getpass(
        'Admin password [default: randomly generated]: '
    )
    if inp_pass and len(inp_pass.strip()) > 0:
        password = inp_pass
    else:
        password = None

    # generate the admin users and initial DB info
    u, p = initial_authdb_inserts('sqlite:///%s' % authdb_path,
                                  superuser_email=userid,
                                  superuser_pass=password)

    creds = os.path.join(basedir,
                         '.authnzerver-admin-credentials')
    with open(creds,'w') as outfd:
        outfd.write('%s %s\n' % (u,p))
        os.chmod(creds, 0o100400)

    if p:
        LOGGER.warning('Generated random admin password, written to: %s\n' %
                       creds)

    # finally, we'll generate the server secrets now so we don't have to deal
    # with them later
    LOGGER.info('Generating server secret tokens...')
    fernet_secret = Fernet.generate_key()
    fernet_secret_file = os.path.join(basedir,'.authnzerver-secret-key')

    with open(fernet_secret_file,'wb') as outfd:
        outfd.write(fernet_secret)
    os.chmod(fernet_secret_file, 0o100400)

    return authdb_path, creds, fernet_secret_file
