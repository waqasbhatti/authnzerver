#!/usr/bin/env python
# -*- coding: utf-8 -*-
# autosetup.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''This contains functions to set up the authnzerver automatically on first-start.

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


def autogen_secrets_authdb(basedir,
                           database_url=None,
                           interactive=False):
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

        - A random salt value will be written to ``.authnzerver-random-salt`` in
          this directory. This is used to hash user IDs and other PII in logs.

    database_url : str or None
        If this is a str, must be a valid SQLAlchemy database URL to use to
        connect to a database and make the necessary tables for authentication
        info. If this is None, will create a new SQLite database in the
        ``<basedir>/.authdb.sqlite`` file.

    interactive : bool
        If True, will ask the user for an admin email address and
        password. Otherwise, will auto-generate both.

    Returns
    -------

    (authdb_path, creds, secret_file, salt_file) : tuple of str
        The names of the files written by this function will be returned as a
        tuple of strings.

    '''

    import getpass
    from .authdb import (
        create_sqlite_authdb, initial_authdb_inserts, create_authdb
    )
    from cryptography.fernet import Fernet

    #
    # get the default permissions JSON
    #
    mod_dir = os.path.dirname(__file__)
    permissions_json = os.path.abspath(
        os.path.join(mod_dir, 'default-permissions-model.json')
    )

    if interactive:

        #
        # get the auth DB URL
        #
        LOGGER.warning(
            "Enter a valid SQLAlchemy database URL to use for the auth DB."
        )
        print("If you leave this blank and hit Enter, an SQLite auth DB")
        print("will be created in the base directory: %s" % basedir)
        input_db_url = input(
            "Auth DB URL [default: auto generated]: "
        )
        if not input_db_url or len(input_db_url) == 0:
            database_url = None

        LOGGER.warning(
            "Enter the path to the permissions policy JSON file to use."
        )
        print("If you leave this blank and hit Enter, the default permissions")
        print("policy JSON shipped with authnzerver will be used: %s" %
              permissions_json)
        input_permissions_json = input(
            "Permission JSON path [default: included permissions JSON]: "
        )
        if input_permissions_json and len(input_permissions_json) > 0:
            permissions_json = input_permissions_json

    if database_url is None:

        # create our authentication database if it doesn't exist
        authdb_path = os.path.join(basedir, '.authdb.sqlite')

        if not os.path.exists(authdb_path):
            LOGGER.warning('No existing authentication DB was found, '
                           'making a new SQLite DB in authnzerver basedir: %s'
                           % authdb_path)

        # generate the initial DB
        create_sqlite_authdb(authdb_path, echo=False, returnconn=False)
        database_url = 'sqlite:///%s' % authdb_path

    elif 'sqlite:///' in database_url:

        # generate the initial DB
        create_sqlite_authdb(authdb_path, echo=False, returnconn=False)

    else:

        create_authdb(database_url, echo=False, returnconn=False)

    # ask the user for their email address and password the default
    # email address will be used for the superuser if the email address
    # is None, we'll use the user's UNIX ID@localhost if the password is
    # None, a random one will be generated
    try:
        userid = '%s@localhost' % getpass.getuser()
    except Exception:
        userid = 'serveradmin@localhost'

    if interactive:

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

    else:
        password = None

    try:

        # generate the admin users and initial DB info
        u, p = initial_authdb_inserts(database_url,
                                      permissions_json=permissions_json,
                                      superuser_email=userid,
                                      superuser_pass=password)

        if not u and not p:
            LOGGER.error("Could not do initial inserts into the auth DB.")
            return None, None, None

    except Exception:

        LOGGER.warning(
            "Auth DB is already set up at the provided database URL. "
            "Not overwriting..."
        )

    creds = os.path.join(basedir,
                         '.authnzerver-admin-credentials')

    if os.path.exists(creds):

        LOGGER.warning("Admin credentials file already exists. "
                       "Not overwriting...")

    else:

        with open(creds,'w') as outfd:
            outfd.write('%s %s\n' % (u,p))
            os.chmod(creds, 0o100400)

        if p:
            LOGGER.warning('Generated random admin password, '
                           'credentials written to: %s\n' %
                           creds)

    # we'll generate the server secrets now so we don't have to deal
    # with them later
    LOGGER.info('Generating server secret tokens...')
    fernet_secret = Fernet.generate_key()
    fernet_secret_file = os.path.join(basedir,'.authnzerver-secret-key')

    if os.path.exists(fernet_secret_file):

        LOGGER.warning("Authnzerver communication secrets file already "
                       "exists. Not overwriting...")

    else:

        with open(fernet_secret_file,'wb') as outfd:
            outfd.write(fernet_secret)
        os.chmod(fernet_secret_file, 0o100400)

    # finally, we'll generate the server PII random salt
    LOGGER.info('Generating server PII random salt...')
    salt = Fernet.generate_key()
    salt_file = os.path.join(basedir,'.authnzerver-salt')

    if os.path.exists(salt_file):

        LOGGER.warning("Authnzerver salt file already "
                       "exists. Not overwriting...")

    else:

        with open(salt_file,'wb') as outfd:
            outfd.write(salt)
        os.chmod(salt_file, 0o100400)

    #
    # return everything
    #

    if database_url is not None:
        return database_url, creds, fernet_secret_file, salt_file
    else:
        return authdb_path, creds, fernet_secret_file, salt_file
