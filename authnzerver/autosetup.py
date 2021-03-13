# -*- coding: utf-8 -*-
# autosetup.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""This contains functions to set up the authnzerver automatically on
first-start.

"""

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
import shutil

from .modtools import object_from_string


# this is the module path
modpath = os.path.abspath(os.path.dirname(__file__))


def autogen_secrets_authdb(basedir,
                           database_url=None,
                           interactive=False,
                           generate_envfile=True):
    """This automatically generates secrets files and an authentication DB.

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

        - A random salt value will be written to ``.authnzerver-random-salt``
          in this directory. This is used to hash user IDs and other PII in
          logs.

    database_url : str or None
        If this is a str, must be a valid SQLAlchemy database URL to use to
        connect to a database and make the necessary tables for authentication
        info. If this is None, will create a new SQLite database in the
        ``<basedir>/.authdb.sqlite`` file.

    interactive : bool
        If True, will ask the user for an admin email address and
        password. Otherwise, will auto-generate both.

    generate_envfile : bool
        If True, generates an .env file in the basedir containing all the
        required information for the next start up of the server.

    Returns
    -------

    (authdb_path, creds, secret_file, salt_file, env_file) : tuple of str
        The names of the files written by this function will be returned as a
        tuple of strings.

    """

    if not os.path.exists(basedir):
        os.makedirs(os.path.abspath(basedir))

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

    # if no database_url is specified, create our auth DB in the basedir
    if database_url is None:
        authdb_path = os.path.join(basedir, '.authdb.sqlite')
        if not os.path.exists(authdb_path):
            LOGGER.warning('No existing authentication DB was found, '
                           'making a new SQLite DB in authnzerver basedir: %s'
                           % authdb_path)

        # generate the initial DB
        create_sqlite_authdb(authdb_path, echo=False, returnconn=False)
        database_url = 'sqlite:///%s' % authdb_path

    # otherwise, if there's an SQLite DB URL provided,
    # create it at the specified path
    elif database_url is not None and 'sqlite:///' in database_url:
        authdb_path = os.path.abspath(database_url.replace('sqlite:///', ''))
        if not os.path.exists(authdb_path):
            create_sqlite_authdb(authdb_path, echo=False, returnconn=False)

    # otherwise, use normal auth DB creation
    else:
        authdb_path = None
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

    u, p = None, None

    try:

        # generate the admin users and initial DB info
        u, p = initial_authdb_inserts(database_url,
                                      permissions_json=permissions_json,
                                      superuser_email=userid,
                                      superuser_pass=password)

        if u is None:
            LOGGER.error("Could not do initial inserts into the auth DB.")
            return None, None, None

    except Exception:

        LOGGER.warning(
            "Auth DB is already set up at the provided database URL. "
            "Not overwriting..."
        )

    creds = os.path.join(basedir, '.authnzerver-admin-credentials')

    if os.path.exists(creds):
        LOGGER.warning("Admin credentials file already exists. "
                       "Not overwriting...")

    elif u and p:
        with open(creds, 'w') as outfd:
            outfd.write('%s %s\n' % (u, p))
            os.chmod(creds, 0o100400)

        if p:
            LOGGER.warning('Generated random admin password, '
                           'credentials written to: %s\n' %
                           creds)

    # we'll generate the server secrets now so we don't have to deal
    # with them later
    LOGGER.info('Generating server secret tokens...')
    fernet_secret = Fernet.generate_key()
    fernet_secret_file = os.path.join(basedir, '.authnzerver-secret-key')

    if os.path.exists(fernet_secret_file):

        LOGGER.warning("Authnzerver communication secrets file already "
                       "exists. Not overwriting...")

    else:

        with open(fernet_secret_file, 'wb') as outfd:
            outfd.write(fernet_secret)
        os.chmod(fernet_secret_file, 0o100400)

    # finally, we'll generate the server PII random salt
    LOGGER.info('Generating server PII random salt...')
    salt = Fernet.generate_key()
    salt_file = os.path.join(basedir, '.authnzerver-salt')

    if os.path.exists(salt_file):

        LOGGER.warning("Authnzerver salt file already "
                       "exists. Not overwriting...")

    else:

        with open(salt_file, 'wb') as outfd:
            outfd.write(salt)
        os.chmod(salt_file, 0o100400)

    # copy over the permission model and confvars
    LOGGER.info(
        "Copying default-permissions-model.json to basedir: %s" %
        basedir
    )
    shutil.copy(
        os.path.join(modpath, 'default-permissions-model.json'),
        basedir
    )
    LOGGER.info(
        "Copying confvars.py to basedir: %s" %
        basedir
    )
    shutil.copy(
        os.path.join(modpath, 'confvars.py'),
        basedir
    )

    # generate the env file if asked for
    if generate_envfile:
        LOGGER.info(
            "Generating an envfile: %s" %
            os.path.join(basedir, '.env')
        )

        envfile = generate_env(
            database_url if database_url is not None else authdb_path,
            creds,
            fernet_secret_file,
            salt_file,
            basedir,
        )
    else:
        envfile = generate_env(
            database_url,
            creds,
            fernet_secret_file,
            salt_file,
            basedir,
        )

    #
    # return everything
    #

    if database_url is not None:
        return (database_url,
                creds,
                fernet_secret_file,
                salt_file,
                envfile)
    else:
        return (authdb_path,
                creds,
                fernet_secret_file,
                salt_file,
                envfile)


def generate_env(database_path,
                 creds,
                 fernet_secret_file,
                 salt_file,
                 basedir):
    """This generates environment variables containing the required items for
    authnzrv start up after autosetup is complete.

    If ``write_env_file`` is True, will write these to an ``.env`` file in the
    ``basedir``.

    Parameters
    ----------

    database_path : str
        The SQLAlchemy URL of the database to use, or the path on disk to an
        SQLite database. If ``database_path`` points to a file on disk, this
        function will assume it's an SQLite file and construct the appropriate
        SQLAlchemy database URL.

    creds : str
        The path to the admin credentials file.

    fernet_secret_file : str
        The path to the shared secret key needed to secure authnzerver-frontend
        communications.

    salt_file : str
        The path to the file containing the PII salt to encrypt PII in
        authnzerver logs.

    basedir : str
        The path to the authnzerver's basedir.

    Returns
    -------

    environ_file
        Returns the path to the ``.env`` file generated in the ``basedir`` as a
        string.

    """

    # first, figure out the database URL
    if os.path.exists(database_path):
        database_url = 'sqlite:///%s' % os.path.abspath(database_path)
    elif '://' in database_path:
        database_url = database_path
    else:
        LOGGER.error("Could not understand the database_path provided.")
        return None

    # get the confvar.py file and generate the env variables in it
    confvars = object_from_string(
        '%s::CONF' % os.path.join(basedir, 'confvars.py')
    )

    env_file = os.path.abspath(os.path.join(basedir, '.env'))

    with open(env_file, 'w') as outfd:

        for key, val in confvars.items():

            if key == 'authdb':
                env_key, env_val = val['env'], database_url

            elif key == 'secret':
                env_key, env_val = (val['env'],
                                    os.path.abspath(fernet_secret_file))

            elif key == 'piisalt':
                env_key, env_val = (val['env'],
                                    os.path.abspath(salt_file))

            elif key == 'permissions':
                env_key, env_val = (
                    val['env'],
                    os.path.abspath(
                        os.path.join(basedir,
                                     'default-permissions-model.json')
                    )
                )

            else:
                env_key, env_val = val['env'], val['default']

            # handle multiple env keys by assigning them all to the value
            if isinstance(env_key, (list, tuple)):
                for key_item in env_key:
                    outfd.write("%s=%s\n" % (key_item, env_val))
            else:
                outfd.write("%s=%s\n" % (env_key, env_val))

    return env_file
