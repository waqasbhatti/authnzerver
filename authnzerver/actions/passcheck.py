# -*- coding: utf-8 -*-
# actions_session.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""This contains functions to drive session-related auth actions.

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

try:

    from datetime import timezone, timedelta
    utc = timezone.utc

except Exception:

    from datetime import timedelta, tzinfo
    ZERO = timedelta(0)

    class UTC(tzinfo):
        """UTC"""

        def utcoffset(self, dt):
            return ZERO

        def tzname(self, dt):
            return "UTC"

        def dst(self, dt):
            return ZERO

    utc = UTC()

import multiprocessing as mp

from sqlalchemy import select
from argon2 import PasswordHasher

from .. import authdb
from ..permissions import pii_hash

from .session import auth_session_exists


############################
## PASSWORD HASHER OBJECT ##
############################

pass_hasher = PasswordHasher()


############################################
## USER PASSWORD CHECK HANDLING FUNCTIONS ##
############################################

def auth_password_check(payload,
                        override_authdb_path=None,
                        raiseonfail=False,
                        config=None):
    """This runs a password check given a session token and password.

    Used to gate high-security areas or operations that require re-verification
    of the password for a user's existing session.

    Parameters
    ----------

    payload : dict
        This is a dict containing the following items:

        - session_token
        - password

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    override_authdb_path : str or None
        The SQLAlchemy database URL to use if not using the default auth DB.

    raiseonfail : bool
        If True, and something goes wrong, this will raise an Exception instead
        of returning normally with a failure condition.

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    dict
        Returns a dict containing the result of the password verification check.

    """

    for key in ('reqid', 'pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success': False,
                'failure_reason': (
                    "invalid request: missing '%s' in request" % key
                ),
                'user_id': None,
                'messages': ["Invalid password check request."],
            }

    # check broken request
    request_ok = True

    for item in ('password', 'session_token'):
        if item not in payload:
            request_ok = False
            break

    # this checks if the database connection is live
    currproc = mp.current_process()
    engine = getattr(currproc, 'authdb_engine', None)

    if override_authdb_path:
        currproc.auth_db_path = override_authdb_path

    if not engine:
        currproc.authdb_engine, currproc.authdb_conn, currproc.authdb_meta = (
            authdb.get_auth_db(
                currproc.auth_db_path,
                echo=raiseonfail
            )
        )

    users = currproc.authdb_meta.tables['users']

    #
    # check if the request is OK
    #

    # if it isn't, then hash the dummy user's password twice
    if not request_ok:

        # dummy session request
        auth_session_exists(
            {'session_token': 'nope',
             'reqid': payload['reqid'],
             'pii_salt': payload['pii_salt']},
            raiseonfail=raiseonfail,
            override_authdb_path=override_authdb_path
        )

        # always get the dummy user's password from the DB
        dummy_sel = select([
            users.c.password
        ]).select_from(users).where(users.c.user_id == 3)
        dummy_results = currproc.authdb_conn.execute(dummy_sel)

        dummy_password = dummy_results.fetchone()['password']
        dummy_results.close()

        try:
            pass_hasher.verify(dummy_password, 'nope')
        except Exception:
            pass

        # always get the dummy user's password from the DB
        dummy_sel = select([
            users.c.password
        ]).select_from(users).where(users.c.user_id == 3)
        dummy_results = currproc.authdb_conn.execute(dummy_sel)
        dummy_password = dummy_results.fetchone()['password']
        dummy_results.close()

        try:
            pass_hasher.verify(dummy_password, 'nope')
        except Exception:
            pass

        LOGGER.error(
            '[%s] Password check failed for session_token: %s. '
            'Missing request items.' %
            (payload['reqid'],
             pii_hash(payload['session_token'], payload['pii_salt']))
        )

        return {
            'success': False,
            'failure_reason': (
                "invalid request: missing either 'password' or 'session_token'"
            ),
            'user_id': None,
            'messages': ['Invalid password verification request.']
        }

    # otherwise, now we'll check if the session exists
    else:

        session_info = auth_session_exists(
            {'session_token': payload['session_token'],
             'reqid': payload['reqid'],
             'pii_salt': payload['pii_salt']},
            raiseonfail=raiseonfail,
            override_authdb_path=override_authdb_path
        )

        # if it doesn't, hash the dummy password twice
        if not session_info['success']:

            # always get the dummy user's password from the DB
            dummy_sel = select([
                users.c.password
            ]).select_from(users).where(users.c.user_id == 3)
            dummy_results = currproc.authdb_conn.execute(dummy_sel)
            dummy_password = dummy_results.fetchone()['password']
            dummy_results.close()

            try:
                pass_hasher.verify(dummy_password, 'nope')
            except Exception:
                pass

            # always get the dummy user's password from the DB
            dummy_sel = select([
                users.c.password
            ]).select_from(users).where(users.c.user_id == 3)
            dummy_results = currproc.authdb_conn.execute(dummy_sel)
            dummy_password = dummy_results.fetchone()['password']
            dummy_results.close()

            try:
                pass_hasher.verify(dummy_password, 'nope')
            except Exception:
                pass

            LOGGER.error(
                '[%s] Password check failed for session_token: %s. '
                'The session token provided does not exist.' %
                (payload['reqid'],
                 pii_hash(payload['session_token'], payload['pii_salt']))
            )
            return {
                'success': False,
                'failure_reason': (
                    "session does not exist"
                ),
                'user_id': None,
                'messages': ['No session token provided.']
            }

        # if the session token does exist, we'll proceed to checking the
        # password for the provided email
        else:

            # always get the dummy user's password from the DB
            dummy_sel = select([
                users.c.password
            ]).select_from(users).where(users.c.user_id == 3)
            dummy_results = currproc.authdb_conn.execute(dummy_sel)
            dummy_password = dummy_results.fetchone()['password']
            dummy_results.close()

            try:
                pass_hasher.verify(dummy_password, 'nope')
            except Exception:
                pass

            # look up the provided user
            user_sel = select([
                users.c.user_id,
                users.c.password,
                users.c.is_active,
                users.c.user_role,
            ]).select_from(
                users
            ).where(users.c.user_id == session_info['session_info']['user_id'])
            user_results = currproc.authdb_conn.execute(user_sel)
            user_info = user_results.fetchone()
            user_results.close()

            if user_info:

                try:

                    pass_ok = pass_hasher.verify(
                        user_info['password'],
                        payload['password'][: 256],
                    )

                except Exception as e:

                    LOGGER.error(
                        '[%s] Password check failed for session_token: %s. '
                        'The password provided does not match the one on '
                        'record for user_id: %s. Exception was: %r' %
                        (payload['reqid'],
                         pii_hash(payload['session_token'],
                                  payload['pii_salt']),
                         pii_hash(user_info['user_id'],
                                  payload['pii_salt']),
                         e)
                    )
                    pass_ok = False

            else:

                try:
                    pass_hasher.verify(dummy_password, 'nope')
                except Exception:
                    pass

                pass_ok = False

            if not pass_ok:

                return {
                    'success': False,
                    'failure_reason': (
                        "user does not exist or password doesn't match"
                    ),
                    'user_id': None,
                    'messages': ["Sorry, that user ID and "
                                 "password combination didn't work."]
                }

            # if password verification succeeeded, check if the user can
            # actually log in (i.e. their account is not locked or is not
            # inactive)
            else:

                # if the user account is active and unlocked, proceed.
                # the frontend will take this user_id and ask for a new session
                # token with it.
                if (user_info['is_active'] and
                    user_info['user_role'] != 'locked'):

                    LOGGER.info(
                        '[%s] Password check successful for session_token: %s. '
                        'Matched user with user_id: %s. ' %
                        (payload['reqid'],
                         pii_hash(payload['session_token'],
                                  payload['pii_salt']),
                         pii_hash(user_info['user_id'],
                                  payload['pii_salt']))
                    )

                    return {
                        'success': True,
                        'user_id': user_info['user_id'],
                        'user_role': user_info['user_role'],
                        'messages': ["Verification successful."]
                    }

                # if the user account is locked, return a failure
                else:

                    LOGGER.error(
                        '[%s] Password check failed for session_token: %s. '
                        'Matched user with user_id: %s is not active '
                        'or is locked.' %
                        (payload['reqid'],
                         pii_hash(payload['session_token'],
                                  payload['pii_salt']),
                         pii_hash(user_info['user_id'],
                                  payload['pii_salt']))
                    )

                    return {
                        'success': False,
                        'failure_reason': (
                            "user exists but is inactive"
                        ),
                        'user_id': user_info['user_id'],
                        'messages': ["Sorry, that user ID and "
                                     "password combination didn't work."]
                    }


def auth_password_check_nosession(payload,
                                  override_authdb_path=None,
                                  raiseonfail=False,
                                  config=None):
    """This runs a password check given an email address and password.

    Used to gate high-security areas or operations that require re-verification
    of the password for a user, without checking if they have a session.

    Useful for APIs, where the 'password' is some API token.

    Parameters
    ----------

    payload : dict
        This is a dict containing the following items:

        - email
        - password

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    override_authdb_path : str or None
        The SQLAlchemy database URL to use if not using the default auth DB.

    raiseonfail : bool
        If True, and something goes wrong, this will raise an Exception instead
        of returning normally with a failure condition.

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    dict
        Returns a dict containing the result of the password verification check.

    """

    for key in ('reqid', 'pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success': False,
                'failure_reason': (
                    "invalid request: missing '%s' in request" % key
                ),
                'user_id': None,
                'messages': ["Invalid password check request."],
            }

    # check broken request
    request_ok = True

    for item in ('password', 'email'):
        if item not in payload:
            request_ok = False
            break

    # this checks if the database connection is live
    currproc = mp.current_process()
    engine = getattr(currproc, 'authdb_engine', None)

    if override_authdb_path:
        currproc.auth_db_path = override_authdb_path

    if not engine:
        currproc.authdb_engine, currproc.authdb_conn, currproc.authdb_meta = (
            authdb.get_auth_db(
                currproc.auth_db_path,
                echo=raiseonfail
            )
        )

    users = currproc.authdb_meta.tables['users']

    #
    # check if the request is OK
    #

    # if it isn't, then hash the dummy user's password twice
    if not request_ok:

        # always get the dummy user's password from the DB
        dummy_sel = select([
            users.c.password
        ]).select_from(users).where(users.c.user_id == 3)
        dummy_results = currproc.authdb_conn.execute(dummy_sel)

        dummy_password = dummy_results.fetchone()['password']
        dummy_results.close()

        try:
            pass_hasher.verify(dummy_password, 'nope')
        except Exception:
            pass

        # always get the dummy user's password from the DB
        dummy_sel = select([
            users.c.password
        ]).select_from(users).where(users.c.user_id == 3)
        dummy_results = currproc.authdb_conn.execute(dummy_sel)
        dummy_password = dummy_results.fetchone()['password']
        dummy_results.close()

        try:
            pass_hasher.verify(dummy_password, 'nope')
        except Exception:
            pass

        LOGGER.error(
            '[%s] Password check failed for email: %s. '
            'Missing request items.' %
            (payload['reqid'],
             pii_hash(payload['email'], payload['pii_salt']))
        )

        return {
            'success': False,
            'failure_reason': (
                "invalid request: missing 'email' or 'password' in request"
            ),
            'user_id': None,
            'messages': ['Invalid password verification request.']
        }

    # otherwise, now we'll check if the user exists and the password is correct
    else:

        # always get the dummy user's password from the DB
        dummy_sel = select([
            users.c.password
        ]).select_from(users).where(users.c.user_id == 3)
        dummy_results = currproc.authdb_conn.execute(dummy_sel)
        dummy_password = dummy_results.fetchone()['password']
        dummy_results.close()

        try:
            pass_hasher.verify(dummy_password, 'nope')
        except Exception:
            pass

        # look up the provided user
        user_sel = select([
            users.c.user_id,
            users.c.password,
            users.c.is_active,
            users.c.user_role,
        ]).select_from(
            users
        ).where(users.c.email == payload['email'])
        user_results = currproc.authdb_conn.execute(user_sel)
        user_info = user_results.fetchone()
        user_results.close()

        pass_ok = False

        if user_info:

            try:

                pass_ok = pass_hasher.verify(
                    user_info['password'],
                    payload['password'][: 256],
                )

            except Exception as e:

                LOGGER.error(
                    '[%s] Password check failed for email: %s. '
                    'The password provided does not match the one on '
                    'record for user_id: %s. Exception was: %r' %
                    (payload['reqid'],
                     pii_hash(payload['email'],
                              payload['pii_salt']),
                     pii_hash(user_info['user_id'],
                              payload['pii_salt']),
                     e)
                )
                pass_ok = False

        # if the user doesn't exist, do a dummy pass hash
        else:

            try:
                pass_hasher.verify(dummy_password, 'nope')
            except Exception:
                pass

                pass_ok = False

        if not pass_ok:

            return {
                'success': False,
                'failure_reason': (
                    "user does not exist or password doesn't match"
                ),
                'user_id': None,
                'messages': ["Sorry, that user ID and "
                             "password combination didn't work."]
            }

        # if password verification succeeeded, check if the user can
        # actually log in (i.e. their account is not locked or is not
        # inactive)
        else:

            # if the user account is active and unlocked, proceed.
            # the frontend will take this user_id and ask for a new session
            # token with it.
            if (user_info['is_active'] and
                user_info['user_role'] != 'locked'):

                LOGGER.info(
                    '[%s] Password check successful for email: %s. '
                    'Matched user with user_id: %s. ' %
                    (payload['reqid'],
                     pii_hash(payload['email'],
                              payload['pii_salt']),
                     pii_hash(user_info['user_id'],
                              payload['pii_salt']))
                )

                return {
                    'success': True,
                    'user_id': user_info['user_id'],
                    'user_role': user_info['user_role'],
                    'messages': ["Verification successful."]
                }

            # if the user account is locked, return a failure
            else:

                LOGGER.error(
                    '[%s] Password check failed for email: %s. '
                    'Matched user with user_id: %s is not active '
                    'or is locked.' %
                    (payload['reqid'],
                     pii_hash(payload['email'],
                              payload['pii_salt']),
                     pii_hash(user_info['user_id'],
                              payload['pii_salt']))
                )

                return {
                    'success': False,
                    'failure_reason': (
                        "user exists but is inactive"
                    ),
                    'user_id': user_info['user_id'],
                    'messages': ["Sorry, that user ID and "
                                 "password combination didn't work."]
                }
