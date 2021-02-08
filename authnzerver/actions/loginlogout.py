# -*- coding: utf-8 -*-
# actions_session.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""This contains functions to log a user in and out.

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

from .session import (
    auth_session_exists,
    auth_session_delete,
)


############################
## PASSWORD HASHER OBJECT ##
############################

pass_hasher = PasswordHasher()


############################
## LOGIN/LOGOUT FUNCTIONS ##
############################

def auth_user_login(payload,
                    override_authdb_path=None,
                    raiseonfail=False,
                    config=None):
    """Logs a user in.

    Login flow for frontend:

    session cookie get -> check session exists -> check user login -> old
    session delete (no matter what) -> new session create (with actual user_id
    and other info now included if successful or same user_id = anon if not
    successful) -> done

    The frontend MUST unset the cookie as well.

    FIXME: update (and fake-update) the Users table with the last_login_try and
    last_login_success.

    Parameters
    ----------

    payload : dict
        The payload dict should contain the following keys:

        - session_token: str
        - email: str
        - password: str

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
                'messages': ["Invalid user login request."],
            }

    # check broken
    request_ok = True
    for item in ('email', 'password', 'session_token'):
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

        # run a fake session delete
        auth_session_delete({'session_token': 'nope',
                             'reqid': payload['reqid'],
                             'pii_salt': payload['pii_salt']},
                            raiseonfail=raiseonfail,
                            override_authdb_path=override_authdb_path)

        LOGGER.error(
            '[%s] User login failed for session_token: %s and '
            'provided email address: %s. '
            'Missing request items.' %
            (payload['reqid'],
             pii_hash(payload['session_token'], payload['pii_salt']),
             pii_hash(payload['email'], payload['pii_salt']))
        )

        return {
            'success': False,
            'failure_reason': (
                "invalid request: missing "
                "'session_token', 'email', or 'password' in request"
            ),
            'user_id': None,
            'messages': ['No session token provided.']
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

            # run a fake session delete
            auth_session_delete(
                {'session_token': 'nope',
                 'reqid': payload['reqid'],
                 'pii_salt': payload['pii_salt']},
                raiseonfail=raiseonfail,
                override_authdb_path=override_authdb_path
            )

            LOGGER.error(
                '[%s] User login failed for session_token: %s and '
                'email address: %s. '
                'The session token provided does not exist.' %
                (payload['reqid'],
                 pii_hash(payload['session_token'], payload['pii_salt']),
                 pii_hash(payload['email'], payload['pii_salt']))
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
            ]).select_from(users).where(
                users.c.email == payload['email']
            ).where(
                users.c.is_active.is_(True)
            ).where(
                users.c.email_verified.is_(True)
            )
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
                        '[%s] User login failed for session_token: %s and '
                        'email address: %s. '
                        'The password provided does not match the one on '
                        'record for user_id: %s. Exception was: %r' %
                        (payload['reqid'],
                         pii_hash(payload['session_token'],
                                  payload['pii_salt']),
                         pii_hash(payload['email'],
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

            # run a session delete on the provided token. the frontend will
            # always re-ask for a new session token on the next request after
            # login if it fails or succeeds.
            auth_session_delete(
                {'session_token': payload['session_token'],
                 'reqid': payload['reqid'],
                 'pii_salt': payload['pii_salt']},
                raiseonfail=raiseonfail,
                override_authdb_path=override_authdb_path
            )

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

                # we now check if the plain-text password provided to us needs
                # to be rehashed with newer parameters. this is useful when the
                # argon library updates its defaults. this is also needed when
                # we update our own values for the work factor, etc. parameters
                # when someone invents a better GPU password cracker machine.

                # check the stored hashed password's parameters
                pass_needs_rehash = pass_hasher.check_needs_rehash(
                    user_info['password']
                )

                # if they need to be updated, rehash the plain-text password
                # provided to us with the newer parameters and store it
                if pass_needs_rehash:

                    # rehash and store the new password
                    rehashed_password = pass_hasher.hash(
                        payload['password'][: 256]
                    )

                    # update the table for this user
                    upd = users.update(
                    ).where(
                        users.c.user_id == user_info['user_id']
                    ).where(
                        users.c.email == payload['email']
                    ).values({
                        'password': rehashed_password
                    })
                    result = currproc.authdb_conn.execute(upd)
                    result.close()

                    LOGGER.warning(
                        '[%s] Password rehashed for user '
                        'because Argon2 parameters '
                        'changed for session_token: %s and '
                        'email address: %s. '
                        'Matched user with user_id: %s. ' %
                        (payload['reqid'],
                         pii_hash(payload['session_token'],
                                  payload['pii_salt']),
                         pii_hash(payload['email'],
                                  payload['pii_salt']),
                         pii_hash(user_info['user_id'],
                                  payload['pii_salt']))
                    )

                # if the user account is active and unlocked, proceed.
                # the frontend will take this user_id and ask for a new session
                # token with it.
                if (user_info['is_active'] and
                    user_info['user_role'] != 'locked'):

                    LOGGER.info(
                        '[%s] User login successful for session_token: %s and '
                        'email address: %s. '
                        'Matched user with user_id: %s. ' %
                        (payload['reqid'],
                         pii_hash(payload['session_token'],
                                  payload['pii_salt']),
                         pii_hash(payload['email'],
                                  payload['pii_salt']),
                         pii_hash(user_info['user_id'],
                                  payload['pii_salt']))
                    )

                    return {
                        'success': True,
                        'user_id': user_info['user_id'],
                        'user_role': user_info['user_role'],
                        'messages': ["Login successful."]
                    }

                # if the user account is locked, return a failure
                else:

                    LOGGER.error(
                        '[%s] User login failed for session_token: %s and '
                        'email address: %s. '
                        'Matched user with user_id: %s is not active '
                        'or is locked.' %
                        (payload['reqid'],
                         pii_hash(payload['session_token'],
                                  payload['pii_salt']),
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


def auth_user_logout(payload,
                     override_authdb_path=None,
                     raiseonfail=False,
                     config=None):
    """Logs out a user.

    Deletes the session token from the session store. On the next request
    (redirect from POST /auth/logout to GET /), the frontend will issue a new
    one.

    The frontend MUST unset the cookie as well.

    Parameters
    ----------

    payload : dict
        The payload dict should contain the following keys:

        - session_token: str
        - user_id: int

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
                'messages': ["Invalid user logout request."],
            }

    for key in ('session_token', 'user_id'):
        if key not in payload:

            LOGGER.error(
                '[%s] Invalid user logout request, missing %s.' %
                (payload['reqid'], key)
            )
            return {
                'success': False,
                'failure_reason': (
                    "invalid request: missing '%s' in request" % key
                ),
                'messages': ["Invalid user logout request. "
                             "No %s provided." % key],
            }

    # check if the session token exists
    session = auth_session_exists(
        {'session_token': payload['session_token'],
         'reqid': payload['reqid'],
         'pii_salt': payload['pii_salt']},
        override_authdb_path=override_authdb_path,
        raiseonfail=raiseonfail)

    if session['success']:

        # check the user ID
        if payload['user_id'] == session['session_info']['user_id']:

            deleted = auth_session_delete(
                {'session_token': payload['session_token'],
                 'reqid': payload['reqid'],
                 'pii_salt': payload['pii_salt']},
                override_authdb_path=override_authdb_path,
                raiseonfail=raiseonfail
            )

            if deleted['success']:

                LOGGER.info(
                    "[%s] User logout request successful for "
                    "session_token: %s, user_id: %s. " %
                    (payload['reqid'],
                     pii_hash(payload['session_token'],
                              payload['pii_salt']),
                     pii_hash(payload['user_id'],
                              payload['pii_salt']))
                )

                return {
                    'success': True,
                    'user_id': session['session_info']['user_id'],
                    'messages': ["Logout successful."]
                }

            else:

                LOGGER.error(
                    "[%s] User logout request failed for "
                    "session_token: %s, user_id: %s. "
                    "Invalid user_id provided for "
                    "corresponding session token." %
                    (payload['reqid'],
                     pii_hash(payload['session_token'],
                              payload['pii_salt']),
                     pii_hash(payload['user_id'],
                              payload['pii_salt']))
                )
                return {
                    'success': False,
                    'failure_reason': (
                        "delete session failed"
                    ),
                    'user_id': payload['user_id'],
                    'messages': ["Logout failed. Invalid "
                                 "session_token for user_id."]
                }

        else:
            LOGGER.error(
                "[%s] User logout request failed for "
                "session_token: %s, user_id: %s. "
                "Invalid user_id provided for "
                "corresponding session token." %
                (payload['reqid'],
                 pii_hash(payload['session_token'],
                          payload['pii_salt']),
                 pii_hash(payload['user_id'],
                          payload['pii_salt']))
            )
            return {
                'success': False,
                'failure_reason': (
                    "user does not exist"
                ),
                'user_id': payload['user_id'],
                'messages': [
                    "Logout failed. Invalid session_token for user_id."
                ]
            }

    else:

        LOGGER.error(
            "[%s] User logout request failed for "
            "session_token: %s, user_id: %s. "
            "Invalid user_id provided for "
            "corresponding session token." %
            (payload['reqid'],
             pii_hash(payload['session_token'],
                      payload['pii_salt']),
             pii_hash(payload['user_id'],
                      payload['pii_salt']))
        )
        return {
            'success': False,
            'failure_reason': (
                "session does not exist"
            ),
            'user_id': payload['user_id'],
            'messages': ["Logout failed. Invalid "
                         "session_token for user_id."]
        }
