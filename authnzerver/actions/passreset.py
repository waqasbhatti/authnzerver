# -*- coding: utf-8 -*-
# actions_user.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""This contains functions to reset passwords.

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

import multiprocessing as mp

from sqlalchemy import select

from .. import authdb
from .session import auth_session_exists
from ..permissions import pii_hash

from argon2 import PasswordHasher

from .passwords import validate_input_password

######################
## PASSWORD CONTEXT ##
######################

pass_hasher = PasswordHasher()


def verify_password_reset(payload,
                          raiseonfail=False,
                          override_authdb_path=None,
                          min_pass_length=12,
                          max_unsafe_similarity=30,
                          config=None):
    """
    Verifies a password reset request.

    Parameters
    ----------

    payload : dict
        This is a dict with the following required keys:

        - email_address: str
        - new_password: str
        - session_token: str

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    min_pass_length : int
        The minimum required character length of the password.

    max_unsafe_similarity : int
        The maximum ratio required to fuzzy-match the input password against
        the server's domain name, the user's email, or their name.

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    dict
        Returns a dict containing a success key indicating if the user's
        password was reset.

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
                'messages': ["Invalid password reset request."],
            }

    for key in ('email_address',
                'new_password',
                'session_token'):

        if key not in payload:

            LOGGER.error(
                '[%s] Invalid password reset request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success': False,
                'failure_reason': (
                    "invalid request: missing '%s' in request" % key
                ),
                'messages': ["Invalid password reset request. "
                             "Some required parameters are missing."]
            }

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

    # check the session
    session_info = auth_session_exists(
        {'session_token': payload['session_token'],
         'pii_salt': payload['pii_salt'],
         'reqid': payload['reqid']},
        raiseonfail=raiseonfail,
        override_authdb_path=override_authdb_path
    )

    if not session_info['success']:

        LOGGER.error(
            "[%s] Password reset request failed for "
            "email: %s, session_token: %s. "
            "Provided session token was not found in the DB or has expired." %
            (payload['reqid'],
             pii_hash(payload['email_address'],
                      payload['pii_salt']),
             pii_hash(payload['session_token'],
                      payload['pii_salt']))
        )

        return {
            'success': False,
            'failure_reason': (
                "session does not exist"
            ),
            'messages': ([
                "Invalid session token for password reset request."
            ])
        }

    sel = select([
        users.c.user_id,
        users.c.full_name,
        users.c.email,
        users.c.password,
    ]).select_from(
        users
    ).where(
        users.c.email == payload['email_address']
    ).where(
        users.c.is_active.is_(True)
    )

    result = currproc.authdb_conn.execute(sel)
    user_info = result.fetchone()
    result.close()

    if not user_info or len(user_info) == 0:

        LOGGER.error(
            "[%s] Password reset request failed for "
            "email: %s, session_token: %s. "
            "User email was not found in the DB or the user is inactive." %
            (payload['reqid'],
             pii_hash(payload['email_address'],
                      payload['pii_salt']),
             pii_hash(payload['session_token'],
                      payload['pii_salt']))
        )

        return {
            'success': False,
            'failure_reason': (
                "user does not exist"
            ),
            'messages': ([
                "Invalid user for password reset request."
            ])
        }

    # let's hash the new password against the current password
    new_password = payload['new_password'][: 256]

    try:
        pass_same = pass_hasher.verify(
            user_info['password'],
            new_password,
        )
    except Exception:
        pass_same = False

    # don't fail here, but note that the user is re-using the password they
    # forgot. FIXME: should we actually fail here?
    if pass_same:

        LOGGER.warning(
            "[%s] Password reset request warning for "
            "email: %s, session_token: %s, user_id: %s. "
            "User is attempting to reuse the password they supposedly forgot." %
            (payload['reqid'],
             pii_hash(payload['email_address'],
                      payload['pii_salt']),
             pii_hash(payload['session_token'],
                      payload['pii_salt']),
             pii_hash(user_info['user_id'],
                      payload['pii_salt']))
        )

    # hash the user's password
    hashed_password = pass_hasher.hash(new_password)

    # validate the input password to see if it's OK
    # do this here to make sure the password hash completes at least once
    passok, messages = validate_input_password(
        user_info['full_name'],
        payload['email_address'],
        new_password,
        payload['pii_salt'],
        payload['reqid'],
        min_pass_length=min_pass_length,
        max_unsafe_similarity=max_unsafe_similarity,
        config=config,
    )

    if not passok:

        LOGGER.error(
            "[%s] Password reset request failed for "
            "email: %s, session_token: %s, user_id: %s. "
            "The new password is insecure." %
            (payload['reqid'],
             pii_hash(payload['email_address'],
                      payload['pii_salt']),
             pii_hash(payload['session_token'],
                      payload['pii_salt']),
             pii_hash(user_info['user_id'],
                      payload['pii_salt']))
        )

        return {
            'success': False,
            'failure_reason': (
                "invalid password"
            ),
            'messages': ([
                "Insecure password for password reset request."
            ] + messages)
        }

    # if the password passes validation, hash it and store it
    else:

        # update the table for this user
        upd = users.update(
        ).where(
            users.c.user_id == user_info['user_id']
        ).where(
            users.c.is_active.is_(True)
        ).where(
            users.c.email == payload['email_address']
        ).values({
            'password': hashed_password
        })
        currproc.authdb_conn.execute(upd)

        sel = select([
            users.c.password,
        ]).select_from(users).where(
            (users.c.email == payload['email_address'])
        )
        result = currproc.authdb_conn.execute(sel)
        rows = result.fetchone()
        result.close()

        if rows and rows['password'] == hashed_password:

            LOGGER.info(
                "[%s] Password reset request succeeded for "
                "email: %s, session_token: %s, user_id: %s. " %
                (payload['reqid'],
                 pii_hash(payload['email_address'],
                          payload['pii_salt']),
                 pii_hash(payload['session_token'],
                          payload['pii_salt']),
                 pii_hash(user_info['user_id'],
                          payload['pii_salt']))
            )

            messages.append('Password changed successfully.')
            return {
                'success': True,
                'messages': messages
            }

        else:

            LOGGER.error(
                "[%s] Password reset request failed for "
                "email: %s, session_token: %s, user_id: %s. "
                "The database row for the user could not be updated." %
                (payload['reqid'],
                 pii_hash(payload['email_address'],
                          payload['pii_salt']),
                 pii_hash(payload['session_token'],
                          payload['pii_salt']),
                 pii_hash(user_info['user_id'],
                          payload['pii_salt']))
            )

            messages.append('Password could not be changed.')
            return {
                'success': False,
                'failure_reason': (
                    "password update failed in DB"
                ),
                'messages': messages
            }


def verify_password_reset_nosession(
        payload,
        raiseonfail=False,
        override_authdb_path=None,
        min_pass_length=12,
        max_unsafe_similarity=30,
        config=None
):
    """Verifies a password reset request.

    This version does not require an active session.

    Parameters
    ----------

    payload : dict
        This is a dict with the following required keys:

        - email_address: str
        - new_password: str
        - required_active: bool

        The *required_active* parameter can be used to check the required state
        of the *is_active* DB entry for the user before password reset is
        allowed to proceed. This is useful when user accounts are required to be
        locked when a successful password reset verification token is received
        by a frontend server.

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    min_pass_length : int
        The minimum required character length of the password.

    max_unsafe_similarity : int
        The maximum ratio required to fuzzy-match the input password against
        the server's domain name, the user's email, or their name.

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    dict
        Returns a dict containing a success key indicating if the user's
        password was reset.

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
                'messages': ["Invalid password reset request."],
            }

    for key in ('email_address',
                'new_password',
                'required_active'):

        if key not in payload:

            LOGGER.error(
                '[%s] Invalid password reset request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success': False,
                'failure_reason': (
                    "invalid request: missing '%s' in request" % key
                ),
                'messages': ["Invalid password reset request. "
                             "Some required parameters are missing."]
            }

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

    required_active = payload["required_active"]

    sel = select([
        users.c.user_id,
        users.c.full_name,
        users.c.email,
        users.c.password,
    ]).select_from(
        users
    ).where(
        users.c.email == payload['email_address']
    ).where(
        users.c.is_active.is_(required_active)
    )

    result = currproc.authdb_conn.execute(sel)
    user_info = result.fetchone()
    result.close()

    if not user_info or len(user_info) == 0:

        LOGGER.error(
            "[%s] Password reset request failed for "
            "email: %s. "
            "User email was not found in the DB or the user is inactive." %
            (payload['reqid'],
             pii_hash(payload['email_address'],
                      payload['pii_salt']))
        )

        return {
            'success': False,
            'failure_reason': (
                "user does not exist or is_active was not as required"
            ),
            'messages': ([
                "Invalid user for password reset request."
            ])
        }

    # let's hash the new password against the current password
    new_password = payload['new_password'][: 256]

    try:
        pass_same = pass_hasher.verify(
            user_info['password'],
            new_password,
        )
    except Exception:
        pass_same = False

    # don't fail here, but note that the user is re-using the password they
    # forgot. FIXME: should we actually fail here?
    if pass_same:

        LOGGER.warning(
            "[%s] Password reset request warning for "
            "email: %s, user_id: %s. "
            "User is attempting to reuse the password they supposedly forgot." %
            (payload['reqid'],
             pii_hash(payload['email_address'],
                      payload['pii_salt']),
             pii_hash(user_info['user_id'],
                      payload['pii_salt']))
        )

    # hash the user's password
    hashed_password = pass_hasher.hash(new_password)

    # validate the input password to see if it's OK
    # do this here to make sure the password hash completes at least once
    passok, messages = validate_input_password(
        user_info['full_name'],
        payload['email_address'],
        new_password,
        payload['pii_salt'],
        payload['reqid'],
        min_pass_length=min_pass_length,
        max_unsafe_similarity=max_unsafe_similarity,
        config=config,
    )

    if not passok:

        LOGGER.error(
            "[%s] Password reset request failed for "
            "email: %s, user_id: %s. "
            "The new password is insecure." %
            (payload['reqid'],
             pii_hash(payload['email_address'],
                      payload['pii_salt']),
             pii_hash(user_info['user_id'],
                      payload['pii_salt']))
        )

        return {
            'success': False,
            'failure_reason': (
                "invalid new password"
            ),
            'messages': ([
                "Insecure new password for password reset request."
            ] + messages)
        }

    # if the password passes validation, hash it and store it
    else:

        # update the table for this user
        upd = users.update(
        ).where(
            users.c.user_id == user_info['user_id']
        ).where(
            users.c.is_active.is_(required_active)
        ).where(
            users.c.email == payload['email_address']
        ).values({
            'password': hashed_password
        })
        currproc.authdb_conn.execute(upd)

        sel = select([
            users.c.password,
        ]).select_from(users).where(
            (users.c.email == payload['email_address'])
        )
        result = currproc.authdb_conn.execute(sel)
        rows = result.fetchone()
        result.close()

        if rows and rows['password'] == hashed_password:

            LOGGER.info(
                "[%s] Password reset request succeeded for "
                "email: %s, user_id: %s. " %
                (payload['reqid'],
                 pii_hash(payload['email_address'],
                          payload['pii_salt']),
                 pii_hash(user_info['user_id'],
                          payload['pii_salt']))
            )

            messages.append('Password changed successfully.')
            return {
                'success': True,
                'messages': messages
            }

        else:

            LOGGER.error(
                "[%s] Password reset request failed for "
                "email: %s, user_id: %s. "
                "The database row for the user could not be updated." %
                (payload['reqid'],
                 pii_hash(payload['email_address'],
                          payload['pii_salt']),
                 pii_hash(user_info['user_id'],
                          payload['pii_salt']))
            )

            messages.append('Password could not be changed.')
            return {
                'success': False,
                'failure_reason': (
                    "password update failed in DB"
                ),
                'messages': messages
            }
