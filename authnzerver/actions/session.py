#!/usr/bin/env python
# -*- coding: utf-8 -*-
# actions_session.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''This contains functions to drive session-related auth actions.

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

try:

    from datetime import datetime, timezone, timedelta
    utc = timezone.utc

except Exception:

    from datetime import datetime, timedelta, tzinfo
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

import ipaddress
import secrets
import multiprocessing as mp

from sqlalchemy import select
from argon2 import PasswordHasher

from .. import authdb
from ..permissions import pii_hash


############################
## PASSWORD HASHER OBJECT ##
############################

pass_hasher = PasswordHasher()


################################
## SESSION HANDLING FUNCTIONS ##
################################

def auth_session_new(payload,
                     override_authdb_path=None,
                     raiseonfail=False):
    '''Generates a new session token.

    Parameters
    ----------

    payload : dict
        This is the input payload dict. Required items:

        - ip_address: str
        - user_agent: str
        - user_id: int or None (None indicates an anonymous user)
        - expires: datetime object or date string in ISO format
        - extra_info_json: dict or None

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    Returns
    -------

    dict
        The dict returned is of the form::

        {'success: True or False,
         'session_token': str session token 32 bytes long in base64 format,
         'expires': str date in ISO format,
         'messages': list of str messages to pass on to the user if any}

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'session_token':None,
                'expires':None,
                'messages':["Invalid session initiation request."],
            }

    # fail immediately if the required payload items are not present
    for item in ('ip_address',
                 'user_agent',
                 'user_id',
                 'expires',
                 'extra_info_json'):

        if item not in payload:

            LOGGER.error(
                '[%s] Invalid session initiation request, missing %s.' %
                (payload['reqid'], item)
            )

            return {
                'success':False,
                'session_token':None,
                'expires':None,
                'messages':["Invalid session initiation request. "
                            "Missing some parameters."]
            }

    try:

        validated_ip = str(ipaddress.ip_address(payload['ip_address']))
        payload['ip_address'] = validated_ip

        # set the userid to anonuser@localhost if no user is provided
        if not payload['user_id']:
            payload['user_id'] = 2

        # check if the payload expires key is a string and not a datetime.time
        # and reform it to a datetime if necessary
        if isinstance(payload['expires'],str):

            # this is assuming UTC
            payload['expires'] = datetime.strptime(
                payload['expires'].replace('Z',''),
                '%Y-%m-%dT%H:%M:%S.%f'
            )

        # this checks if the database connection is live
        currproc = mp.current_process()
        engine = getattr(currproc, 'authdb_engine', None)

        if override_authdb_path:
            currproc.auth_db_path = override_authdb_path

        if not engine:
            (currproc.authdb_engine,
             currproc.authdb_conn,
             currproc.authdb_meta) = (
                authdb.get_auth_db(
                    currproc.auth_db_path,
                    echo=raiseonfail
                )
            )

        # generate a session token
        session_token = secrets.token_urlsafe(32)

        payload['session_token'] = session_token
        payload['created'] = datetime.utcnow()

        # get the insert object from sqlalchemy
        sessions = currproc.authdb_meta.tables['sessions']
        insert = sessions.insert().values({
            'session_token':session_token,
            'ip_address':payload['ip_address'],
            'user_agent':payload['user_agent'],
            'user_id':payload['user_id'],
            'expires':payload['expires'],
            'extra_info_json':payload['extra_info_json'],
        })
        result = currproc.authdb_conn.execute(insert)
        result.close()

        LOGGER.info(
            "[%s] New session initiated for "
            "user_id: %s with IP address: %s, user agent: %s. Expires on: %s" %
            (payload['reqid'],
             pii_hash(payload['user_id'], payload['pii_salt']),
             pii_hash(payload['ip_address'], payload['pii_salt']),
             pii_hash(payload['user_agent'], payload['pii_salt']),
             payload['expires'])
        )

        return {
            'success':True,
            'session_token':session_token,
            'expires':payload['expires'].isoformat(),
            'messages':["Generated session_token successfully. "
                        "Session initiated."]
        }

    except Exception as e:

        LOGGER.error(
            "[%s] Could not create a new session for "
            "user_id: %s with IP address: %s, user agent: %s. "
            "Exception was: %r" %
            (payload['reqid'],
             pii_hash(payload['user_id'], payload['pii_salt']),
             pii_hash(payload['ip_address'], payload['pii_salt']),
             pii_hash(payload['user_agent'], payload['pii_salt']),
             e)
        )

        if raiseonfail:
            raise

        return {
            'success':False,
            'session_token':None,
            'expires':None,
            'messages':["Could not create a new session."],
        }


def auth_session_set_extrainfo(payload,
                               raiseonfail=False,
                               override_authdb_path=None):
    '''Adds info to the extra_info_json key of a session column.

    Parameters
    ----------

    payload : dict
        This should contain the following items:

        - session_token : str, the session token to update
        - extra_info : dict, the update dict to put into the extra_info_json

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    raiseonfail : bool
        If True, and something goes wrong, this will raise an Exception instead
        of returning normally with a failure condition.

    override_authdb_path : str or None
        The SQLAlchemy database URL to use if not using the default auth DB.

    Returns
    -------

    dict
        Returns a dict containing the new session info dict.

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'session_token':None,
                'expires':None,
                'messages':["Invalid session set_extrainfo request."],
            }

    for key in ('session_token',
                'extra_info'):

        if key not in payload:

            LOGGER.error(
                '[%s] Invalid session set_extrainfo request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success':False,
                'session_info':None,
                'messages':["Invalid session set_extrainfo request: "
                            "missing or invalid parameters."],
            }

    session_token = payload['session_token']
    extra_info = payload['extra_info']

    try:

        # this checks if the database connection is live
        currproc = mp.current_process()
        engine = getattr(currproc, 'authdb_engine', None)

        if override_authdb_path:
            currproc.auth_db_path = override_authdb_path

        if not engine:
            (currproc.authdb_engine,
             currproc.authdb_conn,
             currproc.authdb_meta) = (
                authdb.get_auth_db(
                    currproc.auth_db_path,
                    echo=raiseonfail
                )
            )

        sessions = currproc.authdb_meta.tables['sessions']

        upd = sessions.update(
        ).where(
            sessions.c.session_token == session_token
        ).values({'extra_info_json':extra_info})
        result = currproc.authdb_conn.execute(upd)

        s = select([
            sessions.c.user_id,
            sessions.c.session_token,
            sessions.c.ip_address,
            sessions.c.user_agent,
            sessions.c.created,
            sessions.c.expires,
            sessions.c.extra_info_json
        ]).select_from(sessions).where(
            (sessions.c.session_token == session_token) &
            (sessions.c.expires > datetime.utcnow())
        )
        result = currproc.authdb_conn.execute(s)
        rows = result.fetchone()
        result.close()

        try:

            serialized_result = dict(rows)

            LOGGER.info(
                "[%s] Session info updated for "
                "user_id: %s with IP address: %s, "
                "user agent: %s, session_token: %s. "
                "Session expires on: %s" %
                (payload['reqid'],
                 pii_hash(serialized_result['user_id'],
                          payload['pii_salt']),
                 pii_hash(serialized_result['ip_address'],
                          payload['pii_salt']),
                 pii_hash(serialized_result['user_agent'],
                          payload['pii_salt']),
                 pii_hash(serialized_result['session_token'],
                          payload['pii_salt']),
                 serialized_result['expires'])
            )

            return {
                'success':True,
                'session_info':serialized_result,
                'messages':["Session extra_info update successful."],
            }

        except Exception as e:

            LOGGER.error(
                "[%s] Session info update failed for session token: %s. "
                "Exception was: %r." %
                (payload['reqid'],
                 pii_hash(payload['session_token'],
                          payload['pii_salt']),
                 e)
            )

            return {
                'success':False,
                'session_info':None,
                'messages':["Session extra_info update failed."],
            }

    except Exception as e:

        LOGGER.error(
            "[%s] Session info update failed for session token: %s. "
            "Exception was: %r." %
            (payload['reqid'],
             pii_hash(payload['session_token'],
                      payload['pii_salt']),
             e)
        )

        return {
            'success':False,
            'session_info':None,
            'messages':["Session extra_info update failed."],
        }


def auth_session_exists(
        payload,
        override_authdb_path=None,
        raiseonfail=False,
):
    '''
    Checks if the provided session token exists.

    Parameters
    ----------

    payload : dict
        This is a dict, with the following keys required:

        - session_token: str

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    Returns
    -------

    dict
         Returns a dict containing all of the session info if it exists and has
         not expired.

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'session_info':None,
                'messages':["Invalid session info request."],
            }

    if 'session_token' not in payload:
        LOGGER.error(
            '[%s] Invalid session info request, missing session_token.' %
            payload['reqid']
        )

        return {
            'success':False,
            'session_info':None,
            'messages':["No session token provided."],
        }

    session_token = payload['session_token']

    try:

        # this checks if the database connection is live
        currproc = mp.current_process()
        engine = getattr(currproc, 'authdb_engine', None)

        if override_authdb_path:
            currproc.auth_db_path = override_authdb_path

        if not engine:
            (currproc.authdb_engine,
             currproc.authdb_conn,
             currproc.authdb_meta) = (
                authdb.get_auth_db(
                    currproc.auth_db_path,
                    echo=raiseonfail
                )
            )

        sessions = currproc.authdb_meta.tables['sessions']
        users = currproc.authdb_meta.tables['users']
        s = select([
            users.c.user_id,
            users.c.system_id,
            users.c.full_name,
            users.c.email,
            users.c.email_verified,
            users.c.emailverify_sent_datetime,
            users.c.is_active,
            users.c.last_login_try,
            users.c.last_login_success,
            users.c.created_on,
            users.c.user_role,
            sessions.c.session_token,
            sessions.c.ip_address,
            sessions.c.user_agent,
            sessions.c.created,
            sessions.c.expires,
            sessions.c.extra_info_json
        ]).select_from(users.join(sessions)).where(
            (sessions.c.session_token == session_token) &
            (sessions.c.expires > datetime.utcnow())
        )
        result = currproc.authdb_conn.execute(s)
        rows = result.fetchone()
        result.close()

        try:

            serialized_result = dict(rows)

            LOGGER.info(
                "[%s] Session info request successful for "
                "user_id: %s with IP address: %s, "
                "user agent: %s, session_token: %s. "
                "Session expires on: %s" %
                (payload['reqid'],
                 pii_hash(serialized_result['user_id'],
                          payload['pii_salt']),
                 pii_hash(serialized_result['ip_address'],
                          payload['pii_salt']),
                 pii_hash(serialized_result['user_agent'],
                          payload['pii_salt']),
                 pii_hash(serialized_result['session_token'],
                          payload['pii_salt']),
                 serialized_result['expires'])
            )

            return {
                'success':True,
                'session_info':serialized_result,
                'messages':["Session look up successful."],
            }

        except Exception as e:

            LOGGER.error(
                "[%s] Session info lookup failed for session token: %s. "
                "Exception was: %r." %
                (payload['reqid'],
                 pii_hash(payload['session_token'],
                          payload['pii_salt']),
                 e)
            )

            return {
                'success':False,
                'session_info':None,
                'messages':["Session look up failed."],
            }

    except Exception as e:

        LOGGER.error(
            "[%s] Session info lookup failed for session token: %s. "
            "Exception was: %r." %
            (payload['reqid'],
             pii_hash(payload['session_token'],
                      payload['pii_salt']),
             e)
        )

        return {
            'success':False,
            'session_info':None,
            'messages':["Session look up failed."],
        }


def auth_session_delete(
        payload,
        override_authdb_path=None,
        raiseonfail=False,
):
    '''
    Removes a session token, effectively ending a session.

    Parameters
    ----------

    payload : dict
        This is a dict with the following required keys:

        - session_token: str

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    Returns
    -------

    dict
        Returns a dict with a success key indicating if the session was deleted
        successfully.

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'messages':["Invalid session delete request."],
            }

    if 'session_token' not in payload:

        LOGGER.error(
            '[%s] Invalid session delete request, missing session_token.' %
            payload['reqid']
        )

        return {
            'success':False,
            'messages':["Invalid session delete request. "
                        "No session token provided."],
        }

    session_token = payload['session_token']

    try:

        # this checks if the database connection is live
        currproc = mp.current_process()
        engine = getattr(currproc, 'authdb_engine', None)

        if override_authdb_path:
            currproc.auth_db_path = override_authdb_path

        if not engine:
            (currproc.authdb_engine,
             currproc.authdb_conn,
             currproc.authdb_meta) = (
                authdb.get_auth_db(
                    currproc.auth_db_path,
                    echo=raiseonfail
                )
            )

        sessions = currproc.authdb_meta.tables['sessions']
        delete = sessions.delete().where(
            sessions.c.session_token == session_token
        )
        result = currproc.authdb_conn.execute(delete)
        result.close()

        LOGGER.info(
            "[%s] Session delete request successful for "
            "session_token: %s. " %
            (payload['reqid'],
             pii_hash(payload['session_token'],
                      payload['pii_salt']))
        )

        return {
            'success':True,
            'messages':["Session deleted successfully."],
        }

    except Exception as e:

        LOGGER.error(
            "[%s] Session delete request failed for "
            "session_token: %s. Exception was: %r." %
            (payload['reqid'],
             pii_hash(payload['session_token'],
                      payload['pii_salt']), e)
        )

        if raiseonfail:
            raise

        return {
            'success':False,
            'messages':["Session could not be deleted."],
        }


def auth_delete_sessions_userid(
        payload,
        override_authdb_path=None,
        raiseonfail=False,
):
    '''Removes all session tokens corresponding to a user ID.

    If keep_current_session is True, will not delete the session token passed in
    the payload. This allows for "delete all my other logins" functionality.

    Parameters
    ----------

    payload : dict
        This is a dict with the following required keys:

        - session_token: str
        - user_id: int
        - keep_current_session: bool

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    Returns
    -------

    dict
        Returns a dict with a success key indicating if the sessions were
        deleted successfully.

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'messages':["Invalid session delete request."],
            }

    for key in ('user_id',
                'session_token',
                'keep_current_session'):

        if key not in payload:

            LOGGER.error(
                '[%s] Invalid session delete request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success':False,
                'messages':["Missing or invalid parameters "
                            "auth_delete_sessions_userid."],
            }

    user_id = payload['user_id']
    session_token = payload['session_token']
    keep_current_session = payload['session_token']

    try:

        # this checks if the database connection is live
        currproc = mp.current_process()
        engine = getattr(currproc, 'authdb_engine', None)

        if override_authdb_path:
            currproc.auth_db_path = override_authdb_path

        if not engine:
            (currproc.authdb_engine,
             currproc.authdb_conn,
             currproc.authdb_meta) = (
                authdb.get_auth_db(
                    currproc.auth_db_path,
                    echo=raiseonfail
                )
            )

        sessions = currproc.authdb_meta.tables['sessions']

        if keep_current_session:
            delete = sessions.delete().where(
                sessions.c.user_id == user_id
            ).where(
                sessions.c.session_token != session_token
            )

        else:
            delete = sessions.delete().where(
                sessions.c.user_id == user_id
            )

        result = currproc.authdb_conn.execute(delete)
        result.close()

        LOGGER.info(
            "[%s] Session delete request successful for "
            "user_id: %s, keep_current_session was set to %s." %
            (payload['reqid'],
             pii_hash(payload['user_id'],
                      payload['pii_salt']),
             payload['keep_current_session'])
        )

        return {
            'success':True,
            'messages':["Sessions deleted successfully."],
        }

    except Exception as e:

        LOGGER.error(
            "[%s] Session delete request failed for "
            "user_id: %s. Exception was: %s." %
            (payload['reqid'],
             pii_hash(payload['user_id'],
                      payload['pii_salt']),
             e)
        )

        if raiseonfail:
            raise

        return {
            'success':False,
            'messages':["Sessions could not be deleted."],
        }


def auth_kill_old_sessions(
        session_expiry_days=7,
        override_authdb_path=None,
        raiseonfail=False,
):
    '''
    Kills all expired sessions.

    Parameters
    ----------

    session_expiry_days : int
        All sessions older than the current datetime + this value will be
        deleted.

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    Returns
    -------

    dict
        Returns a dict with a success key indicating if the sessions were
        deleted successfully.

    '''

    expires_days = session_expiry_days
    earliest_date = datetime.utcnow() - timedelta(days=expires_days)

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

    sessions = currproc.authdb_meta.tables['sessions']

    sel = select(
        [sessions.c.session_token,
         sessions.c.created,
         sessions.c.expires]
    ).select_from(
        sessions
    ).where(sessions.c.expires < earliest_date)

    result = currproc.authdb_conn.execute(sel)
    rows = result.fetchall()
    result.close()

    if len(rows) > 0:

        LOGGER.warning('Will kill %s sessions older than %sZ.' %
                       (len(rows), earliest_date.isoformat()))

        delete = sessions.delete().where(
            sessions.c.expires < earliest_date
        )
        result = currproc.authdb_conn.execute(delete)
        result.close()

        return {
            'success':True,
            'messages':["%s sessions older than %sZ deleted." %
                        (len(rows),
                         earliest_date.isoformat())]
        }

    else:

        LOGGER.warning(
            'No sessions older than %sZ found to delete.' %
            earliest_date.isoformat()
        )
        return {
            'success':False,
            'messages':['No sessions older than %sZ found to delete' %
                        earliest_date.isoformat()]
        }


###################################
## USER LOGIN HANDLING FUNCTIONS ##
###################################

def auth_password_check(payload,
                        override_authdb_path=None,
                        raiseonfail=False):
    '''This runs a password check given a session token and password.

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

    Returns
    -------

    dict
        Returns a dict containing the result of the password verification check.

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_id':None,
                'messages':["Invalid password check request."],
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
        session_info = auth_session_exists(
            {'session_token':'nope',
             'reqid':payload['reqid'],
             'pii_salt':payload['pii_salt']},
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
            'success':False,
            'user_id':None,
            'messages':['Invalid password verification request.']
        }

    # otherwise, now we'll check if the session exists
    else:

        session_info = auth_session_exists(
            {'session_token':payload['session_token'],
             'reqid':payload['reqid'],
             'pii_salt':payload['pii_salt']},
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
                'success':False,
                'user_id':None,
                'messages':['No session token provided.']
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
                        payload['password'][:1024],
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
                    'success':False,
                    'user_id':None,
                    'messages':["Sorry, that user ID and "
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
                        'success':True,
                        'user_id': user_info['user_id'],
                        'messages':["Verification successful."]
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
                        'success':False,
                        'user_id': user_info['user_id'],
                        'messages':["Sorry, that user ID and "
                                    "password combination didn't work."]
                    }


def auth_user_login(payload,
                    override_authdb_path=None,
                    raiseonfail=False):
    '''Logs a user in.

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

    Returns
    -------

    dict
        Returns a dict containing the result of the password verification check.

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_id':None,
                'messages':["Invalid user login request."],
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
        session_info = auth_session_exists(
            {'session_token':'nope',
             'reqid':payload['reqid'],
             'pii_salt':payload['pii_salt']},
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
        auth_session_delete({'session_token':'nope',
                             'reqid':payload['reqid'],
                             'pii_salt':payload['pii_salt']},
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
            'success':False,
            'user_id':None,
            'messages':['No session token provided.']
        }

    # otherwise, now we'll check if the session exists
    else:

        session_info = auth_session_exists(
            {'session_token':payload['session_token'],
             'reqid':payload['reqid'],
             'pii_salt':payload['pii_salt']},
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
                pass_hasher.verify(dummy_password,'nope')
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
                {'session_token':'nope',
                 'reqid':payload['reqid'],
                 'pii_salt':payload['pii_salt']},
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
                'success':False,
                'user_id':None,
                'messages':['No session token provided.']
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
                        payload['password'][:1024],
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
                {'session_token':payload['session_token'],
                 'reqid':payload['reqid'],
                 'pii_salt':payload['pii_salt']},
                raiseonfail=raiseonfail,
                override_authdb_path=override_authdb_path
            )

            if not pass_ok:

                return {
                    'success':False,
                    'user_id':None,
                    'messages':["Sorry, that user ID and "
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
                        'success':True,
                        'user_id': user_info['user_id'],
                        'messages':["Login successful."]
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
                        'success':False,
                        'user_id': user_info['user_id'],
                        'messages':["Sorry, that user ID and "
                                    "password combination didn't work."]
                    }


def auth_user_logout(payload,
                     override_authdb_path=None,
                     raiseonfail=False):
    '''Logs out a user.

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

    Returns
    -------

    dict
        Returns a dict containing the result of the password verification check.

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_id':None,
                'messages':["Invalid user logout request."],
            }

    for key in ('session_token','user_id'):
        if key not in payload:

            LOGGER.error(
                '[%s] Invalid user logout request, missing %s.' %
                (payload['reqid'], key)
            )
            return {
                'success':False,
                'messages':["Invalid user logout request. "
                            "No %s provided." % key],
            }

    # check if the session token exists
    session = auth_session_exists(
        {'session_token':payload['session_token'],
         'reqid':payload['reqid'],
         'pii_salt':payload['pii_salt']},
        override_authdb_path=override_authdb_path,
        raiseonfail=raiseonfail)

    if session['success']:

        # check the user ID
        if payload['user_id'] == session['session_info']['user_id']:

            deleted = auth_session_delete(
                {'session_token':payload['session_token'],
                 'reqid':payload['reqid'],
                 'pii_salt':payload['pii_salt']},
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
                    'success':True,
                    'user_id': session['session_info']['user_id'],
                    'messages':["Logout successful."]
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
                    'success':False,
                    'user_id':payload['user_id'],
                    'messages':["Logout failed. Invalid "
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
                'success':False,
                'user_id':payload['user_id'],
                'messages':["Logout failed. Invalid session_token for user_id."]
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
            'success':False,
            'user_id':payload['user_id'],
            'messages':["Logout failed. Invalid "
                        "session_token for user_id."]
        }
