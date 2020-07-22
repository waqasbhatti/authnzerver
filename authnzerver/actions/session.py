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

from .. import authdb
from ..permissions import pii_hash


################################
## SESSION HANDLING FUNCTIONS ##
################################

def auth_session_new(payload,
                     override_authdb_path=None,
                     raiseonfail=False,
                     config=None):
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

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

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
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'session_token':None,
                'expires':None,
                'messages':["Invalid session initiation request."],
            }

    # fail immediately if the required payload keys are not present
    for key in ('ip_address',
                'user_agent',
                'user_id',
                'expires',
                'extra_info_json'):

        if key not in payload:

            LOGGER.error(
                '[%s] Invalid session initiation request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success':False,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
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
            'failure_reason':(
                "DB error when making new session"
            ),
            'success':False,
            'session_token':None,
            'expires':None,
            'messages':["Could not create a new session."],
        }


def internal_edit_session(
        payload,
        raiseonfail=False,
        override_authdb_path=None,
        config=None
):
    """Handles editing the *extra_info_json* field for an existing user session.

    Meant for use internally in a frontend server.

    Parameters
    ----------

    payload : dict
        The input payload dict. Required items:

        - target_session_token: int, the session to edit
        - update_dict: dict, the changes to make to the *extra_info_json* column
          of the sessions table for the target session token.

        The *extra_info_json* field in the database will be updated with the
        info in *update_dict*. To delete an item from *extra_info_json*, pass in
        the special value of "__delete__" in *update_dict* for that item.

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

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    dict
        Returns a dict containing the new session information.

    """

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'success':False,
                'session_token':None,
                'expires':None,
                'messages':["Invalid session edit request."],
            }

    for key in ('target_session_token', 'update_dict'):

        if key not in payload:

            LOGGER.error(
                '[%s] Invalid session edit request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success':False,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'session_info':None,
                'messages':["Invalid session edit request: "
                            "missing or invalid parameters."],
            }

    target_session_token = payload['target_session_token']
    update_dict = payload['update_dict']
    if update_dict is None or len(update_dict) == 0:
        return {
            'success':False,
            'failure_reason':(
                "invalid request: missing 'update_dict' in request"
            ),
            'session_info':None,
            'messages':["Invalid session edit request: "
                        "missing or invalid parameters."],
        }

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

        sel = select([
            sessions.c.session_token,
            sessions.c.extra_info_json
        ]).select_from(sessions).where(
            sessions.c.session_token == target_session_token
        ).where(
            sessions.c.expires > datetime.utcnow()
        )
        result = currproc.authdb_conn.execute(sel)
        sessiontoken_extrainfo = result.first()

        if not sessiontoken_extrainfo or len(sessiontoken_extrainfo) == 0:
            return {
                'success':False,
                "failure_reason":"no such session",
                'session_info':None,
                'messages':["Session extra_info update failed."],
            }

        #
        # update the extra_info_json dict
        #
        session_extra_info = sessiontoken_extrainfo[-1]
        if not session_extra_info:
            session_extra_info = {}

        for key, val in update_dict.items():
            if val == "__delete__" and key in session_extra_info:
                del session_extra_info[key]
            else:
                session_extra_info[key] = val

        # write it back to the session column
        # get back the new version
        upd = sessions.update().where(
            sessions.c.session_token == target_session_token
        ).values({"extra_info_json":session_extra_info})
        currproc.authdb_conn.execute(upd)

        s = select([
            sessions.c.user_id,
            sessions.c.session_token,
            sessions.c.ip_address,
            sessions.c.user_agent,
            sessions.c.created,
            sessions.c.expires,
            sessions.c.extra_info_json
        ]).select_from(sessions).where(
            (sessions.c.session_token == target_session_token) &
            (sessions.c.expires > datetime.utcnow())
        )
        result = currproc.authdb_conn.execute(s)
        row = result.first()

        try:

            serialized_result = dict(row)
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
                'failure_reason':(
                    "session requested for update doesn't exist or expired"
                ),
                'session_info':None,
                'messages':["Session extra_info update failed."],
            }

    except Exception as e:

        LOGGER.error(
            "[%s] Session edit failed for user_id: %s. "
            "Exception was: %r." %
            (payload['reqid'],
             pii_hash(payload['target_userid'],
                      payload['pii_salt']),
             e)
        )

        return {
            'success':False,
            'failure_reason':(
                "DB error when updating session info"
            ),
            'session_info':None,
            'messages':["Session info update failed."],
        }


def auth_session_exists(
        payload,
        override_authdb_path=None,
        raiseonfail=False,
        config=None
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

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

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
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
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
            'failure_reason':(
                "invalid request: missing 'session_token' in request"
            ),
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
            users.c.extra_info,
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
                'failure_reason':(
                    "session does not exist or expired"
                ),
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
            'failure_reason':(
                "DB error when retrieving session info"
            ),
            'session_info':None,
            'messages':["Session look up failed."],
        }


def auth_session_delete(
        payload,
        override_authdb_path=None,
        raiseonfail=False,
        config=None
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

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

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
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'messages':["Invalid session delete request."],
            }

    if 'session_token' not in payload:

        LOGGER.error(
            '[%s] Invalid session delete request, missing session_token.' %
            payload['reqid']
        )

        return {
            'success':False,
            'failure_reason':(
                "invalid request: missing 'session_token' in request"
            ),
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
            'failure_reason':(
                "DB error when deleting session"
            ),
            'messages':["Session could not be deleted."],
        }


def auth_delete_sessions_userid(
        payload,
        override_authdb_path=None,
        raiseonfail=False,
        config=None,
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

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

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
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
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
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
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
            'failure_reason':(
                "DB error when updating session info"
            ),
            'messages':["Sessions could not be deleted."],
        }


def auth_kill_old_sessions(
        session_expiry_days=7,
        override_authdb_path=None,
        raiseonfail=False,
        config=None,
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

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

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
            'failure_reason':(
                "no sessions found to delete"
            ),
            'messages':['No sessions older than %sZ found to delete' %
                        earliest_date.isoformat()]
        }
