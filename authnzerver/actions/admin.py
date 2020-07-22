# -*- coding: utf-8 -*-
# admin.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""This contains functions to drive admin related actions (listing users,
editing users, change user roles).
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

from sqlalchemy import select, asc, column

from .. import authdb
from .session import auth_session_exists
from ..permissions import pii_hash, load_permissions_json


######################################################
## user info columns returned by all functions here ##
######################################################

def user_info_columns(table):
    """Returns the column expression for all required info retrieved by
    a user lookup.

    *table* is the users SQLAlchemy table object. Required to preserve type
    information for the columns.

    """

    return [
        table.c.user_id,
        table.c.system_id,
        table.c.full_name,
        table.c.email,
        table.c.email_verified,
        table.c.is_active,
        table.c.last_login_try,
        table.c.last_login_success,
        table.c.failed_login_tries,
        table.c.created_on,
        table.c.last_updated,
        table.c.user_role,
        table.c.extra_info,
        table.c.emailverify_sent_datetime,
        table.c.emailforgotpass_sent_datetime,
        table.c.emailchangepass_sent_datetime
    ]


###################
## LISTING USERS ##
###################

def list_users(payload,
               raiseonfail=False,
               override_authdb_path=None,
               override_permissions_json=None,
               config=None):
    """This lists users.

    FIXME: add permissions checks to this instead of relying on a frontend to
    filter out users who aren't allowed to perform this action.

    Parameters
    ----------

    payload : dict
        This is the input payload dict. Required items:

        - user_id: int or None. If None, all users will be returned

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    override_permissions_json : str or None
        If given as a str, is the alternative path to the permissions JSON
        to use.

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    dict
        The dict returned is of the form::

            {'success': True or False,
             'user_info': list of dicts, one per user,
             'messages': list of str messages if any}

        The dicts per user will contain the following items::

            {'user_id','full_name', 'email',
             'is_active','created_on','user_role',
             'last_login_try','last_login_success'}

    """

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
                'user_info':None,
                'messages':["Invalid user info request."],
            }

    if 'user_id' not in payload:

        LOGGER.error(
            '[%s] Invalid user list request, missing %s.' %
            (payload['reqid'], 'user_id')
        )

        return {
            'success':False,
            'failure_reason':(
                "invalid request: missing 'user_id' in request"
            ),
            'user_info':None,
            'messages':["No user_id provided."],
        }

    user_id = payload['user_id']

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

        users = currproc.authdb_meta.tables['users']

        if user_id is None:

            s = select(user_info_columns(users)).order_by(
                asc(users.c.user_id)
            ).select_from(users)

        else:

            s = select(user_info_columns(users)).order_by(
                asc(users.c.user_id)
            ).select_from(users).where(
                users.c.user_id == user_id
            )

        result = currproc.authdb_conn.execute(s)
        rows = result.fetchall()
        result.close()

        try:

            serialized_result = [dict(x) for x in rows]

            LOGGER.info(
                "[%s] User lookup request succeeded. "
                "user_id provided: %s." %
                (payload['reqid'],
                 pii_hash(payload['user_id'],
                          payload['pii_salt']))
            )
            return {
                'success':True,
                'user_info':serialized_result,
                'messages':["User look up successful."],
            }

        except Exception as e:

            LOGGER.error(
                "[%s] User lookup request failed. "
                "user_id provided: %s. Exception: %r" %
                (payload['reqid'],
                 pii_hash(payload['user_id'],
                          payload['pii_salt']), e)
            )

            if raiseonfail:
                raise

            return {
                'success':False,
                'failure_reason':'target user not found in DB',
                'user_info':None,
                'messages':["User look up failed."],
            }

    except Exception as e:

        LOGGER.error(
            "[%s] User lookup request failed. "
            "user_id provided: %s. Exception: %r" %
            (payload['reqid'],
             pii_hash(payload['user_id'],
                      payload['pii_salt']), e)
        )

        if raiseonfail:
            raise

        return {
            'success':False,
            'user_info':None,
            'messages':["User look up failed."],
        }


def get_user_by_email(payload,
                      raiseonfail=False,
                      override_authdb_path=None,
                      config=None):
    """
    This gets a user's information using their email address.

    FIXME: add permissions checks to this instead of relying on a frontend to
    filter out users who aren't allowed to perform this action.

    Parameters
    ----------

    payload : dict
        This is the input payload dict. Required items:

        - email: str

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    dict
        The dict returned is of the form::

            {'success': True or False,
             'user_info': a user info dict,
             'messages': list of str messages if any}

        The user info dict will contain the following items::

            {'user_id','system_id', 'full_name', 'email',
             'is_active','created_on','user_role',
             'last_login_try','last_login_success'}

    """

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_info':None,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'messages':["Invalid user info request."],
            }

    if 'email' not in payload:

        LOGGER.error(
            '[%s] Invalid user lookup request, missing %s.' %
            (payload['reqid'], 'email')
        )

        return {
            'success':False,
            'user_info':None,
            'failure_reason':"invalid request: missing 'email' in request",
            'messages':["email provided."],
        }

    email = payload['email']

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

        users = currproc.authdb_meta.tables['users']

        s = select(user_info_columns(users)).order_by(
            asc(users.c.user_id)
        ).select_from(users).where(
            users.c.email == email
        )

        result = currproc.authdb_conn.execute(s)
        rows = result.fetchone()
        result.close()

        try:

            serialized_result = dict(rows)

            LOGGER.info(
                "[%s] User lookup request succeeded. "
                "email provided: %s." %
                (payload['reqid'],
                 pii_hash(payload['email'],
                          payload['pii_salt']))
            )
            return {
                'success':True,
                'user_info':serialized_result,
                'messages':["User look up successful."],
            }

        except Exception as e:

            LOGGER.error(
                "[%s] User lookup request failed. "
                "email provided: %s. Exception: %r" %
                (payload['reqid'],
                 pii_hash(payload['email'],
                          payload['pii_salt']), e)
            )

            if raiseonfail:
                raise

            return {
                'success':False,
                'user_info':None,
                'failure_reason':'user email not found in DB',
                'messages':["User look up failed."],
            }

    except Exception as e:

        LOGGER.error(
            "[%s] User lookup request failed. "
            "email provided: %s. Exception: %r" %
            (payload['reqid'],
             pii_hash(payload['email'],
                      payload['pii_salt']), e)
        )

        if raiseonfail:
            raise

        return {
            'success':False,
            'user_info':None,
            'failure_reason':'exception when checking the DB',
            'messages':["User look up failed."],
        }


def lookup_users(payload,
                 raiseonfail=False,
                 override_authdb_path=None,
                 config=None):
    """This looks up users by a given property.

    FIXME: add permissions checks to this instead of relying on a frontend to
    filter out users who aren't allowed to perform this action.

    Valid properties are all the columns in the users table, except for the
    password column.

    Parameters
    ----------

    payload : dict
        This is the input payload dict. Required items:

        - by (str): the property column to use to look up the user by

        - match (object): the required value of the property. Note that in most
          cases, this will be coerced to a string to compare it to the database
          value.

        If by == 'extra_info', then match must be a dict of the form:

            {'extra_info_key': extra_info_value}

        to match one or more keys inside the extra_info JSON column to the
        specified value.

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    dict
        The dict returned is of the form::

            {'success': True or False,
             'user_info': a user info dict,
             'messages': list of str messages if any}

        The user info dict will contain the following items::

            {'user_id','system_id', 'full_name', 'email',
             'is_active','created_on','user_role',
             'last_login_try','last_login_success'}

    """

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_info':None,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'messages':["Invalid user info request."],
            }

    for key in ("by", "match"):
        if key not in payload:
            LOGGER.error(
                '[%s] Invalid user lookup request, missing %s.' %
                (payload['reqid'], key)
            )
            return {
                'success':False,
                'user_info':None,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'messages':["Invalid match condition provided."],
            }

    lookup_by = payload['by']
    lookup_column = column(lookup_by)
    lookup_match = payload['match']

    if ( (isinstance(lookup_match, dict) and lookup_by != "extra_info") or
         (lookup_by == "extra_info" and not isinstance(lookup_match, dict)) ):

        LOGGER.error(
            '[%s] Invalid user lookup request, '
            'extra_info selector must provide a dict.' %
            (payload['reqid'],)
        )

        return {
            'success':False,
            'user_info':None,
            'failure_reason':(
                "invalid request: 'by' is 'extra_info' but "
                "'match' is not a dict or "
                "'match' is a dict and 'by' is not 'extra_info'"
            ),
            'messages':["Invalid match condition provided."],
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

        users = currproc.authdb_meta.tables['users']

        sel = select(user_info_columns(users)).order_by(
            asc(users.c.user_id)
        ).select_from(users)

        if isinstance(lookup_match, dict) and lookup_by == "extra_info":
            for key, val in lookup_match.items():
                # FIXME: check if this is required in Postgres
                # FIXME: this appears to be required in SQLite
                if 'sqlite:///' in currproc.auth_db_path:
                    sel = sel.where(
                        users.c.extra_info[key].as_string() == str(val)
                    )
                else:
                    sel = sel.where(
                        users.c.extra_info[key] == val
                    )

        else:
            sel = sel.where(
                lookup_column == lookup_match
            )

        result = currproc.authdb_conn.execute(sel)
        rows = result.fetchall()
        result.close()

        try:

            serialized_result = [dict(x) for x in rows]

            LOGGER.info(
                "[%s] User lookup request succeeded." %
                payload['reqid']
            )
            return {
                'success':True,
                'user_info':serialized_result,
                'messages':["User look up successful."],
            }

        except Exception as e:

            LOGGER.error(
                "[%s] User lookup request failed because of %s." %
                (payload['reqid'], str(e))
            )

            if raiseonfail:
                raise

            return {
                'success':False,
                'user_info':None,
                'failure_reason':'user not found in DB',
                'messages':["User look up failed."],
            }

    except Exception as e:

        LOGGER.error(
            "[%s] User lookup request failed because of %s." %
            (payload['reqid'], str(e))
        )

        if raiseonfail:
            raise

        return {
            'success':False,
            'user_info':None,
            'failure_reason':'exception in DB access',
            'messages':["User look up failed."],
        }


###################
## EDITING USERS ##
###################

def edit_user(payload,
              raiseonfail=False,
              override_permissions_json=None,
              override_authdb_path=None,
              config=None):
    """This edits users.

    FIXME: add permissions checks to this instead of relying on a frontend to
    filter out users who aren't allowed to perform this action.

    Parameters
    ----------

    payload : dict
        This is the input payload dict. Required items:

        - user_id: int, user ID of an admin user or == target_userid
        - user_role: str, == 'superuser' or == target_userid user_role
        - session_token: str, session token of admin or target_userid token
        - target_userid: int, the user to edit
        - update_dict: dict, the update dict

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

        Only these items can be edited::

            {'full_name', 'email',     <- by user and superuser
             'is_active','user_role', 'email_verified'}  <- by superuser only

        User IDs 2 and 3 are reserved for the system-wide anonymous and locked
        users respectively, and can't be edited.

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    override_permissions_json : str or None
        If given as a str, is the alternative path to the permissions JSON to
        load and use for this request. Normally, the path to the permissions
        JSON has already been specified as a process-local variable by the main
        authnzerver start up routines. If you want to use some other permissions
        model JSON (e.g. for testing), provide that here.

        Note that we load the permissions JSON from disk every time we need to
        take a decision. This might be a bit slower, but allows for much faster
        policy changes by just changing the permissions JSON file and not having
        to restart the authnzerver.

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    dict
        The dict returned is of the form::

            {'success': True or False,
             'user_info': dict, with new user info,
             'messages': list of str messages if any}

    """

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_info':None,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'messages':["Invalid user edit request."],
            }

    for key in ('user_id',
                'user_role',
                'session_token',
                'target_userid',
                'update_dict'):

        if key not in payload:

            LOGGER.error(
                '[%s] Invalid user edit request, missing %s.' %
                (payload['reqid'], key)
            )
            return {
                'success':False,
                'user_info':None,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'messages':["No %s provided." % key],
            }

    user_id = payload['user_id']
    user_role = payload['user_role']
    session_token = payload['session_token']
    target_userid = payload['target_userid']
    update_dict = payload['update_dict']

    if not isinstance(update_dict, dict):

        LOGGER.error(
            "[%s] User edit request failed for "
            "user_id: %s, role: '%s', session_token: %s, target_userid: %s. "
            "An update dict was not provided." %
            (payload['reqid'],
             pii_hash(payload['user_id'],
                      payload['pii_salt']),
             payload['user_role'],
             pii_hash(payload['session_token'],
                      payload['pii_salt']),
             pii_hash(payload['target_userid'],
                      payload['pii_salt']))
        )

        return {
            'success':False,
            'user_info':None,
            'failure_reason':'invalid request: no update dict was provided',
            'messages':["No update_dict provided."],
        }

    if target_userid in (2,3):

        LOGGER.error(
            "[%s] User edit request failed for "
            "user_id: %s, role: '%s', session_token: %s, target_userid: %s. "
            "Editing systemwide anonymous or locked accounts is not allowed." %
            (payload['reqid'],
             pii_hash(payload['user_id'],
                      payload['pii_salt']),
             payload['user_role'],
             pii_hash(payload['session_token'],
                      payload['pii_salt']),
             pii_hash(payload['target_userid'],
                      payload['pii_salt']))
        )
        return {
            'success':False,
            'user_info':None,
            'failure_reason':(
                "invalid request: can't edit anonymous/locked users"
            ),
            'messages':["Editing anonymous/locked user accounts not allowed."],
        }

    try:

        # this checks if the database connection is live
        currproc = mp.current_process()
        engine = getattr(currproc, 'authdb_engine', None)

        if override_authdb_path:
            currproc.auth_db_path = override_authdb_path

        # override permissions JSON if necessary
        if override_permissions_json:
            currproc.permissions_json = override_permissions_json

        if not engine:
            (currproc.authdb_engine,
             currproc.authdb_conn,
             currproc.authdb_meta) = (
                authdb.get_auth_db(
                    currproc.auth_db_path,
                    echo=raiseonfail
                )
            )

        # the case where the user updates their own info
        if target_userid == user_id and user_role in ('authenticated','staff'):

            # check if the user_id == target_userid
            # if so, check if session_token is valid and belongs to user_id
            session_info = auth_session_exists(
                {'session_token':session_token,
                 'pii_salt':payload['pii_salt'],
                 'reqid':payload['reqid']},
                raiseonfail=raiseonfail,
                override_authdb_path=override_authdb_path
            )

            # check if the session info user_id matches the provided user_id and
            # role
            if (session_info and
                session_info['success'] and
                session_info['session_info']['is_active'] is True and
                session_info['session_info']['user_id'] == user_id and
                session_info['session_info']['user_role'] == user_role):

                editeable_elements = {'full_name','email'}
                update_check = set(update_dict.keys()) - editeable_elements

                # check if the update keys are valid
                if len(update_check) > 0:

                    LOGGER.error(
                        "[%s] User edit request failed for "
                        "user_id: %s, role: '%s', "
                        "session_token: %s, target_userid: %s. "
                        "User updating their own info can only"
                        "do so for full_name, email." %
                        (payload['reqid'],
                         pii_hash(payload['user_id'],
                                  payload['pii_salt']),
                         payload['user_role'],
                         pii_hash(payload['session_token'],
                                  payload['pii_salt']),
                         pii_hash(payload['target_userid'],
                                  payload['pii_salt']))
                    )

                    return {
                        'success':False,
                        'user_info':None,
                        'failure_reason':(
                            "role '%s' can't edit anything other "
                            "than 'full_name', 'email'" % payload['user_role']
                        ),
                        'messages':["extra elements in "
                                    "update_dict not allowed"],
                    }

            else:

                LOGGER.error(
                    "[%s] User edit request failed for "
                    "user_id: %s, role: %s, "
                    "session_token: %s, target_userid: %s. "
                    "Valid session not found for the originating user_id." %
                    (payload['reqid'],
                     pii_hash(payload['user_id'],
                              payload['pii_salt']),
                     payload['user_role'],
                     pii_hash(payload['session_token'],
                              payload['pii_salt']),
                     pii_hash(payload['target_userid'],
                              payload['pii_salt']))
                )
                return {
                    'success':False,
                    'failure_reason':(
                        "no valid session found for originating user_id"
                    ),
                    'user_info':None,
                    'messages':["User session info not available "
                                "for this user edit attempt."],
                }

        # the case where the superuser updates a user's info (or their own info)
        elif user_role == 'superuser':

            # check if the user_id == target_userid
            # if so, check if session_token is valid and belongs to user_id
            session_info = auth_session_exists(
                {'session_token':session_token,
                 'pii_salt':payload['pii_salt'],
                 'reqid':payload['reqid']},
                raiseonfail=raiseonfail,
                override_authdb_path=override_authdb_path
            )

            # check if the session info user_id matches the provided user_id and
            # role
            if (session_info and
                session_info['success'] and
                session_info['session_info']['is_active'] is True and
                session_info['session_info']['user_id'] == user_id and
                session_info['session_info']['user_role'] == user_role):

                editeable_elements = {'full_name','email',
                                      'is_active','user_role',
                                      'email_verified'}
                update_check = set(update_dict.keys()) - editeable_elements

                # check if the update keys are valid
                if len(update_check) > 0:

                    LOGGER.error(
                        "[%s] User edit request failed for "
                        "user_id: %s, role: %s, "
                        "session_token: %s, target_userid: %s. "
                        "Extra non-editable elements found in update_dict." %
                        (payload['reqid'],
                         pii_hash(payload['user_id'],
                                  payload['pii_salt']),
                         payload['user_role'],
                         pii_hash(payload['session_token'],
                                  payload['pii_salt']),
                         pii_hash(payload['target_userid'],
                                  payload['pii_salt']))
                    )

                    return {
                        'success':False,
                        'user_info':None,
                        'failure_reason':(
                            "role: '%s' is not allowed to edit items: '%s'" %
                            (payload['user_role'], list(update_dict.keys()))
                        ),
                        'messages':["extra elements in "
                                    "update_dict not allowed"],
                    }

                # check if the roles provided are valid
                permissions_model = load_permissions_json(
                    currproc.permission_json
                )

                if ('user_role' in update_dict and
                    (update_dict['user_role'] not in
                     permissions_model['roles'])):

                    LOGGER.error(
                        "[%s] User edit request failed for "
                        "user_id: %s, role: %s, "
                        "session_token: %s, target_userid: %s. "
                        "Invalid role change in update_dict "
                        "to an non-existent role." %
                        (payload['reqid'],
                         pii_hash(payload['user_id'],
                                  payload['pii_salt']),
                         payload['user_role'],
                         pii_hash(payload['session_token'],
                                  payload['pii_salt']),
                         pii_hash(payload['target_userid'],
                                  payload['pii_salt']))
                    )

                    return {
                        'success':False,
                        'user_info':None,
                        'failure_reason':(
                            "role change requested is not valid"
                        ),
                        'messages':["unknown role change "
                                    "request in update_dict"],
                    }

            else:

                LOGGER.error(
                    "[%s] User edit request failed for "
                    "user_id: %s, role: %s, "
                    "session_token: %s, target_userid: %s. "
                    "Session token provided is invalid "
                    "for a superuser account." %
                    (payload['reqid'],
                     pii_hash(payload['user_id'],
                              payload['pii_salt']),
                     payload['user_role'],
                     pii_hash(payload['session_token'],
                              payload['pii_salt']),
                     pii_hash(payload['target_userid'],
                              payload['pii_salt']))
                )
                return {
                    'success':False,
                    'user_info':None,
                    'failure_reason':(
                        "invalid session for edit attempt"
                    ),
                    'messages':["Superuser session info not available "
                                "for this user edit attempt."],
                }

        # any other case is a failure
        else:

            LOGGER.error(
                "[%s] User edit request failed for "
                "user_id: %s, role: %s, "
                "session_token: %s, target_userid: %s. "
                "Session token provided is invalid." %
                (payload['reqid'],
                 pii_hash(payload['user_id'],
                          payload['pii_salt']),
                 payload['user_role'],
                 pii_hash(payload['session_token'],
                          payload['pii_salt']),
                 pii_hash(payload['target_userid'],
                          payload['pii_salt']))
            )

            return {
                'success':False,
                'user_info':None,
                'failure_reason':(
                    "invalid session for edit attempt"
                ),
                'messages':["user_id or session info not available "
                            "for this user edit attempt."],
            }

        #
        # all update checks passed, do the update
        #

        users = currproc.authdb_meta.tables['users']

        # execute the update
        # NOTE: here, we don't filter on is_active to allow unlocking of users
        upd = users.update(
        ).where(
            users.c.user_id == target_userid
        ).values(update_dict)
        result = currproc.authdb_conn.execute(upd)

        # check the update and return new values
        sel = select(user_info_columns(users)).select_from(users).where(
            users.c.user_id == target_userid
        )
        result = currproc.authdb_conn.execute(sel)
        rows = result.fetchone()
        result.close()

        try:

            serialized_result = dict(rows)

            LOGGER.info(
                "[%s] User edit request succeeded for "
                "user_id: %s, role: %s, "
                "session_token: %s, target_userid: %s." %
                (payload['reqid'],
                 pii_hash(payload['user_id'],
                          payload['pii_salt']),
                 payload['user_role'],
                 pii_hash(payload['session_token'],
                          payload['pii_salt']),
                 pii_hash(payload['target_userid'],
                          payload['pii_salt']))
            )

            return {
                'success':True,
                'user_info':serialized_result,
                'messages':["User update successful."],
            }

        except Exception as e:

            LOGGER.error(
                "[%s] User edit request failed for "
                "user_id: %s, role: %s, "
                "session_token: %s, target_userid: %s. Exception: %r" %
                (payload['reqid'],
                 pii_hash(payload['user_id'],
                          payload['pii_salt']),
                 payload['user_role'],
                 pii_hash(payload['session_token'],
                          payload['pii_salt']),
                 pii_hash(payload['target_userid'],
                          payload['pii_salt']), e)
            )

            if raiseonfail:
                raise

            return {
                'success':False,
                'user_info':None,
                'failure_reason':(
                    "exception when trying to update user"
                ),
                'messages':["User update failed."],
            }

    except Exception as e:

        LOGGER.error(
            "[%s] User edit request failed for "
            "user_id: %s, role: %s, "
            "session_token: %s, target_userid: %s. Exception: %r" %
            (payload['reqid'],
             pii_hash(payload['user_id'],
                      payload['pii_salt']),
             payload['user_role'],
             pii_hash(payload['session_token'],
                      payload['pii_salt']),
             pii_hash(payload['target_userid'],
                      payload['pii_salt']), e)
        )

        if raiseonfail:
            raise

        return {
            'success':False,
            'user_info':None,
            'failure_reason':(
                "exception when trying to update user"
            ),
            'messages':["User update failed."],
        }


def internal_edit_user(
        payload,
        raiseonfail=False,
        override_authdb_path=None,
        config=None
):
    """Handles editing users. Meant for use internally in a frontend server.

    Parameters
    ----------

    payload : dict
        The input payload dict. Required items:

        - target_userid: int, the user to edit
        - update_dict: dict, the changes to make, with each key being a column
          value to change in the *users* table.

        *update_dict* cannot contain the following fields: user_id, system_id,
        password, emailverify_sent_datetime, emailforgotpass_sent_datetime,
        emailchangepass_sent_datetime, last_login_success, last_login_try,
        failed_login_tries, created_on, and last_updated. These are tracked in
        other action functions and should not be changed directly.

        If *update_dict* contains the *extra_info* field, this JSON field in the
        database will be updated with the info in *extra_info*. To delete an
        item from *extra_info*, pass in the special value of "__delete__" in
        *extra_info* for that item.

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
        Returns a dict containing the new user information.

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
                'messages':["Invalid edit-user request."],
            }

    for key in ('target_userid', 'update_dict'):

        if key not in payload:

            LOGGER.error(
                '[%s] Invalid session edit-user request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success':False,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'session_info':None,
                'messages':["Invalid edit-user request: "
                            "missing or invalid parameters."],
            }

    target_userid = payload['target_userid']
    update_dict = payload['update_dict']
    if update_dict is None or len(update_dict) == 0:
        return {
            'success':False,
            'failure_reason':(
                "invalid request: missing 'update_dict' in request"
            ),
            'session_info':None,
            'messages':["Invalid user-edit request: "
                        "missing or invalid parameters."],
        }

    update_dict_keys = set(update_dict.keys())
    disallowed_keys = {
        'user_id', 'system_id', 'password', 'emailverify_sent_datetime',
        'emailforgotpass_sent_datetime', 'emailchangepass_sent_datetime',
        'last_login_success', 'last_login_try',
        'failed_login_tries', 'created_on', 'last_updated'
    }
    leftover_keys = update_dict_keys.intersection(disallowed_keys)

    if len(leftover_keys) > 0:
        LOGGER.error(
            '[%s] Invalid edit-user request, '
            'found disallowed update keys in update_dict: %s.' %
            (payload['reqid'], leftover_keys)
        )
        return {
            'success':False,
            'failure_reason':(
                "invalid request: disallowed keys in update_dict: %s" %
                leftover_keys
            ),
            'session_info':None,
            'messages':["Invalid edit-user request: "
                        "invalid update parameters."],
        }

    #
    # now, try to update
    #
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

        users = currproc.authdb_meta.tables['users']

        sel = select([
            users.c.user_id,
            users.c.extra_info
        ]).select_from(users).where(
            users.c.user_id == target_userid
        )
        result = currproc.authdb_conn.execute(sel)
        userid_and_extrainfo = result.first()

        if not userid_and_extrainfo or len(userid_and_extrainfo) == 0:
            return {
                'success':False,
                "failure_reason":"no such user",
                'user_info':None,
                'messages':["User info update failed."],
            }

        if ('extra_info' in update_dict and
            update_dict['extra_info'] is not None):

            user_extra_info = userid_and_extrainfo[-1]
            if not user_extra_info:
                user_extra_info = {}

            for key, val in update_dict['extra_info'].items():
                if val == "__delete__" and key in user_extra_info:
                    del user_extra_info[key]
                else:
                    user_extra_info[key] = val

        else:
            user_extra_info = userid_and_extrainfo[-1]

        # do the update

        # replace the extra_info key in the update_dict since we update that
        # separately
        update_dict['extra_info'] = user_extra_info

        upd = users.update().where(
            users.c.user_id == target_userid,
        ).values(update_dict)
        currproc.authdb_conn.execute(upd)

        s = select(user_info_columns(users)).select_from(users).where(
            users.c.user_id == target_userid
        )

        result = currproc.authdb_conn.execute(s)
        row = result.first()

        try:

            serialized_result = dict(row)
            LOGGER.info(
                "[%s] User info updated for "
                "user_id: %s." %
                (payload['reqid'],
                 pii_hash(serialized_result['user_id'],
                          payload['pii_salt']))
            )

            return {
                'success':True,
                'user_info':serialized_result,
                'messages':["User-info update successful."],
            }

        except Exception as e:

            LOGGER.error(
                "[%s] User info update failed for session token: %s. "
                "Exception was: %r." %
                (payload['reqid'],
                 pii_hash(payload['target_userid'],
                          payload['pii_salt']),
                 e)
            )

            return {
                'success':False,
                'failure_reason':(
                    "user requested for update doesn't exist"
                ),
                'user_info':None,
                'messages':["User info update failed."],
            }

    except Exception as e:

        LOGGER.error(
            "[%s] User info update failed for user_id: %s. "
            "Exception was: %r." %
            (payload['reqid'],
             pii_hash(payload['target_userid'],
                      payload['pii_salt']),
             e)
        )

        return {
            'success':False,
            'failure_reason':(
                "DB error when updating user info"
            ),
            'session_info':None,
            'messages':["User info update failed."],
        }


def internal_toggle_user_lock(payload,
                              raiseonfail=False,
                              override_authdb_path=None,
                              config=None):
    """Locks/unlocks user accounts.

    This version of the function should only be run internally (i.e. not called
    by a client). The use-case is automatically locking user accounts if there
    are too many incorrect password attempts. The lock can be permanent or
    temporary.

    Parameters
    ----------

    payload : dict
        This is the input payload dict. Required items:

        - target_userid: int, the user to lock/unlock
        - action: str {'unlock','lock'}

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    dict
        The dict returned is of the form::

            {'success': True or False,
             'user_info': dict, with new user info,
             'messages': list of str messages if any}

    """

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_info':None,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'messages':["Invalid user lock toggle request."],
            }

    from .session import auth_delete_sessions_userid

    for key in ('target_userid',
                'action'):

        if key not in payload:
            LOGGER.error(
                '[%s] Invalid user lock toggle request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success':False,
                'user_info':None,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'messages':["No %s provided for toggle_user_lock" % key],
            }

    target_userid = payload['target_userid']
    action = payload['action']

    if action not in ('unlock','lock'):

        LOGGER.error(
            "[%s] Invalid user lock toggle request for user_id: %s. "
            "Unknown action requested: %s" %
            (payload['reqid'],
             pii_hash(payload['target_userid'],
                      payload['pii_salt']),
             action)
        )

        return {
            'success':False,
            'user_info':None,
            'failure_reason':(
                "action must be either 'lock' or 'unlock'"
            ),
            'messages':["Unknown action requested for toggle_user_lock."],
        }

    if target_userid in (2,3):

        LOGGER.error(
            "[%s] Invalid user lock toggle request for user_id: %s. "
            "Systemwide anonymous/locked users cannot be edited." %
            (payload['reqid'],
             pii_hash(payload['target_userid'],
                      payload['pii_salt']))
        )

        return {
            'success':False,
            'user_info':None,
            'failure_reason':(
                "can't edit anonymous/locked users"
            ),
            'messages':["Editing anonymous/locked user accounts not allowed."],
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

        #
        # all update checks, passed, do the update
        #

        users = currproc.authdb_meta.tables['users']

        if payload['action'] == 'lock':
            update_dict = {'is_active': False,
                           'user_role': 'locked'}
        elif payload['action'] == 'unlock':
            update_dict = {'is_active': True,
                           'user_role': 'authenticated'}
        else:
            LOGGER.error(
                "[%s] Invalid user lock toggle request for user_id: %s. "
                "Invalid toggle action requested: '%s'." %
                (payload['reqid'],
                 payload['action'],
                 pii_hash(payload['target_userid'],
                          payload['pii_salt']))
            )

            return {
                'success':False,
                'user_info':None,
                'failure_reason':(
                    "invalid lock toggle requested"
                ),
                'messages':[
                    "Invalid lock toggle action requested."],
            }

        # execute the update
        upd = users.update(
        ).where(
            users.c.user_id == target_userid
        ).values(update_dict)
        result = currproc.authdb_conn.execute(upd)

        # check the update and return new values
        sel = select(user_info_columns(users)).select_from(users).where(
            users.c.user_id == target_userid
        )
        result = currproc.authdb_conn.execute(sel)
        rows = result.fetchone()
        result.close()

        # delete all the sessions belonging to this user if the action to
        # perform is 'lock'
        if payload['action'] == 'lock':

            auth_delete_sessions_userid(
                {'user_id':target_userid,
                 'session_token':None,
                 'keep_current_session':False,
                 'pii_salt':payload['pii_salt'],
                 'reqid':payload['reqid']},
                raiseonfail=raiseonfail,
                override_authdb_path=override_authdb_path
            )

        try:

            serialized_result = dict(rows)

            LOGGER.info(
                "[%s] User lock toggle request succeeded for user_id: %s. " %
                (payload['reqid'],
                 pii_hash(payload['target_userid'],
                          payload['pii_salt']))
            )

            return {
                'success':True,
                'user_info':serialized_result,
                'messages':["User lock toggle successful."],
            }

        except Exception as e:

            LOGGER.error(
                "[%s] User lock toggle request failed for user_id: %s. "
                "Exception was: %r" %
                (payload['reqid'],
                 pii_hash(payload['target_userid'],
                          payload['pii_salt']), e)
            )

            if raiseonfail:
                raise

            return {
                'success':False,
                'user_info':None,
                'failure_reason':(
                    "exception encountered when trying lock toggle action"
                ),
                'messages':["User lock toggle failed."],
            }

    except Exception as e:

        LOGGER.error(
            "[%s] User lock toggle request failed for user_id: %s. "
            "Exception was: %r" %
            (payload['reqid'],
             pii_hash(payload['target_userid'],
                      payload['pii_salt']), e)
        )

        if raiseonfail:
            raise

        return {
            'success':False,
            'user_info':None,
            'failure_reason':(
                "exception encountered when trying lock toggle action"
            ),
            'messages':["User lock toggle failed."],
        }


def toggle_user_lock(payload,
                     raiseonfail=False,
                     override_authdb_path=None,
                     config=None):
    """Locks/unlocks user accounts.

    Can only be run by superusers and is suitable for use when called from a
    frontend.

    Parameters
    ----------

    payload : dict
        This is the input payload dict. Required items:

        - user_id: int, user ID of a superuser
        - user_role: str, == 'superuser'
        - session_token: str, session token of superuser
        - target_userid: int, the user to lock/unlock
        - action: str {'unlock','lock'}

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    dict
        The dict returned is of the form::

            {'success': True or False,
             'user_info': dict, with new user info,
             'messages': list of str messages if any}

    """

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_info':None,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'messages':["Invalid user lock toggle request."],
            }

    for key in ('user_id',
                'user_role',
                'session_token',
                'target_userid',
                'action'):

        if key not in payload:
            LOGGER.error(
                '[%s] Invalid user lock toggle request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success':False,
                'user_info':None,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'messages':["No %s provided for toggle_user_lock" % key],
            }

    user_id = payload['user_id']
    user_role = payload['user_role']
    session_token = payload['session_token']
    target_userid = payload['target_userid']
    action = payload['action']

    # only superusers can toggle locks
    if user_role != 'superuser':

        LOGGER.error(
            "[%s] Invalid user lock toggle request "
            "by user_id: %s with role: %s, "
            "session_token: %s, target user_id: %s "
            "User does not have a superuser role." %
            (payload['reqid'],
             pii_hash(payload['user_id'],
                      payload['pii_salt']),
             pii_hash(payload['user_role'],
                      payload['pii_salt']),
             pii_hash(payload['session_token'],
                      payload['pii_salt']),
             pii_hash(payload['target_userid'],
                      payload['pii_salt']))
        )

        return {
            'success':False,
            'user_info':None,
            'failure_reason':(
                "user role is not 'superuser', required to toggle locks"
            ),
            'messages':["You don't have lock/unlock privileges."],
        }

    # don't lock the calling user out
    if target_userid == user_id:

        LOGGER.error(
            "[%s] Invalid user lock toggle request "
            "by user_id: %s with role: %s, "
            "session_token: %s, target user_id: %s "
            "User attempted to toggle lock on their own account." %
            (payload['reqid'],
             pii_hash(payload['user_id'],
                      payload['pii_salt']),
             pii_hash(payload['user_role'],
                      payload['pii_salt']),
             pii_hash(payload['session_token'],
                      payload['pii_salt']),
             pii_hash(payload['target_userid'],
                      payload['pii_salt']))
        )

        return {
            'success':False,
            'user_info':None,
            'failure_reason':(
                "can't toggle a lock state on self"
            ),
            'messages':["You can't lock/unlock your own user account."],
        }

    # unknown action attempted
    if action not in ('unlock','lock'):

        LOGGER.error(
            "[%s] Invalid user lock toggle request "
            "by user_id: %s with role: %s, "
            "session_token: %s, target user_id: %s "
            "Unknown action requested: %s" %
            (payload['reqid'],
             pii_hash(payload['user_id'],
                      payload['pii_salt']),
             pii_hash(payload['user_role'],
                      payload['pii_salt']),
             pii_hash(payload['session_token'],
                      payload['pii_salt']),
             pii_hash(payload['target_userid'],
                      payload['pii_salt']), action)
        )

        return {
            'success':False,
            'user_info':None,
            'failure_reason':(
                "action must be one of 'lock', 'unlock'"
            ),
            'messages':["Unknown action requested for toggle_user_lock."],
        }

    # attempt to edit systemwide accounts
    if target_userid in (2,3):

        LOGGER.error(
            "[%s] Invalid user lock toggle request "
            "by user_id: %s with role: %s, "
            "session_token: %s, target user_id: %s "
            "Systemwide anonymous/locked accounts can't be edited." %
            (payload['reqid'],
             pii_hash(payload['user_id'],
                      payload['pii_salt']),
             pii_hash(payload['user_role'],
                      payload['pii_salt']),
             pii_hash(payload['session_token'],
                      payload['pii_salt']),
             pii_hash(payload['target_userid'],
                      payload['pii_salt']))
        )

        return {
            'success':False,
            'user_info':None,
            'failure_reason':(
                "can't toggle lock state for system anonymous/locked accounts"
            ),
            'messages':["Editing anonymous/locked user accounts not allowed."],
        }

    #
    # finally, process the attempt
    #

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

        # check if session_token is valid and belongs to user_id
        session_info = auth_session_exists(
            {'session_token':session_token,
             'pii_salt':payload['pii_salt'],
             'reqid':payload['reqid']},
            raiseonfail=raiseonfail,
            override_authdb_path=override_authdb_path
        )

        # check if the session info user_id matches the provided user_id and
        # role
        if not (session_info and
                session_info['success'] and
                session_info['session_info']['is_active'] is True and
                session_info['session_info']['user_id'] == user_id and
                session_info['session_info']['user_role'] == user_role):

            LOGGER.error(
                "[%s] Invalid user lock toggle request "
                "by user_id: %s with role: %s, "
                "session_token: %s, target user_id: %s "
                "Session token does not match the expected user ID or role." %
                (payload['reqid'],
                 pii_hash(payload['user_id'],
                          payload['pii_salt']),
                 pii_hash(payload['user_role'],
                          payload['pii_salt']),
                 pii_hash(payload['session_token'],
                          payload['pii_salt']),
                 pii_hash(payload['target_userid'],
                          payload['pii_salt']))
            )

            return {
                'success':False,
                'user_info':None,
                'failure_reason':(
                    "invalid session for user attempting lock toggle"
                ),
                'messages':["Superuser session info not available "
                            "for this user edit attempt."],
            }

        #
        # all update checks passed, do the update
        #
        res = internal_toggle_user_lock(
            payload,
            raiseonfail=raiseonfail,
            override_authdb_path=override_authdb_path
        )
        return res

    except Exception as e:

        LOGGER.error(
            "[%s] Invalid user lock toggle request "
            "by user_id: %s with role: %s, "
            "session_token: %s, target user_id: %s "
            "Exception was: %r." %
            (payload['reqid'],
             pii_hash(payload['user_id'],
                      payload['pii_salt']),
             pii_hash(payload['user_role'],
                      payload['pii_salt']),
             pii_hash(payload['session_token'],
                      payload['pii_salt']),
             pii_hash(payload['target_userid'],
                      payload['pii_salt']), e)
        )

        if raiseonfail:
            raise

        return {
            'success':False,
            'user_info':None,
            'failure_reason':(
                "exception when trying to toggle lock state"
            ),
            'messages':["User lock toggle failed."],
        }
