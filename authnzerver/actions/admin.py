#!/usr/bin/env python
# -*- coding: utf-8 -*-
# actions_admin.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''This contains functions to drive admin related actions (listing users,
editing users, change user roles).

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

import multiprocessing as mp

from sqlalchemy import select, asc

from .. import authdb
from .session import auth_session_exists
from ..permissions import pii_hash, load_permissions_json


##################
## LISTING USERS ##
###################

def list_users(payload,
               raiseonfail=False,
               override_authdb_path=None):
    '''
    This lists users.

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

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_info':None,
                'messages':["Invalid user info request."],
            }

    if 'user_id' not in payload:

        LOGGER.error(
            '[%s] Invalid password change request, missing %s.' %
            (payload['reqid'], 'user_id')
        )

        return {
            'success':False,
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

            s = select([
                users.c.user_id,
                users.c.system_id,
                users.c.full_name,
                users.c.email,
                users.c.is_active,
                users.c.last_login_try,
                users.c.last_login_success,
                users.c.created_on,
                users.c.user_role,
            ]).order_by(
                asc(users.c.user_id)
            ).select_from(users)

        else:

            s = select([
                users.c.user_id,
                users.c.system_id,
                users.c.full_name,
                users.c.email,
                users.c.is_active,
                users.c.last_login_try,
                users.c.last_login_success,
                users.c.created_on,
                users.c.user_role,
            ]).order_by(
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
                "user_id provided: %s. Exception: %s" %
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

    except Exception as e:

        LOGGER.error(
            "[%s] User lookup request failed. "
            "user_id provided: %s. Exception: %s" %
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


###################
## EDITING USERS ##
###################

def edit_user(payload,
              raiseonfail=False,
              override_permissions_json=None,
              override_authdb_path=None):
    '''This edits users.

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

    Returns
    -------

    dict
        The dict returned is of the form::

            {'success': True or False,
             'user_info': dict, with new user info,
             'messages': list of str messages if any}

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_info':None,
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
            "user_id: %s, role: %s, session_token: %s, target_userid: %s. "
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
            'messages':["No update_dict provided."],
        }

    if target_userid in (2,3):

        LOGGER.error(
            "[%s] User edit request failed for "
            "user_id: %s, role: %s, session_token: %s, target_userid: %s. "
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
                        "user_id: %s, role: %s, "
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
                'messages':["user_id or session info not available "
                            "for this user edit attempt."],
            }

        #
        # all update checks, passed, do the update
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
        sel = select([
            users.c.user_id,
            users.c.user_role,
            users.c.full_name,
            users.c.email,
            users.c.is_active
        ]).select_from(users).where(
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
                "session_token: %s, target_userid: %s. Exception: %s" %
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
                'messages':["User update failed."],
            }

    except Exception as e:

        LOGGER.error(
            "[%s] User edit request failed for "
            "user_id: %s, role: %s, "
            "session_token: %s, target_userid: %s. Exception: %s" %
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
            'messages':["User update failed."],
        }


def internal_toggle_user_lock(payload,
                              raiseonfail=False,
                              override_authdb_path=None):
    '''Locks/unlocks user accounts.

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

    Returns
    -------

    dict
        The dict returned is of the form::

            {'success': True or False,
             'user_info': dict, with new user info,
             'messages': list of str messages if any}

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_info':None,
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

        # execute the update
        upd = users.update(
        ).where(
            users.c.user_id == target_userid
        ).values(update_dict)
        result = currproc.authdb_conn.execute(upd)

        # check the update and return new values
        sel = select([
            users.c.user_id,
            users.c.system_id,
            users.c.user_role,
            users.c.full_name,
            users.c.email,
            users.c.is_active
        ]).select_from(users).where(
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
                "Exception was: %s" %
                (payload['reqid'],
                 pii_hash(payload['target_userid'],
                          payload['pii_salt']), e)
            )

            if raiseonfail:
                raise

            return {
                'success':False,
                'user_info':None,
                'messages':["User lock toggle failed."],
            }

    except Exception as e:

        LOGGER.error(
            "[%s] User lock toggle request failed for user_id: %s. "
            "Exception was: %s" %
            (payload['reqid'],
             pii_hash(payload['target_userid'],
                      payload['pii_salt']), e)
        )

        if raiseonfail:
            raise

        return {
            'success':False,
            'user_info':None,
            'messages':["User lock toggle failed."],
        }


def toggle_user_lock(payload,
                     raiseonfail=False,
                     override_authdb_path=None):
    '''Locks/unlocks user accounts.

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

    Returns
    -------

    dict
        The dict returned is of the form::

            {'success': True or False,
             'user_info': dict, with new user info,
             'messages': list of str messages if any}

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_info':None,
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
            'messages':["User lock toggle failed."],
        }
