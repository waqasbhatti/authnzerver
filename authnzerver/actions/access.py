#!/usr/bin/env python
# -*- coding: utf-8 -*-
# access.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''This contains functions to apply access control.

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

from sqlalchemy import select

from .. import permissions
from .. import authdb


################
## FUNCTIONS  ##
################

def check_user_access(payload,
                      raiseonfail=False,
                      override_permissions_json=None,
                      override_authdb_path=None):
    '''Checks for user access to a specified item based on a permissions policy.

    Parameters
    ----------

    payload : dict
        This is the input payload dict. Required items:

        - user_id: int
        - user_role: str
        - action: str
        - target_name: str
        - target_owner: int
        - target_visibility: str
        - target_sharedwith: str

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
             'messages': list of str messages if any}

    '''

    for key in ('user_id','user_role','action','target_name',
                'target_owner','target_visibility',
                'target_sharedwith'):

        if key not in payload:
            LOGGER.error('Invalid access grant request.')

            return {
                'success':False,
                'user_info':None,
                'messages':["Invalid access grant request."],
            }

    try:

        currproc = mp.current_process()

        # override permissions JSON if necessary
        if override_permissions_json:
            currproc.permissions_json = override_permissions_json

        # validate the access request
        access_granted = permissions.load_policy_and_check_access(
            currproc.permissions_json,
            userid=payload['user_id'],
            role=payload['user_role'],
            action=payload['action'],
            target_name=payload['target_name'],
            target_owner=payload['target_owner'],
            target_visibility=payload['target_visibility'],
            target_sharedwith=payload['target_sharedwith']
        )

        # make sure the incoming user ID, target user ID, and any
        # target_sharedwith user IDs actually exist in the database
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

        originating_userid = int(payload['user_id'])
        originating_user_role = payload['user_role']
        target_userid = int(payload['target_owner'])
        target_sharedwith = payload['target_sharedwith']

        userids_to_check = [originating_userid,
                            target_userid]

        if (target_sharedwith and
            target_sharedwith != '' and
            target_sharedwith.lower() != 'none'):

            sharedwith_userids = target_sharedwith.split(',')
            sharedwith_userids = [int(x) for x in sharedwith_userids]
            userids_to_check.extend(sharedwith_userids)

        userids_to_check = list(set(userids_to_check))

        # check if the originating_userid is legit
        s = select([
            users.c.user_id
        ]).select_from(users).where(
            users.c.user_id == originating_userid
        ).where(
            users.c.user_role == originating_user_role
        ).where(
            users.c.is_active.is_(True)
        )
        result = currproc.authdb_conn.execute(s)
        row = result.scalar()

        if not row or row != originating_userid:
            return {
                'success': False,
                'messages':['Access request check successful. '
                            'Access granted: False.']
            }

        # now check if the rest of the user IDs make sense
        s = select([
            users.c.user_id,
        ]).select_from(users).where(
            users.c.user_id.in_(userids_to_check)
        ).where(
            users.c.is_active.is_(True)
        )

        result = currproc.authdb_conn.execute(s)
        rows = result.fetchall()
        result.close()

        try:

            # make sure all of the userids to check were found in the DB
            if rows and len(rows) > 0:

                users_found = list(list(zip(*rows))[0])
                if sorted(userids_to_check) == sorted(users_found):

                    return {
                        'success': access_granted,
                        'messages':['Access request check successful. '
                                    'Access granted: %s.' % access_granted]
                    }

                else:

                    return {
                        'success': False,
                        'messages':['Access request check successful. '
                                    'Access granted: False.']
                    }

            else:

                return {
                    'success': False,
                    'messages':['Access request check successful. '
                                'Access granted: False.']
                }

        except Exception:

            if raiseonfail:
                raise

            return {
                'success':False,
                'messages':["Access request check failed."],
            }

    except Exception:

        if raiseonfail:
            raise

        LOGGER.error('Could not validate access to the '
                     'requested item because of an exception.')

        return {
            'success':False,
            'messages':["Could not validate access to the requested item."],
        }


def check_user_limit(payload,
                     raiseonfail=False,
                     override_permissions_json=None,
                     override_authdb_path=None):
    '''Applies a specified limit to an item based on a permissions policy.

    Parameters
    ----------

    payload : dict
        This is the input payload dict. Required items:

        - user_id: int
        - user_role: str
        - limit_name: str
        - value_to_check: any

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
             'messages': list of str messages if any}

    '''

    for key in ('user_id','user_role','limit_name','value_to_check'):

        if key not in payload:
            LOGGER.error('Invalid limit check request.')

            return {
                'success':False,
                'user_info':None,
                'messages':["Invalid limit check request."],
            }

    try:

        currproc = mp.current_process()

        # override if necessary
        if override_permissions_json:
            currproc.permissions_json = override_permissions_json

        # load the permissions JSON
        limit_checked = permissions.load_policy_and_check_limits(
            currproc.permissions_json,
            payload['user_role'],
            payload['limit_name'],
            payload['value_to_check']
        )

        # make sure the incoming user ID and role actually exist in the database
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

        originating_userid = int(payload['user_id'])
        originating_user_role = str(payload['user_role'])

        s = select([
            users.c.user_id
        ]).select_from(users).where(
            users.c.user_id == originating_userid
        ).where(
            users.c.user_role == originating_user_role
        ).where(
            users.c.is_active.is_(True)
        )

        result = currproc.authdb_conn.execute(s)
        rows = result.fetchall()
        result.close()

        try:

            if rows and len(rows) > 0:
                return {
                    'success': limit_checked,
                    'messages':['Limit check successful. '
                                'Limit check passed: %s.' % limit_checked]
                }
            else:

                return {
                    'success': False,
                    'messages':['Limit check successful. '
                                'Limit check passed: False.']
                }

        except Exception:

            if raiseonfail:
                raise

            return {
                'success':False,
                'user_info':None,
                'messages':["Limit check failed."],
            }

    except Exception:

        if raiseonfail:
            raise

        LOGGER.error('Could not validate limit rule for the '
                     'requested item because of an exception.')

        return {
            'success':False,
            'messages':["Could not validate limit "
                        "rule for the requested item."],
        }
