#!/usr/bin/env python
# -*- coding: utf-8 -*-
# actions_admin.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
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
    '''
    This lists users.

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
        load and use for this request. Normally, the permissions JSON has
        already been loaded into process-local variables by the main authnzerver
        start up routines. If you want to use some other permissions model JSON
        (e.g. for testing), provide that here.

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

        if override_permissions_json:
            currproc.permissions_model = permissions.load_permissions_json(
                override_permissions_json
            )

        # validate the access request
        access_granted = permissions.check_item_access(
            currproc.permissions_model,
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

        s = select([
            users.c.user_id
        ]).select_from(users).where(
            users.c.user_id.in_(userids_to_check)
        )

        result = currproc.authdb_conn.execute(s)
        rows = result.fetchall()
        result.close()

        try:

            if rows and len(rows) > 0:
                return {
                    'success': access_granted,
                    'messages':['Access request check successful. '
                                'Access granted: %s.' % access_granted]
                }
            else:

                return {
                    'success': False,
                    'messages':['Access request check failed.']
                }

        except Exception:

            if raiseonfail:
                raise

            return {
                'success':False,
                'user_info':None,
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
