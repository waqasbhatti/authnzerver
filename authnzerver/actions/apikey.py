# -*- coding: utf-8 -*-
# actions_apikey.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''This contains functions to drive API key related auth actions.

'''

#############
## LOGGING ##
#############

import logging
import json

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

import secrets
import multiprocessing as mp

from sqlalchemy import select

from .. import authdb
from .session import auth_session_exists
from ..permissions import pii_hash
from .access import check_user_access


######################
## API KEY HANDLING ##
######################

def issue_apikey(payload,
                 raiseonfail=False,
                 override_authdb_path=None,
                 override_permissions_json=None):
    '''Issues a new API key.

    Parameters
    ----------

    payload : dict
        The payload dict must have the following keys:

        - issuer: str, the entity that will be designated as the API key issuer
        - audience: str, the service this API key is being issued for
        - subject: str, the specific API endpoint API key is being issued for
        - apiversion: int or str, the API version that the API key is valid for
        - expires_days: int, the number of days after which the API key will
          expire
        - not_valid_before: float or int, the amount of seconds after utcnow()
          when the API key becomes valid
        - user_id: int, the user ID of the user requesting the API key
        - user_role: str, the user role of the user requesting the API key
        - ip_address: str, the IP address to tie the API key to
        - user_agent: str, the browser user agent requesting the API key
        - session_token: str, the session token of the user requesting the API
          key

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    override_permissions_json : str or None
        If given as a str, is the alternative path to the permissions JSON to
        use. This is used to check if the user_id is allowed to actually request
        an API key.

    Returns
    -------

    dict
        The dict returned is of the form::

            {'success': True or False,
             'apikey': apikey dict,
             'expires': expiry datetime in ISO format,
             'messages': list of str messages if any}

    Notes
    -----

    API keys are tied to an IP address and client header combination.

    This function will return a dict with all the API key information. This
    entire dict should be serialized to JSON, encrypted and time-stamp signed by
    the frontend as the final "API key", and finally sent back to the client.

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'apikey':None,
                'expires':None,
                'messages':["Invalid API key request."],
            }

    for key in ('user_id',
                'user_role',
                'expires_days',
                'not_valid_before',
                'issuer',
                'audience',
                'subject',
                'ip_address',
                'user_agent',
                'session_token',
                'apiversion'):

        if key not in payload:
            LOGGER.error(
                '[%s] Invalid API key request, missing %s.' %
                (payload['reqid'], key)
            )

        if key not in payload:
            return {
                'success':False,
                'apikey':None,
                'expires':None,
                'messages':["Some required keys are missing from payload."]
            }

    # check if the provided user_id and role can actually create an API key
    user_id = payload['user_id']
    user_role = payload['user_role']

    apikey_creation_allowed = check_user_access(
        {'user_id':user_id,
         'user_role':user_role,
         'action':'create',
         'target_name':'apikey',
         'target_owner':user_id,
         'target_visibility':'private',
         'target_sharedwith':None,
         'reqid':payload['reqid'],
         'pii_salt':payload['pii_salt']},
        raiseonfail=raiseonfail,
        override_permissions_json=override_permissions_json,
        override_authdb_path=override_authdb_path
    )

    if not apikey_creation_allowed['success']:

        LOGGER.error(
            "[%s] Invalid API key issuance request. "
            "from user_id: %s, role: %s. "
            "The user is not allowed to create an API key." %
            (payload['reqid'],
             pii_hash(user_id, payload['pii_salt']),
             pii_hash(user_role, payload['pii_salt']))
        )
        return {
            'success':False,
            'messages':["API key issuance failed. "
                        "You are not allowed to issue an API key."]
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

    # check the session
    session_info = auth_session_exists(
        {'session_token':payload['session_token'],
         'pii_salt':payload['pii_salt'],
         'reqid':payload['reqid']},
        raiseonfail=raiseonfail,
        override_authdb_path=override_authdb_path
    )

    if not session_info['success']:

        LOGGER.error(
            "[%s] Invalid API key request. "
            "user_id: %s, session_token: %s, role: %s, "
            "ip_address: %s, user_agent: %s requested an API key for "
            "audience: %s, subject: %s, apiversion: %s."
            "Session token of requestor was not found in the DB." %
            (payload['reqid'],
             pii_hash(payload['user_id'],
                      payload['pii_salt']),
             pii_hash(payload['session_token'],
                      payload['pii_salt']),
             payload['user_role'],
             pii_hash(payload['ip_address'],
                      payload['pii_salt']),
             pii_hash(payload['user_agent'],
                      payload['pii_salt']),
             payload['audience'],
             payload['subject'],
             payload['apiversion'])
        )

        return {
            'success':False,
            'apikey':None,
            'expires':None,
            'messages':([
                "Invalid session token for password reset request."
            ])
        }

    session = session_info['session_info']

    # check if the session info matches what we have in the payload
    session_ok = (
        (session['user_id'] == payload['user_id']) and
        (session['ip_address'] == payload['ip_address']) and
        (session['user_agent'] == payload['user_agent']) and
        (session['user_role'] == payload['user_role'])
    )

    if not session_ok:

        LOGGER.error(
            "[%s] Invalid API key request. "
            "user_id: %s, session_token: %s, role: %s, "
            "ip_address: %s, user_agent: %s requested an API key for "
            "audience: %s, subject: %s, apiversion: %s."
            "Session token info of requestor does not match payload info." %
            (payload['reqid'],
             pii_hash(payload['user_id'],
                      payload['pii_salt']),
             pii_hash(payload['session_token'],
                      payload['pii_salt']),
             payload['user_role'],
             pii_hash(payload['ip_address'],
                      payload['pii_salt']),
             pii_hash(payload['user_agent'],
                      payload['pii_salt']),
             payload['audience'],
             payload['subject'],
             payload['apiversion'])
        )

        return {
            'success':False,
            'apikey':None,
            'expires':None,
            'messages':([
                "DB session user_id, ip_address, user_agent, "
                "user_role does not match provided session info."
            ])
        }

    #
    # finally, generate the API key
    #
    random_token = secrets.token_urlsafe(32)

    # we'll return this API key dict to the frontend so it can JSON dump it,
    # encode to bytes, then encrypt, then sign it, and finally send back to the
    # client
    issued = datetime.utcnow()
    expires = issued + timedelta(days=payload['expires_days'])

    notvalidbefore = (
        issued +
        timedelta(seconds=payload['not_valid_before'])
    )

    apikey_dict = {
        'iss':payload['issuer'],
        'ver':payload['apiversion'],
        'uid':payload['user_id'],
        'rol':payload['user_role'],
        'usa':payload['user_agent'],
        'aud':payload['audience'],
        'sub':payload['subject'],
        'ipa':payload['ip_address'],
        'tkn':random_token,
        'iat':issued.isoformat(),
        'nbf':notvalidbefore.isoformat(),
        'exp':expires.isoformat()
    }
    apikey_json = json.dumps(apikey_dict)

    # we'll also store this dict in the apikeys table
    apikeys = currproc.authdb_meta.tables['apikeys']

    # NOTE: we store only the random token. this will later be checked for
    # equality against the value stored in the API key dict['tkn'] when we send
    # in this API key for verification later
    ins = apikeys.insert({
        'apikey':random_token,
        'issued':issued,
        'expires':expires,
        'not_valid_before':notvalidbefore,
        'user_id':payload['user_id'],
        'user_role':payload['user_role'],
        'session_token':payload['session_token'],
    })

    result = currproc.authdb_conn.execute(ins)
    result.close()

    #
    # return the API key to the frontend
    #

    LOGGER.info(
        "[%s] API key request successful. "
        "user_id: %s, session_token: %s, role: %s, "
        "ip_address: %s, user_agent: %s requested an API key for "
        "audience: %s, subject: %s, apiversion: %s."
        "API key not valid before: %s, expires on: %s." %
        (payload['reqid'],
         pii_hash(payload['user_id'],
                  payload['pii_salt']),
         pii_hash(payload['session_token'],
                  payload['pii_salt']),
         payload['user_role'],
         pii_hash(payload['ip_address'],
                  payload['pii_salt']),
         pii_hash(payload['user_agent'],
                  payload['pii_salt']),
         payload['audience'],
         payload['subject'],
         payload['apiversion'],
         notvalidbefore.isoformat(),
         expires.isoformat())
    )

    messages = (
        "API key generated successfully for user_id = %s, expires: %s." %
        (payload['user_id'],
         expires.isoformat())
    )

    return {
        'success':True,
        'apikey':apikey_json,
        'expires':expires.isoformat(),
        'messages':([
            messages
        ])
    }


def verify_apikey(payload,
                  raiseonfail=False,
                  override_authdb_path=None,
                  override_permissions_json=None):
    '''Checks if an API key is valid.

    Parameters
    ----------

    payload : dict
        This dict contains a single key:

        - apikey_dict: the decrypted and verified API key info dict from the
          frontend.

        - user_id: the user ID of the person wanting to verify this key.

        - user_role: the user role of the person wanting to verify this key.

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    override_permissions_json : str or None
        If given as a str, is the alternative path to the permissions JSON to
        use. This is used to check if the user_id is allowed to actually verify
        ("read") an API key.

    Returns
    -------

    dict
        The dict returned is of the form::

            {'success': True if API key is OK and False otherwise,
             'messages': list of str messages if any}

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'apikey':None,
                'expires':None,
                'messages':["Invalid API key request."],
            }

    if 'apikey_dict' not in payload:

        LOGGER.error(
            '[%s] Invalid API key request, missing %s.' %
            (payload['reqid'], 'apikey_dict')
        )

        return {
            'success':False,
            'messages':["Some required keys are missing from payload."]
        }

    apikey_dict = payload['apikey_dict']
    user_id = payload['user_id']
    user_role = payload['user_role']

    # check if the user is allowed to read the presented API key
    apikey_verify_allowed = check_user_access(
        {'user_id':user_id,
         'user_role':user_role,
         'action':'view',
         'target_name':'apikey',
         'target_owner':apikey_dict['uid'],
         'target_visibility':'private',
         'target_sharedwith':None,
         'reqid':payload['reqid'],
         'pii_salt':payload['pii_salt']},
        raiseonfail=raiseonfail,
        override_permissions_json=override_permissions_json,
        override_authdb_path=override_authdb_path
    )

    if not apikey_verify_allowed['success']:

        LOGGER.error(
            "[%s] Invalid API key verification request. "
            "from user_id: %s, role: %s. The API key presented is "
            "not readable by this user." %
            (payload['reqid'],
             pii_hash(user_id, payload['pii_salt']),
             pii_hash(user_role, payload['pii_salt']))
        )
        return {
            'success':False,
            'messages':["API key verification failed. "
                        "You are not allowed to operate on this API key."]
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

    apikeys = currproc.authdb_meta.tables['apikeys']

    # the apikey sent to us must match the stored apikey's properties:
    # - token
    # - userid
    # - expired must be in the future
    # - issued must be in the past
    # - not_valid_before must be in the past
    dt_utcnow = datetime.utcnow()

    sel = select([
        apikeys.c.apikey,
        apikeys.c.expires,
    ]).select_from(apikeys).where(
        apikeys.c.apikey == apikey_dict['tkn']
    ).where(
        apikeys.c.user_id == apikey_dict['uid']
    ).where(
        apikeys.c.user_role == apikey_dict['rol']
    ).where(
        apikeys.c.expires > dt_utcnow
    ).where(
        apikeys.c.issued < dt_utcnow
    ).where(
        apikeys.c.not_valid_before < dt_utcnow
    )
    result = currproc.authdb_conn.execute(sel)
    row = result.fetchone()
    result.close()

    if row is not None and len(row) != 0:

        LOGGER.info(
            '[%s] API key verified successfully. '
            'user_id: %s, role: %s, audience: %s, subject: %s, '
            'apiversion: %s, expires on: %s' %
            (payload['reqid'],
             pii_hash(apikey_dict['uid'],
                      payload['pii_salt']),
             apikey_dict['rol'],
             apikey_dict['aud'],
             apikey_dict['sub'],
             apikey_dict['ver'],
             apikey_dict['exp'])
        )

        return {
            'success':True,
            'messages':[(
                "API key verified successfully. Expires: %s." %
                row['expires'].isoformat()
            )]
        }

    else:

        LOGGER.error(
            '[%s] API key verification failed. Failed key '
            'user_id: %s, role: %s, audience: %s, subject: %s, '
            'apiversion: %s, expires on: %s' %
            (payload['reqid'],
             pii_hash(apikey_dict['uid'],
                      payload['pii_salt']),
             apikey_dict['rol'],
             apikey_dict['aud'],
             apikey_dict['sub'],
             apikey_dict['ver'],
             apikey_dict['exp'])
        )

        return {
            'success':False,
            'messages':[(
                "API key could not be verified."
            )]
        }


def revoke_apikey(payload,
                  raiseonfail=False,
                  override_authdb_path=None,
                  override_permissions_json=None):
    '''Revokes an API key.

    Parameters
    ----------

    payload : dict
        This dict contains the following keys:

        - apikey_dict: the decrypted and verified API key info dict from the
          frontend.

        - user_id: the user ID of the person revoking this key. Only superusers
          or staff can revoke an API key that doesn't belong to them.

        - user_role: the user ID of the person revoking this key. Only
          superusers or staff can revoke an API key that doesn't belong to them.

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    override_permissions_json : str or None
        If given as a str, is the alternative path to the permissions JSON to
        use. This is used to check if the user_id is allowed to actually revoke
        ("delete") an API key.


    Returns
    -------

    dict
        The dict returned is of the form::

            {'success': True if API key was revoked and False otherwise,
             'messages': list of str messages if any}

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'messages':["Invalid API key revocation request."],
            }

    for key in ('apikey_dict','user_id','user_role'):
        if 'apikey_dict' not in payload:

            LOGGER.error(
                '[%s] Invalid API key revocation request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success':False,
                'messages':["Some required keys are missing from payload."]
            }

    apikey_dict = payload['apikey_dict']
    user_id = payload['user_id']
    user_role = payload['user_role']

    # check if the user is allowed to revoke the presented API key
    apikey_revocation_allowed = check_user_access(
        {'user_id':user_id,
         'user_role':user_role,
         'action':'delete',
         'target_name':'apikey',
         'target_owner':apikey_dict['uid'],
         'target_visibility':'private',
         'target_sharedwith':None,
         'reqid':payload['reqid'],
         'pii_salt':payload['pii_salt']},
        raiseonfail=raiseonfail,
        override_permissions_json=override_permissions_json,
        override_authdb_path=override_authdb_path
    )

    if not apikey_revocation_allowed['success']:

        LOGGER.error(
            "[%s] Invalid API key revocation request. "
            "from user_id: %s, role: %s. The API key presented is "
            "not revocable by this user." %
            (payload['reqid'],
             pii_hash(user_id, payload['pii_salt']),
             pii_hash(user_role, payload['pii_salt']))
        )
        return {
            'success':False,
            'messages':["API key revocation failed. "
                        "You are not allowed to operate on this API key."]
        }

    #
    # everything checks out so go ahead and delete the API key
    #

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

    apikeys = currproc.authdb_meta.tables['apikeys']
    delete = apikeys.delete().where(
        apikeys.c.apikey == apikey_dict['tkn']
    ).where(
        apikeys.c.user_id == apikey_dict['uid']
    ).where(
        apikeys.c.user_role == apikey_dict['rol']
    )
    result = currproc.authdb_conn.execute(delete)
    result.close()

    LOGGER.info(
        "[%s] API key revocation request succeeded. "
        "User_id: %s, role: %s." %
        (payload['reqid'],
         pii_hash(user_id, payload['pii_salt']),
         pii_hash(user_role, payload['pii_salt']))
    )

    return {
        'success':True,
        'messages':["API key revocation successful."]
    }
