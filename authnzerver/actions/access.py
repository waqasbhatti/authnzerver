# -*- coding: utf-8 -*-
# access.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""This contains functions to apply access control.

"""

#############
## LOGGING ##
#############

import logging
from types import SimpleNamespace

# get a logger
LOGGER = logging.getLogger(__name__)


#############
## IMPORTS ##
#############

from sqlalchemy import select

from ..permissions import (
    load_policy_and_check_limits,
    load_policy_and_check_access,
    pii_hash,
)
from authnzerver.actions.utils import get_procdb_permjson


################
## FUNCTIONS  ##
################


def check_user_access(
    payload: dict,
    raiseonfail: bool = False,
    override_permissions_json: str = None,
    override_authdb_path: str = None,
    config: SimpleNamespace = None,
) -> dict:
    """Checks for user access to a specified item based on a permissions policy.

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

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

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
             'messages': list of str messages if any}

    """

    engine, meta, permjson, dbpath = get_procdb_permjson(
        override_authdb_path=override_authdb_path,
        override_permissions_json=override_permissions_json,
        raiseonfail=raiseonfail,
    )

    for key in ("reqid", "pii_salt"):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                "success": False,
                "failure_reason": (
                    "invalid request: missing '%s' in request" % key
                ),
                "messages": ["Invalid access grant request."],
            }

    for key in {
        "user_id",
        "user_role",
        "action",
        "target_name",
        "target_owner",
        "target_visibility",
        "target_sharedwith",
    }:

        if key not in payload:
            LOGGER.error(
                "[%s] Invalid access grant request, missing %s."
                % (payload["reqid"], key)
            )

            return {
                "success": False,
                "failure_reason": (
                    "invalid request: missing '%s' in request" % key
                ),
                "messages": ["Invalid access grant request."],
            }

    originating_userid = int(payload["user_id"])
    originating_user_role = payload["user_role"]
    target_userid = int(payload["target_owner"])
    target_sharedwith = payload["target_sharedwith"]

    try:

        # validate the access request
        access_granted = load_policy_and_check_access(
            permjson,
            userid=payload["user_id"],
            role=payload["user_role"],
            action=payload["action"],
            target_name=payload["target_name"],
            target_owner=payload["target_owner"],
            target_visibility=payload["target_visibility"],
            target_sharedwith=payload["target_sharedwith"],
        )

        users = meta.tables["users"]
        userids_to_check = [originating_userid, target_userid]

        if (
            target_sharedwith
            and target_sharedwith != ""
            and target_sharedwith.lower() != "none"
        ):

            sharedwith_userids = target_sharedwith.split(",")
            sharedwith_userids = [int(x) for x in sharedwith_userids]
            userids_to_check.extend(sharedwith_userids)

        userids_to_check = list(set(userids_to_check))

        # check if the originating_userid is legit
        s = (
            select(users.c.user_id)
            .select_from(users)
            .where(users.c.user_id == originating_userid)
            .where(users.c.user_role == originating_user_role)
            .where(users.c.is_active.is_(True))
        )
        with engine.begin() as conn:
            result = conn.execute(s)
            row = result.scalar()

        if not row or row != originating_userid:

            LOGGER.warning(
                "[%s] Access check failed. "
                "user_id: %s with role: '%s' attempted '%s' on '%s', "
                "which was owned by user_id: %s and had visibility: '%s'. "
                % (
                    payload["reqid"],
                    pii_hash(originating_userid, payload["pii_salt"]),
                    payload["user_role"],
                    payload["action"],
                    payload["target_name"],
                    pii_hash(target_userid, payload["pii_salt"]),
                    payload["target_visibility"],
                )
            )

            return {
                "success": False,
                "failure_reason": "user initiating request is not valid",
                "messages": [
                    "Access request check successful. "
                    "Access granted: False."
                ],
            }

        # now check if the rest of the user IDs make sense
        s = (
            select(
                users.c.user_id,
            )
            .select_from(users)
            .where(users.c.user_id.in_(userids_to_check))
            .where(users.c.is_active.is_(True))
        )

        with engine.begin() as conn:
            result = conn.execute(s)
            rows = result.fetchall()

        try:

            # make sure all of the userids to check were found in the DB
            if rows and len(rows) > 0:

                users_found = list(list(zip(*rows))[0])
                if sorted(userids_to_check) == sorted(users_found):

                    LOGGER.info(
                        "[%s] Access check success: %s. "
                        "user_id: %s with role: '%s' attempted '%s' on '%s', "
                        "which was owned by user_id: %s "
                        "and had visibility: '%s'. "
                        % (
                            payload["reqid"],
                            access_granted,
                            pii_hash(originating_userid, payload["pii_salt"]),
                            payload["user_role"],
                            payload["action"],
                            payload["target_name"],
                            pii_hash(target_userid, payload["pii_salt"]),
                            payload["target_visibility"],
                        )
                    )

                    retdict = {
                        "success": access_granted,
                        "messages": [
                            "Access request check successful. "
                            "Access granted: %s." % access_granted
                        ],
                    }

                    if not access_granted:
                        retdict["failure_reason"] = "action not permitted"

                    return retdict

                else:

                    LOGGER.warning(
                        "[%s] Access check failed. "
                        "user_id: %s with role: '%s' attempted '%s' on '%s', "
                        "which was owned by user_id: %s "
                        "and had visibility: '%s'. "
                        % (
                            payload["reqid"],
                            pii_hash(originating_userid, payload["pii_salt"]),
                            payload["user_role"],
                            payload["action"],
                            payload["target_name"],
                            pii_hash(target_userid, payload["pii_salt"]),
                            payload["target_visibility"],
                        )
                    )

                    return {
                        "success": False,
                        "failure_reason": (
                            "users specified as owner or shared-with not found"
                        ),
                        "messages": [
                            "Access request check successful. "
                            "Access granted: False."
                        ],
                    }

            else:

                LOGGER.warning(
                    "[%s] Access check failed. "
                    "user_id: '%s' with role: '%s' attempted '%s' on '%s', "
                    "which was owned by user_id: %s "
                    "and had visibility: '%s'."
                    % (
                        payload["reqid"],
                        pii_hash(originating_userid, payload["pii_salt"]),
                        payload["user_role"],
                        payload["action"],
                        payload["target_name"],
                        pii_hash(target_userid, payload["pii_salt"]),
                        payload["target_visibility"],
                    )
                )

                return {
                    "success": False,
                    "failure_reason": (
                        "none of the users specified in the request were found"
                    ),
                    "messages": [
                        "Access request check successful. "
                        "Access granted: False."
                    ],
                }

        except Exception as e:

            LOGGER.error(
                "[%s] Access check ran into an exception: %r. "
                "user_id: %s with role: '%s' attempted '%s' on '%s', "
                "which was owned by user_id: '%s' and had visibility: '%s'."
                % (
                    payload["reqid"],
                    e,
                    pii_hash(originating_userid, payload["pii_salt"]),
                    payload["user_role"],
                    payload["action"],
                    payload["target_name"],
                    pii_hash(target_userid, payload["pii_salt"]),
                    payload["target_visibility"],
                )
            )

            if raiseonfail:
                raise

            return {
                "success": False,
                "failure_reason": "exception when checking the DB",
                "messages": ["Access request check failed."],
            }

    except Exception as e:

        if raiseonfail:
            raise

        LOGGER.error(
            "[%s] Access check ran into an exception: %r. "
            "user_id: %s with role: '%s' attempted '%s' on '%s', "
            "which was owned by user_id: %s and had visibility: '%s'."
            % (
                payload["reqid"],
                e,
                pii_hash(originating_userid, payload["pii_salt"]),
                payload["user_role"],
                payload["action"],
                payload["target_name"],
                pii_hash(target_userid, payload["pii_salt"]),
                payload["target_visibility"],
            )
        )

        return {
            "success": False,
            "failure_reason": "exception when checking the DB",
            "messages": ["Could not validate access to the requested item."],
        }


def check_user_limit(
    payload: dict,
    raiseonfail: bool = False,
    override_permissions_json: str = None,
    override_authdb_path: str = None,
    config: SimpleNamespace = None,
) -> dict:
    """Applies a specified limit to an item based on a permissions policy.

    Parameters
    ----------

    payload : dict
        This is the input payload dict. Required items:

        - user_id: int
        - user_role: str
        - limit_name: str
        - value_to_check: any

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

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
             'messages': list of str messages if any}

    """

    engine, meta, permjson, dbpath = get_procdb_permjson(
        override_authdb_path=override_authdb_path,
        override_permissions_json=override_permissions_json,
        raiseonfail=raiseonfail,
    )

    for key in ("reqid", "pii_salt"):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                "success": False,
                "failure_reason": (
                    "invalid request: missing '%s' from request" % key
                ),
                "messages": ["Invalid access grant request."],
            }

    for key in ("user_id", "user_role", "limit_name", "value_to_check"):

        if key not in payload:
            LOGGER.error(
                "[%s] Invalid limit check request, missing %s."
                % (payload["reqid"], key)
            )

            return {
                "success": False,
                "failure_reason": (
                    "invalid request: missing '%s' from request" % key
                ),
                "messages": ["Invalid limit check request."],
            }

    originating_userid = int(payload["user_id"])
    originating_user_role = str(payload["user_role"])

    try:

        # load the permissions JSON
        limit_checked = load_policy_and_check_limits(
            permjson,
            payload["user_role"],
            payload["limit_name"],
            payload["value_to_check"],
        )

        # make sure the incoming user ID and role actually exist in the database
        users = meta.tables["users"]

        s = (
            select(users.c.user_id)
            .select_from(users)
            .where(users.c.user_id == originating_userid)
            .where(users.c.user_role == originating_user_role)
            .where(users.c.is_active.is_(True))
        )

        with engine.begin() as conn:
            result = conn.execute(s)
            rows = result.fetchall()

        try:

            if rows and len(rows) > 0:

                LOGGER.info(
                    "[%s] Limit check success: %s. "
                    "user_id: %s with role: '%s', limit name: '%s', "
                    "value checked against limit was: %s."
                    % (
                        payload["reqid"],
                        limit_checked,
                        pii_hash(originating_userid, payload["pii_salt"]),
                        payload["user_role"],
                        payload["limit_name"],
                        payload["value_to_check"],
                    )
                )

                retdict = {
                    "success": limit_checked,
                    "messages": [
                        "Limit check successful. "
                        "Limit check passed: %s." % limit_checked
                    ],
                }

                if not limit_checked:
                    retdict["failure_reason"] = "user is over limit"
                return retdict

            else:

                LOGGER.warning(
                    "[%s] Limit check failed. "
                    "Possibly unknown user_id: %s with "
                    "role: '%s', limit name: '%s', "
                    "value checked against limit was: %s."
                    % (
                        payload["reqid"],
                        pii_hash(originating_userid, payload["pii_salt"]),
                        payload["user_role"],
                        payload["limit_name"],
                        payload["value_to_check"],
                    )
                )

                return {
                    "success": False,
                    "failure_reason": "user attempting access not found",
                    "messages": [
                        "Limit check successful. " "Limit check passed: False."
                    ],
                }

        except Exception as e:

            if raiseonfail:
                raise

            LOGGER.error(
                "[%s] Limit check ran into an exception: %r. "
                "Provided user_id: %s with "
                "role: '%s', limit name: '%s', "
                "value checked against limit was: %s."
                % (
                    payload["reqid"],
                    e,
                    pii_hash(originating_userid, payload["pii_salt"]),
                    payload["user_role"],
                    payload["limit_name"],
                    payload["value_to_check"],
                )
            )

            return {
                "success": False,
                "failure_reason": "exception when checking the DB",
                "messages": ["Limit check failed."],
            }

    except Exception as e:

        if raiseonfail:
            raise

        LOGGER.error(
            "[%s] Limit check ran into an exception: %r. "
            "Provided user_id: %s with "
            "role: '%s', limit name: '%s', "
            "value checked against limit was: %s."
            % (
                payload["reqid"],
                e,
                pii_hash(originating_userid, payload["pii_salt"]),
                payload["user_role"],
                payload["limit_name"],
                payload["value_to_check"],
            )
        )

        return {
            "success": False,
            "failure_reason": "exception when checking the DB",
            "messages": [
                "Could not validate limit " "rule for the requested item."
            ],
        }
