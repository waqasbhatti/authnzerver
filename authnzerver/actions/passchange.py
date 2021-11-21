# -*- coding: utf-8 -*-
# actions_user.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""This contains functions to change passwords.

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

import multiprocessing as mp

from sqlalchemy import select

from .. import authdb
from .session import auth_delete_sessions_userid
from authnzerver.actions.utils import get_procdb_permjson
from ..permissions import pii_hash

from argon2 import PasswordHasher

from .passwords import validate_input_password

######################
## PASSWORD CONTEXT ##
######################

pass_hasher = PasswordHasher()


def change_user_password(
    payload: dict,
    override_authdb_path: str = None,
    raiseonfail: bool = False,
    min_pass_length: int = 12,
    max_unsafe_similarity: int = 33,
    config: SimpleNamespace = None,
) -> dict:
    """Changes the user's password.

    Parameters
    ----------

    payload : dict
        This is a dict with the following required keys:

        - user_id: int
        - session_token: str
        - full_name: str
        - email: str
        - current_password: str
        - new_password: str

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    min_pass_length : int
        The minimum required character length of the password. The value
        provided in this kwarg will be overriden by the ``passpolicy`` attribute
        in the config object if that is passed in as well.

    max_unsafe_similarity : int
        The maximum ratio required to fuzzy-match the input password against
        the server's domain name, the user's email, or their name. The value
        provided in this kwarg will be overriden by the ``passpolicy`` attribute
        in the config object if that is passed in as well.

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    dict
        Returns a dict with the user's user_id and email as keys if successful.

    Notes
    -----

    This logs out the user from all of their other sessions.

    """

    engine, meta, permjson, dbpath = get_procdb_permjson(
        override_authdb_path=override_authdb_path,
        override_permissions_json=None,
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
                "user_id": None,
                "email": None,
                "messages": ["Invalid password change request."],
            }

    for key in {
        "user_id",
        "session_token",
        "full_name",
        "email",
        "current_password",
        "new_password",
    }:

        if key not in payload:

            LOGGER.error(
                "[%s] Invalid password change request, missing %s."
                % (payload["reqid"], key)
            )

            return {
                "success": False,
                "failure_reason": (
                    "invalid request: missing '%s' in request" % key
                ),
                "user_id": None,
                "email": None,
                "messages": [
                    "Invalid password change request. "
                    "Some args are missing."
                ],
            }

    users = meta.tables["users"]

    # get the current password
    sel = (
        select(
            users.c.password,
        )
        .select_from(users)
        .where(users.c.user_id == payload["user_id"])
        .where(users.c.email == payload["email"])
        .where(users.c.is_active.is_(True))
    )

    with engine.begin() as conn:
        result = conn.execute(sel)
        rows = result.first()

    if not rows or len(rows) == 0:

        LOGGER.error(
            "[%s] Password change request failed for "
            "user_id: %s, email: %s. "
            "The user was not found in the DB or is inactive."
            % (
                payload["reqid"],
                pii_hash(payload["user_id"], payload["pii_salt"]),
                pii_hash(payload["email"], payload["pii_salt"]),
            )
        )

        return {
            "success": False,
            "failure_reason": ("user does not exist"),
            "user_id": payload["user_id"],
            "email": payload["email"],
            "messages": [
                "Your current password did " "not match the stored password."
            ],
        }

    #
    # proceed with hashing
    #
    current_password = payload["current_password"][:256]
    new_password = payload["new_password"][:256]

    try:
        pass_check = pass_hasher.verify(rows.password, current_password)
    except Exception:
        pass_check = False

    if not pass_check:

        LOGGER.error(
            "[%s] Password change request failed for "
            "user_id: %s, email: %s. "
            "The input password did not match the stored password."
            % (
                payload["reqid"],
                pii_hash(payload["user_id"], payload["pii_salt"]),
                pii_hash(payload["email"], payload["pii_salt"]),
            )
        )

        return {
            "success": False,
            "failure_reason": ("user password does not match"),
            "user_id": payload["user_id"],
            "email": payload["email"],
            "messages": [
                "Your current password did " "not match the stored password."
            ],
        }

    # check if the new hashed password is the same as the old hashed password,
    # meaning that the new password is just the old one
    try:
        same_check = pass_hasher.verify(rows.password, new_password)
    except Exception:
        same_check = False

    if same_check:

        LOGGER.error(
            "[%s] Password change request failed for "
            "user_id: %s, email: %s. "
            "The new password was the same as the current password."
            % (
                payload["reqid"],
                pii_hash(payload["user_id"], payload["pii_salt"]),
                pii_hash(payload["email"], payload["pii_salt"]),
            )
        )

        return {
            "success": False,
            "failure_reason": ("password did not change"),
            "user_id": payload["user_id"],
            "email": payload["email"],
            "messages": [
                "Your new password cannot " "be the same as your old password."
            ],
        }

    # hash the user's password
    hashed_password = pass_hasher.hash(new_password)

    # validate the input password to see if it's OK
    # do this here to make sure the password hash completes at least once
    # verify the new password is OK
    passok, messages = validate_input_password(
        payload["full_name"],
        payload["email"],
        new_password,
        payload["pii_salt"],
        payload["reqid"],
        min_pass_length=min_pass_length,
        max_unsafe_similarity=max_unsafe_similarity,
        config=config,
    )

    if passok:

        # update the table for this user
        upd = (
            users.update()
            .where(users.c.user_id == payload["user_id"])
            .where(users.c.is_active.is_(True))
            .where(users.c.email == payload["email"])
            .values({"password": hashed_password})
        )

        with engine.begin() as conn:
            conn.execute(upd)

            sel = (
                select(
                    users.c.password,
                )
                .select_from(users)
                .where((users.c.user_id == payload["user_id"]))
            )
            result = conn.execute(sel)
            rows = result.first()

        if rows and rows.password == hashed_password:
            messages.append("Password changed successfully.")

            LOGGER.info(
                "[%s] Password change request succeeded for "
                "user_id: %s, email: %s."
                % (
                    payload["reqid"],
                    pii_hash(payload["user_id"], payload["pii_salt"]),
                    pii_hash(payload["email"], payload["pii_salt"]),
                )
            )

            # delete all of this user's other sessions
            auth_delete_sessions_userid(
                {
                    "session_token": payload["session_token"],
                    "user_id": payload["user_id"],
                    "keep_current_session": True,
                    "reqid": payload["reqid"],
                    "pii_salt": payload["pii_salt"],
                },
                override_authdb_path=override_authdb_path,
                raiseonfail=raiseonfail,
            )

            return {
                "success": True,
                "user_id": payload["user_id"],
                "email": payload["email"],
                "messages": (
                    messages
                    + [
                        "For security purposes, you have been "
                        "logged out of all other sessions."
                    ]
                ),
            }

        else:

            messages.append("Password could not be changed.")

            LOGGER.error(
                "[%s] Password change request failed for "
                "user_id: %s, email: %s. "
                "The user row could not be updated in the DB."
                % (
                    payload["reqid"],
                    pii_hash(payload["user_id"], payload["pii_salt"]),
                    pii_hash(payload["email"], payload["pii_salt"]),
                )
            )

            return {
                "success": False,
                "failure_reason": ("DB error when updating password"),
                "user_id": payload["user_id"],
                "email": payload["email"],
                "messages": messages,
            }

    else:

        LOGGER.error(
            "[%s] Password change request failed for "
            "user_id: %s, email: %s. "
            "The new password entered is insecure."
            % (
                payload["reqid"],
                pii_hash(payload["user_id"], payload["pii_salt"]),
                pii_hash(payload["email"], payload["pii_salt"]),
            )
        )

        messages.append(
            "The new password you entered is insecure. "
            "It must be at least 12 characters long and "
            "be sufficiently complex."
        )
        return {
            "success": False,
            "failure_reason": ("new password is insecure"),
            "user_id": payload["user_id"],
            "email": payload["email"],
            "messages": messages,
        }


def change_user_password_nosession(
    payload: dict,
    override_authdb_path: str = None,
    raiseonfail: bool = False,
    min_pass_length: int = 12,
    max_unsafe_similarity: int = 33,
    config: SimpleNamespace = None,
) -> dict:
    """Changes the user's password.

    This version doesn't require an active session.

    Parameters
    ----------

    payload : dict
        This is a dict with the following required keys:

        - user_id: int
        - full_name: str
        - email: str
        - current_password: str
        - new_password: str

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    min_pass_length : int
        The minimum required character length of the password. The value
        provided in this kwarg will be overriden by the ``passpolicy`` attribute
        in the config object if that is passed in as well.

    max_unsafe_similarity : int
        The maximum ratio required to fuzzy-match the input password against
        the server's domain name, the user's email, or their name. The value
        provided in this kwarg will be overriden by the ``passpolicy`` attribute
        in the config object if that is passed in as well.

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    dict
        Returns a dict with the user's user_id and email as keys if successful.

    Notes
    -----

    This logs out the user from all of their other sessions.

    """

    engine, meta, permjson, dbpath = get_procdb_permjson(
        override_authdb_path=override_authdb_path,
        override_permissions_json=None,
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
                "user_id": None,
                "email": None,
                "messages": ["Invalid password change request."],
            }

    for key in {
        "user_id",
        "full_name",
        "email",
        "current_password",
        "new_password",
    }:

        if key not in payload:

            LOGGER.error(
                "[%s] Invalid password change request, missing %s."
                % (payload["reqid"], key)
            )

            return {
                "success": False,
                "failure_reason": (
                    "invalid request: missing '%s' in request" % key
                ),
                "user_id": None,
                "email": None,
                "messages": [
                    "Invalid password change request. "
                    "Some args are missing."
                ],
            }

    users = meta.tables["users"]

    # get the current password
    sel = (
        select(
            users.c.password,
        )
        .select_from(users)
        .where(users.c.user_id == payload["user_id"])
        .where(users.c.email == payload["email"])
        .where(users.c.is_active.is_(True))
    )

    with engine.begin() as conn:
        result = conn.execute(sel)
        rows = result.first()

    if not rows or len(rows) == 0:

        LOGGER.error(
            "[%s] Password change request failed for "
            "user_id: %s, email: %s. "
            "The user was not found in the DB or is inactive."
            % (
                payload["reqid"],
                pii_hash(payload["user_id"], payload["pii_salt"]),
                pii_hash(payload["email"], payload["pii_salt"]),
            )
        )

        return {
            "success": False,
            "failure_reason": ("user does not exist"),
            "user_id": payload["user_id"],
            "email": payload["email"],
            "messages": [
                "Your current password did " "not match the stored password."
            ],
        }

    #
    # proceed with hashing
    #
    current_password = payload["current_password"][:256]
    new_password = payload["new_password"][:256]

    try:
        pass_check = pass_hasher.verify(rows.password, current_password)
    except Exception:
        pass_check = False

    if not pass_check:

        LOGGER.error(
            "[%s] Password change request failed for "
            "user_id: %s, email: %s. "
            "The input password did not match the stored password."
            % (
                payload["reqid"],
                pii_hash(payload["user_id"], payload["pii_salt"]),
                pii_hash(payload["email"], payload["pii_salt"]),
            )
        )

        return {
            "success": False,
            "failure_reason": ("user password does not match"),
            "user_id": payload["user_id"],
            "email": payload["email"],
            "messages": [
                "Your current password did " "not match the stored password."
            ],
        }

    # check if the new hashed password is the same as the old hashed password,
    # meaning that the new password is just the old one
    try:
        same_check = pass_hasher.verify(rows.password, new_password)
    except Exception:
        same_check = False

    if same_check:

        LOGGER.error(
            "[%s] Password change request failed for "
            "user_id: %s, email: %s. "
            "The new password was the same as the current password."
            % (
                payload["reqid"],
                pii_hash(payload["user_id"], payload["pii_salt"]),
                pii_hash(payload["email"], payload["pii_salt"]),
            )
        )

        return {
            "success": False,
            "failure_reason": ("password did not change"),
            "user_id": payload["user_id"],
            "email": payload["email"],
            "messages": [
                "Your new password cannot " "be the same as your old password."
            ],
        }

    # hash the user's password
    hashed_password = pass_hasher.hash(new_password)

    # validate the input password to see if it's OK
    # do this here to make sure the password hash completes at least once
    # verify the new password is OK
    passok, messages = validate_input_password(
        payload["full_name"],
        payload["email"],
        new_password,
        payload["pii_salt"],
        payload["reqid"],
        min_pass_length=min_pass_length,
        max_unsafe_similarity=max_unsafe_similarity,
        config=config,
    )

    if passok:

        # update the table for this user
        upd = (
            users.update()
            .where(users.c.user_id == payload["user_id"])
            .where(users.c.is_active.is_(True))
            .where(users.c.email == payload["email"])
            .values({"password": hashed_password})
        )

        with engine.begin() as conn:
            conn.execute(upd)
            sel = (
                select(
                    users.c.password,
                )
                .select_from(users)
                .where((users.c.user_id == payload["user_id"]))
            )
            result = conn.execute(sel)
            rows = result.first()

        if rows and rows.password == hashed_password:
            messages.append("Password changed successfully.")

            LOGGER.info(
                "[%s] Password change request succeeded for "
                "user_id: %s, email: %s."
                % (
                    payload["reqid"],
                    pii_hash(payload["user_id"], payload["pii_salt"]),
                    pii_hash(payload["email"], payload["pii_salt"]),
                )
            )

            return {
                "success": True,
                "user_id": payload["user_id"],
                "email": payload["email"],
                "messages": (messages),
            }

        else:

            messages.append("Password could not be changed.")

            LOGGER.error(
                "[%s] Password change request failed for "
                "user_id: %s, email: %s. "
                "The user row could not be updated in the DB."
                % (
                    payload["reqid"],
                    pii_hash(payload["user_id"], payload["pii_salt"]),
                    pii_hash(payload["email"], payload["pii_salt"]),
                )
            )

            return {
                "success": False,
                "failure_reason": ("DB error when updating password"),
                "user_id": payload["user_id"],
                "email": payload["email"],
                "messages": messages,
            }

    else:

        LOGGER.error(
            "[%s] Password change request failed for "
            "user_id: %s, email: %s. "
            "The new password entered is insecure."
            % (
                payload["reqid"],
                pii_hash(payload["user_id"], payload["pii_salt"]),
                pii_hash(payload["email"], payload["pii_salt"]),
            )
        )

        messages.append(
            "The new password you entered is insecure. "
            "It must be at least 12 characters long and "
            "be sufficiently complex."
        )
        return {
            "success": False,
            "failure_reason": ("new password is insecure"),
            "user_id": payload["user_id"],
            "email": payload["email"],
            "messages": messages,
        }
