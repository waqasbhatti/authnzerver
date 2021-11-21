# -*- coding: utf-8 -*-
# actions_user.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""This contains functions to drive user account related auth actions.

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

import multiprocessing as mp
import uuid

from sqlalchemy import select
from argon2 import PasswordHasher
from tornado.escape import xhtml_escape, squeeze

from ..permissions import pii_hash

from .. import validators

from .passwords import validate_input_password
from authnzerver.actions.utils import get_procdb_permjson

######################
## PASSWORD CONTEXT ##
######################

pass_hasher = PasswordHasher()


###################
## USER HANDLING ##
###################


def create_new_user(
    payload: dict,
    min_pass_length: int = 12,
    max_unsafe_similarity: int = 33,
    override_authdb_path: str = None,
    raiseonfail: bool = False,
    config: SimpleNamespace = None,
) -> dict:
    """Makes a new user.

    Parameters
    ----------

    payload : dict
        This is a dict with the following required keys:

        - full_name: str. Full name for the user

        - email: str. User's email address

        - password: str. User's password.

        Optional payload items include:

        - extra_info: dict. optional dict to add any extra
          info for this user, will be stored as JSON in the DB

        - verify_retry_wait: int, default: 6. This sets the amount of
          time in hours a user must wait before retrying a failed verification
          action, i.e., responding before expiry of and with the correct
          verification token.

        - system_id: str. If this is provided, must be a unique string that will
          serve as the system_id for the user. This ID is safe to share with
          client JS, etc., as opposed to the user_id primary key for the
          user. If not provided, a UUIDv4 will be generated and used for the
          system_id.

        - public_suffix_list: list of str. If this is provided as a payload
          item, it must be a list of domain name suffixes sources from the
          Mozilla Public Suffix list: https://publicsuffix.org/list/. This is
          used to check if the full name of the user may possibly be a spam
          link intended to be used when the authnzerver emails out verification
          tokens for new users. If the full name contains a suffix in this list,
          the user creation request will fail. If this item is not provided in
          the payload, this function will look up the current process's
          namespace to see if it was loaded there and use it from there if so.
          If the public suffix list can't be found in either item, new user
          creation will fail.

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
        Returns a dict with the user's user_id and user_email, and a boolean for
        send_verification.

    Notes
    -----

    If the email address already exists in the database, then either the user
    has forgotten that they have an account or someone else is being
    annoying. In this case, if is_active is True, we'll tell the user that we've
    sent an email but won't do anything. If is_active is False and
    emailverify_sent_datetime is at least *payload['verify_retry_wait']* hours
    in the past, we'll send a new email verification email and update the
    emailverify_sent_datetime. In this case, we'll just tell the user that we've
    sent the email but won't tell them if their account exists.

    Only after the user verifies their email, is_active will be set to True and
    user_role will be set to 'authenticated'.

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
                "user_email": None,
                "user_id": None,
                "send_verification": False,
                "failure_reason": (
                    "invalid request: missing '%s' in request" % key
                ),
                "messages": ["Invalid user creation request."],
            }

    for key in ("full_name", "email", "password"):

        if key not in payload:

            LOGGER.error(
                "[%s] Invalid user creation request, missing %s."
                % (payload["reqid"], key)
            )

            return {
                "success": False,
                "user_email": None,
                "user_id": None,
                "send_verification": False,
                "failure_reason": (
                    "invalid request: missing '%s' in request" % key
                ),
                "messages": ["Invalid user creation request."],
            }

    #
    # validate the email provided
    #

    # check for Unicode confusables and dangerous usernames
    email_confusables_ok = validators.validate_confusables_email(
        payload["email"]
    )

    # check if the email is a valid one according to HTML5 specs
    email_regex_ok = validators.validate_email_address(payload["email"])

    # check if the email domain is not a disposable email address
    if email_confusables_ok and email_regex_ok:
        email_domain = payload["email"].split("@")[1].casefold()
        email_domain_not_disposable = (
            email_domain not in validators.DISPOSABLE_EMAIL_DOMAINS
        )
    else:
        email_domain_not_disposable = False

    # if all of the tests above pass, the email is OK
    email_ok = (
        email_regex_ok and email_confusables_ok and email_domain_not_disposable
    )

    if not email_ok:

        LOGGER.error(
            "[%s] User creation request failed for "
            "email: %s. "
            "The email address provided is not valid."
            % (
                payload["reqid"],
                pii_hash(payload["email"], payload["pii_salt"]),
            )
        )

        return {
            "success": False,
            "user_email": None,
            "user_id": None,
            "send_verification": False,
            "failure_reason": "invalid email",
            "messages": [
                "The email address provided doesn't "
                "seem to be a valid email address and cannot be used "
                "to sign up for an account on this server."
            ],
        }

    email = validators.normalize_value(payload["email"])
    full_name = validators.normalize_value(
        payload["full_name"], casefold=False
    )

    # sanitize the full name
    full_name = squeeze(xhtml_escape(full_name))
    if "http" in full_name.casefold() or "://" in full_name:
        LOGGER.error(
            f"[{payload['reqid']}] Full name provided contains "
            f"a link or is close to one: {full_name} "
            f"and is likely suspicious."
        )
        return {
            "success": False,
            "user_email": None,
            "user_id": None,
            "send_verification": False,
            "failure_reason": "invalid full name",
            "messages": [
                "The full name provided appears to contain "
                "an HTTP link, and cannot be used "
                "to sign up for an account on this server."
            ],
        }

    # check if the full name contains a valid public suffix domain
    # it's probably suspicious if so
    currproc = mp.current_process()
    public_suffix_list = getattr(currproc, "public_suffix_list", None)
    if not public_suffix_list:
        public_suffix_list = payload.get("public_suffix_list", None)

    if not public_suffix_list:
        LOGGER.error(
            f"[{payload['reqid']}] Could not validate full name "
            f"because the public suffix list is not provided in "
            f"either the payload or in the current process namespace."
        )
        return {
            "success": False,
            "user_email": None,
            "user_id": None,
            "send_verification": False,
            "failure_reason": "public suffix list not present",
            "messages": [
                "Full name could not be validated "
                "because of an internal server error"
            ],
        }

    for domain_suffix in public_suffix_list:
        if domain_suffix in full_name.casefold():
            LOGGER.error(
                f"[{payload['reqid']}] Full name provided contains "
                f"a link or is close to one: {full_name} "
                f"and is likely suspicious."
            )
            return {
                "success": False,
                "user_email": None,
                "user_id": None,
                "send_verification": False,
                "failure_reason": "invalid full name",
                "messages": [
                    "The full name provided appears to contain "
                    "an HTTP link, and cannot be used "
                    "to sign up for an account on this server."
                ],
            }

    # get the password
    password = payload["password"]

    #
    # optional items
    #

    # 1. get extra info if any
    extra_info = payload.get("extra_info", None)

    # 2. get the verify_retry_wait time
    verify_retry_wait = payload.get("verify_retry_wait", 6)
    try:
        verify_retry_wait = int(verify_retry_wait)
    except Exception:
        verify_retry_wait = 6

    if verify_retry_wait < 1:
        verify_retry_wait = 1

    # 3. generate or get a system_id for this user
    if "system_id" in payload and isinstance(payload["system_id"], str):
        system_id = payload["system_id"]
    else:
        system_id = str(uuid.uuid4())

    #
    # proceed to processing
    #

    users = meta.tables["users"]

    # the password is restricted to 256 characters since that should be enough
    # (for 2020), and we don't want to kill our own server when hashing absurdly
    # long passwords through Argon2-id.
    input_password = password[:256]

    # hash the user's password
    hashed_password = pass_hasher.hash(input_password)

    # validate the input password to see if it's OK
    # do this here to make sure the password hash completes at least once
    passok, messages = validate_input_password(
        full_name,
        email,
        input_password,
        payload["pii_salt"],
        payload["reqid"],
        min_pass_length=min_pass_length,
        max_unsafe_similarity=max_unsafe_similarity,
        config=config,
    )

    if not passok:

        LOGGER.error(
            "[%s] User creation request failed for "
            "email: %s. "
            "The password provided is not secure."
            % (
                payload["reqid"],
                pii_hash(payload["email"], payload["pii_salt"]),
            )
        )

        return {
            "success": False,
            "user_email": email,
            "user_id": None,
            "send_verification": False,
            "failure_reason": "invalid password",
            "messages": messages,
        }

    # insert stuff into the user's table, set is_active = False, user_role =
    # 'locked', the emailverify_sent_datetime to datetime.utcnow()
    new_user_dict = None

    try:

        if not extra_info:
            extra_info = {
                "provenance": "request-created",
                "type": "normal-user",
                "verify_retry_wait": verify_retry_wait,
            }
        else:
            extra_info.update(
                {
                    "provenance": "request-created",
                    "type": "normal-user",
                    "verify_retry_wait": verify_retry_wait,
                }
            )

        new_user_dict = {
            "full_name": full_name,
            "system_id": system_id,
            "password": hashed_password,
            "email": email,
            "email_verified": False,
            "is_active": False,
            "emailverify_sent_datetime": datetime.utcnow(),
            "created_on": datetime.utcnow(),
            "user_role": "locked",
            "last_updated": datetime.utcnow(),
            "extra_info": extra_info,
        }

        with engine.begin() as conn:
            ins = users.insert(new_user_dict)
            conn.execute(ins)

        user_added = True

    # this will catch stuff like people trying to sign up again with their email
    # address
    except Exception:

        user_added = False

    with engine.begin() as conn:

        # get back the user ID
        sel = (
            select(
                users.c.email,
                users.c.user_id,
                users.c.system_id,
                users.c.is_active,
                users.c.emailverify_sent_datetime,
            )
            .select_from(users)
            .where(users.c.email == email)
        )
        result = conn.execute(sel)
        rows = result.first()

    # if the user was added successfully, tell the frontend all is good and to
    # send a verification email
    if user_added and rows:

        LOGGER.info(
            "[%s] User creation request succeeded for "
            "email: %s. New user_id: %s"
            % (
                payload["reqid"],
                pii_hash(payload["email"], payload["pii_salt"]),
                pii_hash(rows.user_id, payload["pii_salt"]),
            )
        )

        messages.append(
            "User account created. Please verify your email address to log in."
        )

        return {
            "success": True,
            "user_email": rows.email,
            "user_id": rows.user_id,
            "system_id": rows.system_id,
            "send_verification": True,
            "messages": messages,
        }

    # if the user wasn't added successfully, then they exist in the DB already
    elif (not user_added) and rows:

        LOGGER.error(
            "[%s] User creation request failed for "
            "email: %s. "
            "The email provided probably exists in the DB already. "
            % (
                payload["reqid"],
                pii_hash(payload["email"], payload["pii_salt"]),
            )
        )

        # check the timedelta between now and the emailverify_sent_datetime
        verification_timedelta = (
            datetime.utcnow() - rows.emailverify_sent_datetime
        )

        # this sets whether we should resend the verification email
        resend_verification = (not rows.is_active) and (
            verification_timedelta > timedelta(hours=verify_retry_wait)
        )
        LOGGER.warning(
            "[%s] Existing user_id = %s for new user creation "
            "request with email = %s, is_active = %s. "
            "Email verification originally sent at = %sZ, "
            "verification timedelta: %s, verify_retry_wait = %s hours. "
            "Will resend verification = %s"
            % (
                payload["reqid"],
                pii_hash(rows.user_id, payload["pii_salt"]),
                pii_hash(payload["email"], payload["pii_salt"]),
                rows.is_active,
                rows.emailverify_sent_datetime.isoformat(),
                verification_timedelta,
                verify_retry_wait,
                resend_verification,
            )
        )

        if resend_verification:

            # if we're going to resend the verification, update the users table
            # with the latest info sent by the user (they might've changed their
            # password in the meantime)
            if new_user_dict is not None:
                del new_user_dict["created_on"]
                del new_user_dict["system_id"]

            with engine.begin() as conn:

                upd = (
                    users.update()
                    .where(users.c.user_id == rows.user_id)
                    .values(new_user_dict)
                )
                conn.execute(upd)

                # get back the user ID
                sel = (
                    select(
                        users.c.email,
                        users.c.user_id,
                        users.c.system_id,
                        users.c.is_active,
                        users.c.emailverify_sent_datetime,
                    )
                    .select_from(users)
                    .where(users.c.email == email)
                )
                result = conn.execute(sel)
                rows = result.first()

            LOGGER.warning(
                "[%s] Resending verification to user: %s because timedelta "
                "between original sign up and retry: %s > "
                "verify_retry_wait: %s hours. "
                "User information has been updated "
                "with their latest provided sign-up info."
                % (
                    payload["reqid"],
                    pii_hash(rows.user_id, payload["pii_salt"]),
                    verification_timedelta,
                    verify_retry_wait,
                )
            )

        messages.append(
            "User account created. Please verify your email address to log in."
        )
        return {
            "success": False,
            "user_email": rows.email,
            "user_id": rows.user_id,
            "system_id": rows.system_id,
            "send_verification": resend_verification,
            "failure_reason": "user exists",
            "messages": messages,
        }

    # otherwise, the user wasn't added successfully and they don't already exist
    # in the database so something else went wrong.
    else:

        LOGGER.error(
            "[%s] User creation request failed for email: %s. "
            "Could not add row to the DB."
            % (
                payload["reqid"],
                pii_hash(payload["email"], payload["pii_salt"]),
            )
        )

        messages.append(
            "User account created. Please verify your email address to log in."
        )
        return {
            "success": False,
            "user_email": None,
            "user_id": None,
            "send_verification": False,
            "failure_reason": "DB issue with user creation",
            "messages": messages,
        }


def internal_delete_user(
    payload: dict,
    raiseonfail: bool = False,
    override_authdb_path: str = None,
    config: SimpleNamespace = None,
) -> dict:
    """Deletes a user and does not check for permissions.

    Suitable ONLY for internal server use by a frontend. Do NOT expose this
    function to an end user.

    Parameters
    ----------

    payload : dict
        This is a dict with the following required keys:

        - target_userid: int

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
        Returns a dict containing a success key indicating if the user was
        deleted.
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
                "messages": ["Invalid user deletion request."],
            }

    if "target_userid" not in payload:

        LOGGER.error(
            "[%s] Invalid user deletion request, missing %s."
            % (payload["reqid"], "target_userid")
        )

        return {
            "success": False,
            "failure_reason": (
                "invalid request: missing 'target_userid' in request"
            ),
            "messages": ["Invalid user deletion request."],
        }

    with engine.begin() as conn:

        users = meta.tables["users"]
        sessions = meta.tables["sessions"]

        # delete the user
        delete = users.delete().where(
            users.c.user_id == payload["target_userid"]
        )
        conn.execute(delete)

        # don't forget to delete their sessions as well
        delete = sessions.delete().where(
            sessions.c.user_id == payload["target_userid"]
        )
        conn.execute(delete)

        sel = (
            select(users.c.user_id, users.c.email, sessions.c.session_token)
            .select_from(users.join(sessions))
            .where(users.c.user_id == payload["target_userid"])
        )

        result = conn.execute(sel)
        rows = result.fetchall()

    if rows and len(rows) > 0:

        LOGGER.error(
            "[%s] User deletion request failed for "
            "user_id: %s. "
            "The database rows for this user could not be deleted."
            % (
                payload["reqid"],
                pii_hash(payload["target_userid"], payload["pii_salt"]),
            )
        )

        return {
            "success": False,
            "failure_reason": "user deletion failed in DB",
            "messages": ["Could not delete user from DB."],
        }

    else:

        LOGGER.warning(
            "[%s] User deletion request succeeded for "
            "user_id: %s. "
            % (
                payload["reqid"],
                pii_hash(payload["target_userid"], payload["pii_salt"]),
            )
        )

        return {
            "success": True,
            "user_id": payload["target_userid"],
            "messages": ["User successfully deleted from DB."],
        }


def delete_user(
    payload: dict,
    raiseonfail: bool = False,
    override_authdb_path: str = None,
    config: SimpleNamespace = None,
) -> dict:
    """Deletes a user.

    This can only be called by the user themselves or the superuser.

    FIXME: does this actually check if it's called by the right user?

    FIXME: add check_permissions to this to make more robust

    This will also immediately invalidate all sessions corresponding to the
    target user.

    Superuser accounts cannot be deleted.

    Parameters
    ----------

    payload : dict
        This is a dict with the following required keys:

        - email: str
        - user_id: int
        - password: str

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
        Returns a dict containing a success key indicating if the user was
        deleted.
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
                "email": None,
                "user_id": None,
                "messages": ["Invalid user deletion request."],
            }

    for key in ("email", "user_id", "password"):

        if key not in payload:

            LOGGER.error(
                "[%s] Invalid user deletion request, missing %s."
                % (payload["reqid"], key)
            )

            return {
                "success": False,
                "failure_reason": (
                    "invalid request: missing '%s' in request" % key
                ),
                "user_id": None,
                "email": None,
                "messages": ["Invalid user deletion request."],
            }

    users = meta.tables["users"]
    sessions = meta.tables["sessions"]

    # check if the incoming email address actually belongs to the user making
    # the request
    sel = (
        select(
            users.c.user_id, users.c.email, users.c.password, users.c.user_role
        )
        .select_from(users)
        .where(users.c.user_id == payload["user_id"])
        .where(users.c.email == payload["email"])
    )
    with engine.begin() as conn:
        result = conn.execute(sel)
        row = result.first()

    if not row or len(row) == 0:

        LOGGER.error(
            "[%s] User deletion request failed for "
            "email: %s, user_id: %s. "
            "The email address provided does not match the one on record."
            % (
                payload["reqid"],
                pii_hash(payload["email"], payload["pii_salt"]),
                pii_hash(payload["user_id"], payload["pii_salt"]),
            )
        )

        return {
            "success": False,
            "failure_reason": "invalid email",
            "user_id": payload["user_id"],
            "email": payload["email"],
            "messages": [
                "We could not verify your email address or password."
            ],
        }

    # check if the user's password is valid and matches the one on record
    try:
        pass_ok = pass_hasher.verify(
            row["password"], payload["password"][:256]
        )
    except Exception as e:

        LOGGER.error(
            "[%s] User deletion request failed for "
            "email: %s, user_id: %s. "
            "The password provided does not match "
            "the one on record. Exception: %s"
            % (
                payload["reqid"],
                pii_hash(payload["email"], payload["pii_salt"]),
                pii_hash(payload["user_id"], payload["pii_salt"]),
                e,
            )
        )
        pass_ok = False

    if not pass_ok:
        return {
            "success": False,
            "failure_reason": "invalid password",
            "user_id": payload["user_id"],
            "email": payload["email"],
            "messages": [
                "We could not verify your email address or password."
            ],
        }

    if row["user_role"] == "superuser":

        LOGGER.error(
            "[%s] User deletion request failed for "
            "email: %s, user_id: %s. "
            "Superusers can't be deleted."
            % (
                payload["reqid"],
                pii_hash(payload["email"], payload["pii_salt"]),
                pii_hash(payload["user_id"], payload["pii_salt"]),
            )
        )

        return {
            "success": False,
            "failure_reason": "can't delete superusers",
            "user_id": payload["user_id"],
            "email": payload["email"],
            "messages": ["Can't delete superusers."],
        }

    # delete the user
    with engine.begin() as conn:
        delete = (
            users.delete()
            .where(users.c.user_id == payload["user_id"])
            .where(users.c.email == payload["email"])
            .where(users.c.user_role != "superuser")
        )
        result = conn.execute(delete)
        result.close()

        # don't forget to delete the sessions as well
        delete = sessions.delete().where(
            sessions.c.user_id == payload["user_id"]
        )
        result = conn.execute(delete)
        result.close()

        sel = (
            select(users.c.user_id, users.c.email, sessions.c.session_token)
            .select_from(users.join(sessions))
            .where(users.c.user_id == payload["user_id"])
        )

        result = conn.execute(sel)
        rows = result.fetchall()

    if rows and len(rows) > 0:

        LOGGER.error(
            "[%s] User deletion request failed for "
            "email: %s, user_id: %s. "
            "The database rows for this user could not be deleted."
            % (
                payload["reqid"],
                pii_hash(payload["email"], payload["pii_salt"]),
                pii_hash(payload["user_id"], payload["pii_salt"]),
            )
        )

        return {
            "success": False,
            "failure_reason": "user deletion failed in DB",
            "user_id": payload["user_id"],
            "email": payload["email"],
            "messages": ["Could not delete user from DB."],
        }
    else:

        LOGGER.warning(
            "[%s] User deletion request succeeded for "
            "email: %s, user_id: %s. "
            % (
                payload["reqid"],
                pii_hash(payload["email"], payload["pii_salt"]),
                pii_hash(payload["user_id"], payload["pii_salt"]),
            )
        )

        return {
            "success": True,
            "user_id": payload["user_id"],
            "email": payload["email"],
            "messages": ["User successfully deleted from DB."],
        }
