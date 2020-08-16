# -*- coding: utf-8 -*-
# actions_user.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""This contains functions to drive user account related auth actions.

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

from .. import authdb
from ..permissions import pii_hash

from .. import validators

from .passwords import validate_input_password

######################
## PASSWORD CONTEXT ##
######################

pass_hasher = PasswordHasher()


###################
## USER HANDLING ##
###################

def create_new_user(
        payload,
        min_pass_length=12,
        max_unsafe_similarity=30,
        override_authdb_path=None,
        raiseonfail=False,
        config=None
):
    """Makes a new user.

    Parameters
    ----------

    payload : dict
        This is a dict with the following required keys:

        - full_name: str. Full name for the user

        - email: str. User's email address

        - password: str. User's password.

        - extra_info: dict or None. optional dict to add any extra info for this
          user, will be stored as JSON in the DB

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
    emailverify_sent_datetime is at least 24 hours in the past, we'll send a new
    email verification email and update the emailverify_sent_datetime. In this
    case, we'll just tell the user that we've sent the email but won't tell them
    if their account exists.

    Only after the user verifies their email, is_active will be set to True and
    user_role will be set to 'authenticated'.

    """

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_email':None,
                'user_id':None,
                'send_verification':False,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'messages':["Invalid user creation request."],
            }

    for key in ('full_name',
                'email',
                'password'):

        if key not in payload:

            LOGGER.error(
                '[%s] Invalid user creation request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success':False,
                'user_email':None,
                'user_id':None,
                'send_verification':False,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'messages':["Invalid user creation request."]
            }

    #
    # validate the email provided
    #

    # check for Unicode confusables and dangerous usernames
    email_confusables_ok = (
        validators.validate_confusables_email(payload['email'])
    )

    # check if the email is a valid one according to HTML5 specs
    email_regex_ok = validators.validate_email_address(payload['email'])

    # check if the email domain is not a disposable email address
    if email_confusables_ok and email_regex_ok:
        email_domain = payload['email'].split('@')[1].casefold()
        email_domain_not_disposable = (
            email_domain not in validators.DISPOSABLE_EMAIL_DOMAINS
        )
    else:
        email_domain_not_disposable = False

    # if all of the tests above pass, the email is OK
    email_ok = (
        email_regex_ok and
        email_confusables_ok and
        email_domain_not_disposable
    )

    if not email_ok:

        LOGGER.error(
            "[%s] User creation request failed for "
            "email: %s. "
            "The email address provided is not valid." %
            (payload['reqid'],
             pii_hash(payload['email'],
                      payload['pii_salt']))
        )

        return {
            'success':False,
            'user_email':None,
            'user_id':None,
            'send_verification':False,
            'failure_reason':"invalid email",
            'messages':["The email address provided doesn't "
                        "seem to be a valid email address and cannot be used "
                        "to sign up for an account on this server."]
        }

    email = validators.normalize_value(payload['email'])
    full_name = validators.normalize_value(payload['full_name'])
    password = payload['password']
    extra_info = payload.get("extra_info", None)

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

    input_password = password[:256]

    # hash the user's password
    hashed_password = pass_hasher.hash(input_password)

    # validate the input password to see if it's OK
    # do this here to make sure the password hash completes at least once
    passok, messages = validate_input_password(
        full_name,
        email,
        input_password,
        payload['pii_salt'],
        payload['reqid'],
        min_pass_length=min_pass_length,
        max_unsafe_similarity=max_unsafe_similarity,
        config=config,
    )

    if not passok:

        LOGGER.error(
            "[%s] User creation request failed for "
            "email: %s. "
            "The password provided is not secure." %
            (payload['reqid'],
             pii_hash(payload['email'],
                      payload['pii_salt']))
        )

        return {
            'success':False,
            'user_email':email,
            'user_id':None,
            'send_verification':False,
            'failure_reason':"invalid password",
            'messages':messages
        }

    # insert stuff into the user's table, set is_active = False, user_role =
    # 'locked', the emailverify_sent_datetime to datetime.utcnow()

    try:

        # create a system_id for this user
        system_id = str(uuid.uuid4())

        if not extra_info:
            extra_info = {
                "provenance":"request-created",
                "type":"normal-user",
            }
        else:
            extra_info.update({
                "provenance":"request-created",
                "type":"normal-user",
            })

        new_user_dict = {
            'full_name':full_name,
            'system_id':system_id,
            'password':hashed_password,
            'email':email,
            'email_verified':False,
            'is_active':False,
            'emailverify_sent_datetime':datetime.utcnow(),
            'created_on':datetime.utcnow(),
            'user_role':'locked',
            'last_updated':datetime.utcnow(),
            'extra_info':extra_info,
        }
        ins = users.insert(new_user_dict)
        result = currproc.authdb_conn.execute(ins)
        result.close()

        user_added = True

    # this will catch stuff like people trying to sign up again with their email
    # address
    except Exception:

        user_added = False

    # get back the user ID
    sel = select([
        users.c.email,
        users.c.user_id,
        users.c.is_active,
        users.c.emailverify_sent_datetime,
    ]).select_from(users).where(
        users.c.email == email
    )
    result = currproc.authdb_conn.execute(sel)
    rows = result.fetchone()
    result.close()

    # if the user was added successfully, tell the frontend all is good and to
    # send a verification email
    if user_added and rows:

        LOGGER.info(
            "[%s] User creation request succeeded for "
            "email: %s. New user_id: %s" %
            (payload['reqid'],
             pii_hash(payload['email'],
                      payload['pii_salt']),
             pii_hash(rows['user_id'], payload['pii_salt']))
        )

        messages.append(
            'User account created. Please verify your email address to log in.'
        )

        return {
            'success':True,
            'user_email':rows['email'],
            'user_id':rows['user_id'],
            'send_verification':True,
            'messages':messages
        }

    # if the user wasn't added successfully, then they exist in the DB already
    elif (not user_added) and rows:

        LOGGER.error(
            "[%s] User creation request failed for "
            "email: %s. "
            "The email provided probably exists in the DB already. " %
            (payload['reqid'],
             pii_hash(payload['email'],
                      payload['pii_salt']))
        )

        # check the timedelta between now and the emailverify_sent_datetime
        verification_timedelta = (datetime.utcnow() -
                                  rows['emailverify_sent_datetime'])

        # this sets whether we should resend the verification email
        resend_verification = (
            not(rows['is_active']) and
            (verification_timedelta > timedelta(hours=24))
        )
        LOGGER.warning(
            '[%s] Existing user_id = %s for new user creation '
            'request with email = %s, is_active = %s. '
            'Email verification originally sent at = %sZ, '
            'will resend verification = %s' %
            (payload['reqid'],
             pii_hash(rows['user_id'], payload['pii_salt']),
             pii_hash(payload['email'], payload['pii_salt']),
             rows['is_active'],
             rows['emailverify_sent_datetime'].isoformat(),
             resend_verification)
        )

        messages.append(
            'User account created. Please verify your email address to log in.'
        )
        return {
            'success':False,
            'user_email':rows['email'],
            'user_id':rows['user_id'],
            'send_verification':resend_verification,
            'failure_reason':"user exists",
            'messages':messages
        }

    # otherwise, the user wasn't added successfully and they don't already exist
    # in the database so something else went wrong.
    else:

        LOGGER.error(
            '[%s] User creation request failed for email: %s. '
            'Could not add row to the DB.' %
            (payload['reqid'],
             pii_hash(payload['email'], payload['pii_salt']))
        )

        messages.append(
            'User account created. Please verify your email address to log in.'
        )
        return {
            'success':False,
            'user_email':None,
            'user_id':None,
            'send_verification':False,
            'failure_reason':"DB issue with user creation",
            'messages':messages
        }


def delete_user(payload,
                raiseonfail=False,
                override_authdb_path=None,
                config=None):
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
                'email':None,
                'user_id':None,
                'messages':["Invalid user deletion request."],
            }

    for key in ('email',
                'user_id',
                'password'):

        if key not in payload:

            LOGGER.error(
                '[%s] Invalid user deletion request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success': False,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'user_id':None,
                'email':None,
                'messages':["Invalid user deletion request."],
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

    users = currproc.authdb_meta.tables['users']
    sessions = currproc.authdb_meta.tables['sessions']

    # check if the incoming email address actually belongs to the user making
    # the request
    sel = select([
        users.c.user_id,
        users.c.email,
        users.c.password,
        users.c.user_role
    ]).select_from(
        users
    ).where(
        users.c.user_id == payload['user_id']
    ).where(
        users.c.email == payload['email']
    )
    result = currproc.authdb_conn.execute(sel)
    row = result.fetchone()

    if not row or len(row) == 0:

        LOGGER.error(
            "[%s] User deletion request failed for "
            "email: %s, user_id: %s. "
            "The email address provided does not match the one on record." %
            (payload['reqid'],
             pii_hash(payload['email'],
                      payload['pii_salt']),
             pii_hash(payload['user_id'],
                      payload['pii_salt']))
        )

        return {
            'success': False,
            'failure_reason':(
                "invalid email"
            ),
            'user_id':payload['user_id'],
            'email':payload['email'],
            'messages':["We could not verify your email address or password."]
        }

    # check if the user's password is valid and matches the one on record
    try:
        pass_ok = pass_hasher.verify(row['password'],
                                     payload['password'][:256])
    except Exception as e:

        LOGGER.error(
            "[%s] User deletion request failed for "
            "email: %s, user_id: %s. "
            "The password provided does not match "
            "the one on record. Exception: %s" %
            (payload['reqid'],
             pii_hash(payload['email'],
                      payload['pii_salt']),
             pii_hash(payload['user_id'],
                      payload['pii_salt']), e)
        )
        pass_ok = False

    if not pass_ok:
        return {
            'success': False,
            'failure_reason':(
                "invalid password"
            ),
            'user_id':payload['user_id'],
            'email':payload['email'],
            'messages':["We could not verify your email address or password."]
        }

    if row['user_role'] == 'superuser':

        LOGGER.error(
            "[%s] User deletion request failed for "
            "email: %s, user_id: %s. "
            "Superusers can't be deleted." %
            (payload['reqid'],
             pii_hash(payload['email'],
                      payload['pii_salt']),
             pii_hash(payload['user_id'],
                      payload['pii_salt']))
        )

        return {
            'success': False,
            'failure_reason':(
                "can't delete superusers"
            ),
            'user_id':payload['user_id'],
            'email':payload['email'],
            'messages':["Can't delete superusers."]
        }

    # delete the user
    delete = users.delete().where(
        users.c.user_id == payload['user_id']
    ).where(
        users.c.email == payload['email']
    ).where(
        users.c.user_role != 'superuser'
    )
    result = currproc.authdb_conn.execute(delete)
    result.close()

    # don't forget to delete the sessions as well
    delete = sessions.delete().where(
        sessions.c.user_id == payload['user_id']
    )
    result = currproc.authdb_conn.execute(delete)
    result.close()

    sel = select([
        users.c.user_id,
        users.c.email,
        sessions.c.session_token
    ]).select_from(
        users.join(sessions)
    ).where(
        users.c.user_id == payload['user_id']
    )

    result = currproc.authdb_conn.execute(sel)
    rows = result.fetchall()

    if rows and len(rows) > 0:

        LOGGER.error(
            "[%s] User deletion request failed for "
            "email: %s, user_id: %s. "
            "The database rows for this user could not be deleted." %
            (payload['reqid'],
             pii_hash(payload['email'],
                      payload['pii_salt']),
             pii_hash(payload['user_id'],
                      payload['pii_salt']))
        )

        return {
            'success': False,
            'failure_reason':(
                "user deletion failed in DB"
            ),
            'user_id':payload['user_id'],
            'email':payload['email'],
            'messages':["Could not delete user from DB."]
        }
    else:

        LOGGER.warning(
            "[%s] User deletion request succeeded for "
            "email: %s, user_id: %s. " %
            (payload['reqid'],
             pii_hash(payload['email'],
                      payload['pii_salt']),
             pii_hash(payload['user_id'],
                      payload['pii_salt']))
        )

        return {
            'success': True,
            'user_id':payload['user_id'],
            'email':payload['email'],
            'messages':["User successfully deleted from DB."]
        }
