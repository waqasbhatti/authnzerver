#!/usr/bin/env python
# -*- coding: utf-8 -*-
# actions_email.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''This contains functions to drive email-related auth actions.

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

import multiprocessing as mp
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
import smtplib
import time

from sqlalchemy import select

from .. import authdb
from .session import auth_session_exists
from ..permissions import pii_hash


####################
## SENDING EMAILS ##
####################

SIGNUP_VERIFICATION_EMAIL_SUBJECT = (
    '[{server_name}] Please verify your account sign up request'
)
SIGNUP_VERIFICATION_EMAIL_TEMPLATE = '''\
Hello,

This is an automated message from the {server_name} at: {server_baseurl}.

We received an account sign up request for: {user_email}. This request
was made using the browser:

{browser_identifier}

from the IP address: {ip_address}.

Please enter this code:

{verification_code}

into the account verification form at: {server_baseurl}{account_verify_url}

to verify that you made this request. This code will expire on

{verification_expiry}

You will also need to enter your email address and password
to log in.

If you do not recognize the browser and IP address above or did not
initiate this request, someone else may have used your email address
in error. Feel free to ignore this email.

You can see your IP address here: https://www.google.com/search?q=my+ip+address

Thanks,
{server_name} admins
{server_baseurl}
'''


FORGOTPASS_VERIFICATION_EMAIL_SUBJECT = (
    '[{server_name}] Please verify your password reset request'
)
FORGOTPASS_VERIFICATION_EMAIL_TEMPLATE = '''\
Hello,

This is an automated message from the {server_name} at: {server_baseurl}.

We received a password reset request for: {user_email}. This request
was initiated using the browser:

{browser_identifier}

from the IP address: {ip_address}.

Please enter this code:

{verification_code}

into the account verification form at: {server_baseurl}{password_forgot_url}

to verify that you made this request. This code will expire on

{verification_expiry}

If you do not recognize the browser and IP address above or did not
initiate this request, someone else may have used your email address
in error. Feel free to ignore this email.

You can see your IP address here: https://www.google.com/search?q=my+ip+address

Thanks,
{server_name} admins
{server_baseurl}
'''


CHANGEPASS_VERIFICATION_EMAIL_SUBJECT = (
    '[{server_name}] Please verify your password change request'
)
CHANGEPASS_VERIFICATION_EMAIL_TEMPLATE = '''\
Hello,

This is an automated message from the {server_name} at: {server_baseurl}.

We received a password change request for: {user_email}. This request
was initiated using the browser:

{browser_identifier}

from the IP address: {ip_address}.

Please enter this code:

{verification_code}

into the account verification form at: {server_baseurl}{password_change_url}

to verify that you made this request. This code will expire on

{verification_expiry}

If you do not recognize the browser and IP address above or did not
initiate this request, someone else may have used your email address
in error. Feel free to ignore this email.

You can see your IP address here: https://www.google.com/search?q=my+ip+address

Thanks,
{server_name} admins
{server_baseurl}
'''


def authnzerver_send_email(
        sender,
        subject,
        text,
        recipients,
        server,
        user,
        password,
        pii_salt,
        port=587
):
    '''
    This is a utility function to send email.

    Parameters
    ----------

    sender : str
        The name and email address of the entity sending the email in the
        following form::

            "Sender Name <senderemail@example.com>"

    subject : str
        The subject of the email.

    text : str
        The text of the email.

    recipients : list of str
        A list of the email addresses to send the email to. Use either of the
        formats below for each email address::

            "Recipient Name <recipient@example.com>"
            "recipient@example.com"

    server : str
        The address of the email server to use.

    user : str
        The username to use when logging into the email server via SMTP.

    password : str
        The password to use when logging into the email server via SMTP.

    pii_salt : str
        The PII salt value passed in from a wrapping function. Used to censor
        personally identifying information in the logs emitted from this
        function.

    port : int
        The SMTP port to use when logging into the email server via SMTP.

    Returns
    -------

    bool
        Returns True if email sending succeeded. False otherwise.

    '''

    msg = MIMEText(text)
    msg['From'] = sender
    msg['To'] = ', '.join(recipients)
    msg['Message-Id'] = make_msgid()
    msg['Subject'] = subject
    msg['Date'] = formatdate(time.time())

    # next, we'll try to login to the SMTP server
    try:

        server = smtplib.SMTP(server, port)
        server.ehlo()

        if server.has_extn('STARTTLS'):

            try:

                server.starttls()
                server.ehlo()

                server.login(
                    user,
                    password
                )

                server.sendmail(
                    sender,
                    recipients,
                    msg.as_string()
                )

                server.quit()
                return True

            except Exception as e:

                LOGGER.error(
                    "Could not send the email to recipients: %s "
                    "with subject: %s because of an exception: %r"
                    % (', '.join([pii_hash(x, pii_salt) for x in recipients]),
                       subject, e)
                )
                server.quit()
                return False
        else:

            LOGGER.error('Email server: %s does not support TLS, '
                         'will not send an insecure email.' % server)
            server.quit()
            return False

    except Exception as e:

        LOGGER.error(
            "Could not send the email to recipients: %s "
            "with subject: %s because of an exception: %r"
            % (', '.join([pii_hash(x, pii_salt) for x in recipients]),
               subject, e)
        )
        server.quit()
        return False


def send_signup_verification_email(payload,
                                   raiseonfail=False,
                                   override_authdb_path=None):
    '''This actually sends the verification email.

    Parameters
    -----------

    payload : dict
        Keys expected in this dict from a client are:

        - email_address: str, the email address to send the email to
        - session_token: str, session token of the user being sent the email
        - created_info: str, the dict returned by ``users.auth_create_user()``
        - server_name: str, the name of the frontend server
        - server_baseurl: str, the base URL of the frontend server
        - account_verify_url: str, the URL fragment of the frontend verification
          endpoint
        - verification_token: str, a verification token generated by frontend
        - verification_expiry: int, number of seconds after which the token
          expires

        In addition, the following keys must be provided by a wrapper function
        to set up the email server.

        - smtp_user
        - smtp_pass
        - smtp_server
        - smtp_port
        - smtp_sender

        Finally, the payload must also include the following keys (usually added
        in by a wrapping function):

        - reqid: int or str
        - pii_salt: str

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    Returns
    -------

    dict
        Returns a dict containing the user_id, email_address, and the
        verifyemail_sent_datetime value if email was sent successfully.

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_id':None,
                'email_address':None,
                'verifyemail_sent_datetime':None,
                'messages':["Invalid verify email request."],
            }

    for key in ('email_address',
                'session_token',
                'server_name',
                'server_baseurl',
                'account_verify_url',
                'verification_token',
                'verification_expiry',
                'smtp_sender',
                'smtp_user',
                'smtp_pass',
                'smtp_server',
                'smtp_port',
                'created_info'):

        if key not in payload:

            LOGGER.error(
                '[%s] Invalid verify email request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success':False,
                'user_id':None,
                'email_address':None,
                'verifyemail_sent_datetime':None,
                'messages':([
                    "Invalid verify email request."
                ])
            }

    # check if we don't need to send an email to this user
    if payload['created_info']['send_verification'] is False:

        LOGGER.error(
            '[%s] Verify email request failed for '
            'user_id: %s, email: %s, session_token: %s.'
            'Not allowed to send a verification email to this user.' %
            (payload['reqid'],
             pii_hash(payload['created_info']['user_id'], payload['pii_salt']),
             pii_hash(payload['email_address'], payload['pii_salt']),
             pii_hash(payload['session_token'], payload['pii_salt']))
        )

        return {
            'success':False,
            'user_id':None,
            'email_address':None,
            'verifyemail_sent_datetime':None,
            'messages':([
                "Not allowed to send an email verification request."
            ])
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

    # first, we'll verify the user was created successfully, their account is
    # currently set to inactive and their role is 'locked'. then, we'll verify
    # if the session token provided exists and get the IP address and the
    # browser identifier out of it.
    # look up the provided user
    user_sel = select([
        users.c.user_id,
        users.c.email,
        users.c.is_active,
        users.c.user_role,
    ]).select_from(users).where(
        users.c.email == payload['email_address']
    ).where(
        users.c.user_id == payload['created_info']['user_id']
    )
    user_results = currproc.authdb_conn.execute(user_sel)
    user_info = user_results.fetchone()
    user_results.close()

    if not user_info:

        LOGGER.error(
            '[%s] Verify email request failed for '
            'user_id: %s, email: %s, session_token: %s.'
            'The specified user does not exist.' %
            (payload['reqid'],
             pii_hash(payload['created_info']['user_id'], payload['pii_salt']),
             pii_hash(payload['email_address'], payload['pii_salt']),
             pii_hash(payload['session_token'], payload['pii_salt']))
        )

        return {
            'success':False,
            'user_id':None,
            'email_address':None,
            'verifyemail_sent_datetime':None,
            'messages':([
                "Invalid verify email request."
            ])
        }

    if user_info['is_active'] or user_info['user_role'] != 'locked':

        LOGGER.error(
            '[%s] Verify email request failed for '
            'user_id: %s, email: %s, session_token: %s.'
            'The specified user is already active and '
            'does not need a verification email.' %
            (payload['reqid'],
             pii_hash(payload['created_info']['user_id'], payload['pii_salt']),
             pii_hash(payload['email_address'], payload['pii_salt']),
             pii_hash(payload['session_token'], payload['pii_salt']))
        )

        return {
            'success':False,
            'user_id':None,
            'email_address':None,
            'verifyemail_sent_datetime':None,
            'messages':([
                "Not sending an verify email request to an existing user."
            ])
        }

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
            '[%s] Verify email request failed for '
            'user_id: %s, email: %s, session_token: %s.'
            'The session requesting a verify email is not valid.' %
            (payload['reqid'],
             pii_hash(payload['created_info']['user_id'], payload['pii_salt']),
             pii_hash(payload['email_address'], payload['pii_salt']),
             pii_hash(payload['session_token'], payload['pii_salt']))
        )

        return {
            'success':False,
            'user_id':None,
            'email_address':None,
            'verifyemail_sent_datetime':None,
            'messages':([
                "Invalid verify email request."
            ])
        }

    # get the IP address and browser ID from the session
    ip_addr = session_info['session_info']['ip_address']
    browser = session_info['session_info']['user_agent']

    # TODO: we'll use geoip to get the location of the person who initiated the
    # request.

    # get the verification token's expiry datetime
    verification_expiry_td = timedelta(seconds=payload['verification_expiry'])
    verification_expiry_dt = (
        datetime.utcnow() + verification_expiry_td
    ).isoformat()

    # generate the email message
    msgtext = SIGNUP_VERIFICATION_EMAIL_TEMPLATE.format(
        server_baseurl=payload['server_baseurl'],
        server_name=payload['server_name'],
        account_verify_url=payload['account_verify_url'],
        verification_code=payload['verification_token'],
        verification_expiry='%s (UTC time)' % verification_expiry_dt,
        browser_identifier=browser.replace('_','.'),
        ip_address=ip_addr,
        user_email=payload['email_address'],
    )
    sender = payload['smtp_sender']
    recipients = [user_info['email']]
    subject = SIGNUP_VERIFICATION_EMAIL_SUBJECT.format(
        server_name=payload['server_name']
    )

    # send the email
    email_sent = authnzerver_send_email(
        sender,
        subject,
        msgtext,
        recipients,
        payload['smtp_server'],
        payload['smtp_user'],
        payload['smtp_pass'],
        payload['pii_salt'],
        port=payload['smtp_port']
    )

    if email_sent:

        emailverify_sent_datetime = datetime.utcnow()

        # finally, we'll update the users table with the actual
        # verifyemail_sent_datetime if sending succeeded.
        upd = users.update(
        ).where(
            users.c.user_id == payload['created_info']['user_id']
        ).where(
            users.c.is_active.is_(False)
        ).where(
            users.c.email == payload['created_info']['user_email']
        ).values({
            'emailverify_sent_datetime': emailverify_sent_datetime,
        })
        result = currproc.authdb_conn.execute(upd)
        result.close()

        LOGGER.info(
            '[%s] Verify email request succeeded for '
            'user_id: %s, email: %s, session_token: %s.'
            'Email sent on: %s UTC.' %
            (payload['reqid'],
             pii_hash(payload['created_info']['user_id'], payload['pii_salt']),
             pii_hash(payload['email_address'], payload['pii_salt']),
             pii_hash(payload['session_token'], payload['pii_salt']),
             emailverify_sent_datetime.isoformat())
        )

        return {
            'success':True,
            'user_id':user_info['user_id'],
            'email_address':user_info['email'],
            'verifyemail_sent_datetime':emailverify_sent_datetime,
            'messages':([
                "Verify email sent successfully."
            ])
        }

    else:

        LOGGER.error(
            '[%s] Verify email request failed for '
            'user_id: %s, email: %s, session_token: %s.'
            'The email server could not send the email '
            'to the specified address.' %
            (payload['reqid'],
             pii_hash(payload['created_info']['user_id'], payload['pii_salt']),
             pii_hash(payload['email_address'], payload['pii_salt']),
             pii_hash(payload['session_token'], payload['pii_salt']))
        )

        return {
            'success':False,
            'user_id':None,
            'email_address':None,
            'verifyemail_sent_datetime':None,
            'messages':([
                "Could not send email for the verify email request."
            ])
        }


def verify_user_email_address(payload,
                              raiseonfail=False,
                              override_authdb_path=None):
    '''Sets the verification status of the email address of the user.

    This is called by the frontend after it verifies that the token challenge to
    verify the user's email succeeded and has not yet expired. This will set the
    user_role to 'authenticated' and the is_active column to True.

    Parameters
    ----------

    payload : dict
        This is a dict with the following key:

        - email

        Finally, the payload must also include the following keys (usually added
        in by a wrapping function):

        - reqid: int or str
        - pii_salt: str

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    Returns
    -------

    dict
        Returns a dict containing the user_id, is_active, and user_role values
        if verification status is successfully set.

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_id':None,
                'is_active':False,
                'user_role':'locked',
                'messages':["Invalid email verification toggle request."],
            }

    if 'email' not in payload:

        LOGGER.error(
            '[%s] Invalid email verification toggle request, missing %s.' %
            (payload['reqid'], 'email')
        )

        return {
            'success':False,
            'user_id':None,
            'is_active': False,
            'user_role':'locked',
            'messages':["Invalid email verification toggle request."]
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

    # update the table for this user
    upd = users.update(
    ).where(
        users.c.is_active.is_(False)
    ).where(
        users.c.email == payload['email']
    ).values({
        'is_active':True,
        'email_verified':True,
        'user_role':'authenticated'
    })
    result = currproc.authdb_conn.execute(upd)

    sel = select([
        users.c.user_id,
        users.c.is_active,
        users.c.user_role,
    ]).select_from(users).where(
        (users.c.email == payload['email'])
    )
    result = currproc.authdb_conn.execute(sel)
    rows = result.fetchone()
    result.close()

    if rows:

        LOGGER.info(
            '[%s] Email verification toggle request succeeded for '
            'user_id: %s, email: %s, role: %s, is_active: %s.' %
            (payload['reqid'],
             pii_hash(rows['user_id'], payload['pii_salt']),
             pii_hash(payload['email'], payload['pii_salt']),
             pii_hash(rows['user_role'], payload['pii_salt']),
             rows['is_active'])
        )

        return {
            'success':True,
            'user_id':rows['user_id'],
            'is_active':rows['is_active'],
            'user_role':rows['user_role'],
            'messages':["Email verification toggle request succeeded."]
        }

    else:

        LOGGER.error(
            '[%s] Email verification toggle request failed for '
            'email: %s.'
            'The database rows corresponding to '
            'the user could not be updated.' %
            (payload['reqid'],
             pii_hash(rows['user_id'], payload['pii_salt']))
        )

        return {
            'success':False,
            'user_id':None,
            'is_active':False,
            'user_role':'locked',
            'messages':["Email verification toggle request failed."]
        }


##############################
## FORGOT PASSWORD HANDLING ##
##############################

def send_forgotpass_verification_email(payload,
                                       raiseonfail=False,
                                       override_authdb_path=None):
    '''This actually sends the forgot password email.

    Parameters
    -----------

    payload : dict
        Keys expected in this dict from a client are:

        - email_address: str, the email address to send the email to
        - session_token: str, session token of the user being sent the email
        - server_name: str, the name of the frontend server
        - server_baseurl: str, the base URL of the frontend server
        - password_forgot_url: str, the URL fragment of the frontend
          forgot-password process initiation endpoint
        - verification_token: str, a verification token generated by frontend
        - verification_expiry: int, number of seconds after which the token
          expires

        In addition, the following keys must be provided by a wrapper function
        to set up the email server.

        - smtp_user
        - smtp_pass
        - smtp_server
        - smtp_port
        - smtp_sender

        Finally, the payload must also include the following keys (usually added
        in by a wrapping function):

        - reqid: int or str
        - pii_salt: str

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    Returns
    -------

    dict
        Returns a dict containing the user_id, email_address, and the
        forgotemail_sent_datetime value if email was sent successfully.

    '''

    for key in ('reqid','pii_salt'):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                'success':False,
                'user_id':None,
                'email_address':None,
                'forgotemail_sent_datetime':None,
                'messages':["Invalid forgot-password email request."],
            }

    for key in ('email_address',
                'session_token',
                'server_name',
                'server_baseurl',
                'password_forgot_url',
                'verification_token',
                'verification_expiry',
                'smtp_sender',
                'smtp_user',
                'smtp_pass',
                'smtp_server',
                'smtp_port'):

        if key not in payload:

            LOGGER.error(
                '[%s] Invalid forgot-password request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success':False,
                'user_id':None,
                'email_address':None,
                'forgotemail_sent_datetime':None,
                'messages':([
                    "Invalid forgot-password email request."
                ])
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
    user_sel = select([
        users.c.user_id,
        users.c.email,
        users.c.is_active,
        users.c.user_role,
        users.c.emailforgotpass_sent_datetime,
    ]).select_from(users).where(
        users.c.email == payload['email_address']
    ).where(
        users.c.is_active.is_(True)
    ).where(
        users.c.user_role != 'locked'
    ).where(
        users.c.user_role != 'anonymous'
    )
    user_results = currproc.authdb_conn.execute(user_sel)
    user_info = user_results.fetchone()
    user_results.close()

    if not user_info:

        LOGGER.error(
            "[%s] Forgot-password email request failed for "
            "email: %s, session_token: %s."
            "User matching the provided email address "
            "doesn't exist or is not active." %
            (payload['reqid'],
             pii_hash(payload['email_address'], payload['pii_salt']),
             pii_hash(payload['session_token'], payload['pii_salt']))
        )

        return {
            'success':False,
            'user_id':None,
            'email_address':None,
            'forgotemail_sent_datetime':None,
            'messages':([
                "Invalid password reset email request."
            ])
        }

    # check the last time we sent a forgot password email to this user
    if user_info['emailforgotpass_sent_datetime'] is not None:

        check_elapsed = (
            datetime.utcnow() - user_info['emailforgotpass_sent_datetime']
        ) > timedelta(hours=24)

        if check_elapsed:
            send_email = True
        else:
            send_email = False

    # if we've never sent a forgot-password email before, it's OK to send it
    else:
        send_email = True

    if not send_email:

        LOGGER.error(
            "[%s] Forgot-password email request failed for "
            "email: %s, session_token: %s."
            "A forgot-password email was already sent to "
            "this user within the last 24 hours." %
            (payload['reqid'],
             pii_hash(payload['email_address'], payload['pii_salt']),
             pii_hash(payload['session_token'], payload['pii_salt']))
        )

        return {
            'success':False,
            'user_id':None,
            'email_address':None,
            'forgotemail_sent_datetime':None,
            'messages':([
                "Invalid password reset email request."
            ])
        }

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
            "[%s] Forgot-password email request failed for "
            "email: %s, session_token: %s."
            "The session associated with the request is not valid." %
            (payload['reqid'],
             pii_hash(payload['email_address'], payload['pii_salt']),
             pii_hash(payload['session_token'], payload['pii_salt']))
        )

        return {
            'success':False,
            'user_id':None,
            'email_address':None,
            'verifyemail_sent_datetime':None,
            'messages':([
                "Invalid verification email request."
            ])
        }

    #
    # finally! we'll process the email sending request
    #

    # get the IP address and browser ID from the session
    ip_addr = session_info['session_info']['ip_address']
    browser = session_info['session_info']['user_agent']

    # TODO: we'll use geoip to get the location of the person who initiated the
    # request.

    # get the verification token's expiry datetime
    verification_expiry_td = timedelta(seconds=payload['verification_expiry'])
    verification_expiry_dt = (
        datetime.utcnow() + verification_expiry_td
    ).isoformat()

    # generate the email message
    msgtext = FORGOTPASS_VERIFICATION_EMAIL_TEMPLATE.format(
        server_baseurl=payload['server_baseurl'],
        password_forgot_url=payload['password_forgot_url'],
        server_name=payload['server_name'],
        verification_code=payload['verification_token'],
        verification_expiry='%s (UTC time)' % verification_expiry_dt,
        browser_identifier=browser.replace('_','.'),
        ip_address=ip_addr,
        user_email=payload['email_address'],
    )
    sender = payload['smtp_sender']
    recipients = [user_info['email']]
    subject = FORGOTPASS_VERIFICATION_EMAIL_SUBJECT.format(
        server_name=payload['server_name']
    )

    # send the email
    email_sent = authnzerver_send_email(
        sender,
        subject,
        msgtext,
        recipients,
        payload['smtp_server'],
        payload['smtp_user'],
        payload['smtp_pass'],
        payload['pii_salt'],
        port=payload['smtp_port']
    )

    if email_sent:

        emailforgotpass_sent_datetime = datetime.utcnow()

        # finally, we'll update the users table with the actual
        # verifyemail_sent_datetime if sending succeeded.
        upd = users.update(
        ).where(
            users.c.is_active.is_(True)
        ).where(
            users.c.email == payload['email_address']
        ).values({
            'emailforgotpass_sent_datetime': emailforgotpass_sent_datetime,
        })
        result = currproc.authdb_conn.execute(upd)
        result.close()

        LOGGER.info(
            '[%s] Forgot-password email request succeeded for '
            'email: %s, session_token: %s.'
            'Email sent on: %s UTC.' %
            (payload['reqid'],
             pii_hash(payload['email_address'], payload['pii_salt']),
             pii_hash(payload['session_token'], payload['pii_salt']),
             emailforgotpass_sent_datetime.isoformat())
        )

        return {
            'success':True,
            'user_id':user_info['user_id'],
            'email_address':user_info['email'],
            'forgotemail_sent_datetime':emailforgotpass_sent_datetime,
            'messages':([
                "Password reset request sent successfully to %s"
                % recipients
            ])
        }

    else:

        LOGGER.error(
            '[%s] Forgot-password email request failed for '
            'email: %s, session_token: %s.'
            'The email server could not send the '
            'email to the specified address.' %
            (payload['reqid'],
             pii_hash(payload['email_address'], payload['pii_salt']),
             pii_hash(payload['session_token'], payload['pii_salt']))
        )

        return {
            'success':False,
            'user_id':None,
            'email_address':None,
            'verifyemail_sent_datetime':None,
            'messages':([
                "Could not send email to %s for "
                "the user password reset request."
                % recipients
            ])
        }
