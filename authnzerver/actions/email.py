# -*- coding: utf-8 -*-
# actions_email.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""This contains functions to drive email-related auth actions.

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
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
import smtplib
import time
import re
import textwrap

from sqlalchemy import select

from .. import authdb
from .session import auth_session_exists
from ..permissions import pii_hash
from ..validators import validate_email_address

from .email_templates import (
    SIGNUP_VERIFICATION_EMAIL_SUBJECT,
    SIGNUP_VERIFICATION_EMAIL_TEMPLATE,
    FORGOTPASS_VERIFICATION_EMAIL_SUBJECT,
    FORGOTPASS_VERIFICATION_EMAIL_TEMPLATE
)


####################
## SENDING EMAILS ##
####################

def send_email(
        sender,
        subject,
        text,
        recipients,
        server,
        user,
        password,
        pii_salt,
        bcc=False,
        port=587
):
    """
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

    bcc : bool or list of str
        If True, will set the To: field in the email itself to
        "undisclosed-recipients" and send the email to all recipients such that
        none of them know who the message was sent to (effectively BCCs all the
        recipients). If this is set to a list of email addresses in RFC822
        format as strings, will only BCC those email addresses. If this is set
        to False, the To: field in the email itself will contain the addresses
        of all recipients.

    port : int
        The SMTP port to use when logging into the email server via SMTP.

    Returns
    -------

    sent_ok : bool
        Returns True if email sending succeeded. False otherwise.

    """

    # validate the sender's email address
    if '<' in sender and '>' in sender:
        sender_email = re.findall(r'<(\S+)>', sender)
        if not sender_email:
            LOGGER.error("Invalid sender email address. Can't send this email.")
            return False
        else:
            sender_email = sender_email[0]
    else:
        sender_email = sender

    valid_sender_email = validate_email_address(sender_email)
    if not valid_sender_email:
        LOGGER.error("Invalid sender email address. Can't send this email.")
        return False

    # remove all newlines from the subject, the sender's email address,
    # and all the recipient email address to prevent header injection attacks
    cleaned_sender = sender.replace('\n','')
    cleaned_subject = subject.replace('\n','')
    cleaned_recipients = [x.replace('\n','') for x in recipients]

    # validate the recipients' email addresses
    validated_recipients = []

    for recipient in cleaned_recipients:

        if '<' in recipient and '>' in recipient:
            recipient_email = re.findall(r'<(\S+)>', recipient)
            if recipient_email:
                recipient_email = recipient_email[0]
            else:
                LOGGER.warning(
                    "Recipient email address: %s is not valid, skipping..." %
                    pii_hash(recipient, pii_salt)
                )
                continue
        else:
            recipient_email = recipient

        recipient_email_valid = validate_email_address(recipient_email)

        if not recipient_email_valid:
            LOGGER.warning(
                "Recipient email address: %s not valid, skipping..." %
                pii_hash(recipient, pii_salt)
            )
        else:
            validated_recipients.append(recipient)

    if not validated_recipients:

        LOGGER.error("No valid recipients found for this email.")
        return False

    #
    # construct the message
    #

    msg = MIMEText(text)
    msg['From'] = cleaned_sender
    msg['To'] = ', '.join(recipients)
    msg['Message-Id'] = make_msgid()
    msg['Subject'] = cleaned_subject
    msg['Date'] = formatdate(time.time())
    msg['Sender'] = sender_email

    #
    # handle the BCC kwarg
    #

    # if everyone is to be BCCed, remove all the recipients from the "To:" field
    if bcc is True:

        msg['To'] = "undisclosed-recipients"

    # if there are specific people who need to be BCCed, clean their addresses,
    # validate them, and then add them to the validated_recipients list
    elif isinstance(bcc, (list, tuple)):

        for bcc_recipient in bcc:

            cleaned_bcc_recipient = bcc_recipient.replace('\n','')

            if '<' in cleaned_bcc_recipient and '>' in cleaned_bcc_recipient:
                bcc_recipient_email = re.findall(r'<(\S+)>',
                                                 cleaned_bcc_recipient)
                if bcc_recipient_email:
                    bcc_recipient_email = bcc_recipient_email[0]
                else:
                    LOGGER.warning(
                        "BCC email address: %s is not valid, skipping..." %
                        pii_hash(bcc_recipient, pii_salt)
                    )
                    continue

            else:
                bcc_recipient_email = cleaned_bcc_recipient

            bcc_email_valid = validate_email_address(bcc_recipient_email)
            if not bcc_email_valid:
                LOGGER.warning(
                    "BCC email address: %s not valid, skipping..." %
                    pii_hash(bcc_recipient, pii_salt)
                )
            else:
                validated_recipients.append(cleaned_bcc_recipient)

    #
    # finally, send the emails
    #

    # next, we'll try to login to the SMTP server
    try:

        server = smtplib.SMTP(server, port)
        server.ehlo()

        if server.has_extn('STARTTLS'):

            # try to send the email
            try:

                server.starttls()
                server.ehlo()

                if server.has_extn('AUTH'):
                    server.login(
                        user,
                        password
                    )

                server.sendmail(
                    cleaned_sender,
                    validated_recipients,
                    msg.as_string()
                )

                server.quit()
                return True

            # if it fails, bail out
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

            LOGGER.error('Email server: %s does not support STARTTLS, '
                         'refusing to send an insecure email.' % server)
            server.quit()
            return False

    except Exception as e:

        LOGGER.error(
            "Could not send the email to recipients: %s "
            "with subject: %s because of an exception: %r"
            % (', '.join([pii_hash(x, pii_salt) for x in recipients]),
               subject, e)
        )
        try:
            server.quit()
        except Exception:
            pass
        return False


def send_signup_verification_email(payload,
                                   raiseonfail=False,
                                   override_authdb_path=None,
                                   config=None):
    """Sends an account verification email.

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

        In addition, the following items must be provided by a wrapper function
        to set up the email server.

        - emailuser
        - emailpass
        - emailserver
        - emailport
        - emailsender

        These can be provided as part of the payload as dict keys or as
        attributes in the SimpleNamespace object passed in the config kwarg. The
        config object will be checked first, and the payload items will override
        it.

        Finally, the payload must also include the following keys (usually added
        in by a wrapping function):

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
        Returns a dict containing the user_id, email_address, and the
        emailverify_sent_datetime value if email was sent successfully.

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
                'user_id':None,
                'email_address':None,
                'emailverify_sent_datetime':None,
                'messages':["Invalid verify email request."],
            }

    for key in ('email_address',
                'session_token',
                'server_name',
                'server_baseurl',
                'account_verify_url',
                'verification_token',
                'verification_expiry',
                'created_info'):

        if key not in payload:

            LOGGER.error(
                '[%s] Invalid verify email request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success':False,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'user_id':None,
                'email_address':None,
                'emailverify_sent_datetime':None,
                'messages':([
                    "Invalid verify email request."
                ])
            }

    # now check for the SMTP server config items in the payload or in config
    if config is not None:

        emailsender = getattr(config, "emailsender", None)
        emailuser = getattr(config, "emailuser", None)
        emailpass = getattr(config, "emailpass", None)
        emailserver = getattr(config, "emailserver", None)
        emailport = getattr(config, "emailport", None)

    else:
        emailsender, emailuser, emailpass, emailserver, emailport = (
            None, None, None, None, None
        )

    # override with payload values
    if 'emailsender' in payload:
        emailsender = payload['emailsender']
    if 'emailuser' in payload:
        emailuser = payload['emailuser']
    if 'emailpass' in payload:
        emailpass = payload['emailpass']
    if 'emailserver' in payload:
        emailserver = payload['emailserver']
    if 'emailport' in payload:
        emailport = payload['emailport']

    if (emailsender is None or
        emailserver is None or
        emailport is None):

        LOGGER.error(
            "[%s] Invalid email server settings "
            "provided. Can't send an email." %
            payload['reqid']
        )
        return {
            'success':False,
            'failure_reason':(
                "invalid request: missing 'emailsender', "
                "'emailserver', or 'emailport' in request"
            ),
            'user_id':None,
            'email_address':None,
            'emailverify_sent_datetime':None,
            'messages':([
                "Invalid email server settings provided. Can't send an email."
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
            'failure_reason':(
                "not allowed to send verification email to target user, "
                "send_verification = False"
            ),
            'user_id':None,
            'email_address':None,
            'emailverify_sent_datetime':None,
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
            'failure_reason':(
                "target user for verification email does not exist"
            ),
            'user_id':None,
            'email_address':None,
            'emailverify_sent_datetime':None,
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
            'failure_reason':(
                "target user for verification email already active and verified"
            ),
            'user_id':None,
            'email_address':None,
            'emailverify_sent_datetime':None,
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
            'failure_reason':(
                "invalid session for requesting a verification email"
            ),
            'user_id':None,
            'email_address':None,
            'emailverify_sent_datetime':None,
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

    # format the verification token and wrap it to 70 chars per line because now
    # it's a bit too long for one line. we'll use a textbox on the verification
    # page to let people to paste this in
    if isinstance(payload['verification_token'], bytes):
        payload['verification_token'] = (
            payload['verification_token'].decode('utf-8')
        )

    formatted_verification_token = '\n'.join(
        textwrap.wrap(payload['verification_token'])
    )

    # generate the email message
    msgtext = SIGNUP_VERIFICATION_EMAIL_TEMPLATE.format(
        server_baseurl=payload['server_baseurl'],
        server_name=payload['server_name'],
        account_verify_url=payload['account_verify_url'],
        verification_code=formatted_verification_token,
        verification_expiry='%s (UTC time)' % verification_expiry_dt,
        browser_identifier=browser.replace('_','.'),
        ip_address=ip_addr,
        user_email=payload['email_address'],
    )
    recipients = [user_info['email']]
    subject = SIGNUP_VERIFICATION_EMAIL_SUBJECT.format(
        server_name=payload['server_name']
    )

    # send the email
    email_sent = send_email(
        emailsender,
        subject,
        msgtext,
        recipients,
        emailserver,
        emailuser,
        emailpass,
        payload['pii_salt'],
        port=emailport
    )

    if email_sent:

        emailverify_sent_datetime = datetime.utcnow()

        # finally, we'll update the users table with the actual
        # emailverify_sent_datetime if sending succeeded.
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
            'user_id: %s, email: %s, session_token: %s. '
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
            'emailverify_sent_datetime':emailverify_sent_datetime,
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
            'failure_reason':(
                "verification email could not be sent "
                "because of an email server problem"
            ),
            'user_id':None,
            'email_address':None,
            'emailverify_sent_datetime':None,
            'messages':([
                "Could not send email for the verify email request."
            ])
        }


def set_user_emailaddr_verified(payload,
                                raiseonfail=False,
                                override_authdb_path=None,
                                config=None):
    """Sets the verification status of the email address of the user.

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

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    dict
        Returns a dict containing the user_id, is_active, and user_role values
        if verification status is successfully set.

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
            'failure_reason':(
                "invalid request: missing '%s' in request" % 'email'
            ),
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
    currproc.authdb_conn.execute(upd)

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
            'failure_reason':(
                "could not update user verified status in DB"
            ),
            'user_id':None,
            'is_active':False,
            'user_role':'locked',
            'messages':["Email verification toggle request failed."]
        }


def set_user_email_sent(payload,
                        raiseonfail=False,
                        override_authdb_path=None,
                        config=None):
    """Sets the verify/forgot email sent flag & time for the newly created user.

    This is useful when some other way of emailing the user to verify their sign
    up or their password forgot request is used, external to authnzerver. Use
    this function to let the authnzerver know that an email has been sent so it
    knows the correct move if someone tries to sign up for an account with the
    same email address later.

    Parameters
    ----------

    payload : dict
        This is a dict with the following key:

        - email, str
        - email_type, str: one of "signup", "forgotpass"

        Finally, the payload must also include the following keys (usually added
        in by a wrapping function):

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
        Returns a dict containing the email address and
        email*_sent_datetime values if the sent-email notification was
        successfully set.

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
                'messages':["Invalid email sent notification request."],
            }

    for key in ('email','email_type'):
        if key not in payload:

            LOGGER.error(
                '[%s] Invalid email sent notification request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success':False,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'messages':["Invalid email sent notification request."]
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

    email_sent_datetime = datetime.utcnow()

    if payload["email_type"] == "signup":
        update_col = "emailverify_sent_datetime"
    elif payload["email_type"] == "forgotpass":
        update_col = "emailforgotpass_sent_datetime"
    else:
        LOGGER.error(
            '[%s] Invalid email sent notification request, '
            'incorrect email_type.' % payload['reqid']
        )
        return {
            'success':False,
            'failure_reason':(
                "invalid request: invalid email_type requested"
            ),
            'messages':["Invalid email sent notification request."]
        }

    # update the table for this user
    upd = users.update(
    ).where(
        users.c.email == payload['email']
    ).values({
        update_col:email_sent_datetime,
    })
    currproc.authdb_conn.execute(upd)

    sel = select([
        users.c.user_id,
        users.c.is_active,
        users.c.user_role,
        users.c.email,
        users.c.emailverify_sent_datetime,
        users.c.emailforgotpass_sent_datetime,
    ]).select_from(users).where(
        (users.c.email == payload['email'])
    )
    result = currproc.authdb_conn.execute(sel)
    rows = result.fetchone()
    result.close()

    if rows:

        LOGGER.info(
            '[%s] Email sent notification request succeeded for '
            'user_id: %s, email: %s, role: %s, is_active: %s.' %
            (payload['reqid'],
             pii_hash(rows['user_id'], payload['pii_salt']),
             pii_hash(payload['email'], payload['pii_salt']),
             pii_hash(rows['user_role'], payload['pii_salt']),
             rows['is_active'])
        )

        return {
            'success':True,
            'email':rows['email'],
            'emailverify_sent_datetime':rows['emailverify_sent_datetime'],
            'emailforgotpass_sent_datetime':(
                rows['emailforgotpass_sent_datetime']
            ),
            'user_id':rows['user_id'],
            'is_active':rows['is_active'],
            'user_role':rows['user_role'],
            'messages':["Email sent notification request succeeded."]
        }

    else:

        LOGGER.error(
            '[%s] Email sent notification request failed for '
            'email: %s.'
            'The database rows corresponding to '
            'the user could not be updated.' %
            (payload['reqid'],
             pii_hash(rows['user_id'], payload['pii_salt']))
        )

        return {
            'success':False,
            'failure_reason':(
                "could not update the email sent status in DB"
            ),
            'messages':["Email sent notification request failed."]
        }


##############################
## FORGOT PASSWORD HANDLING ##
##############################

def send_forgotpass_verification_email(payload,
                                       raiseonfail=False,
                                       override_authdb_path=None,
                                       config=None):
    """This actually sends the forgot password email.

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

        In addition, the following items must be provided by a wrapper function
        to set up the email server.

        - emailuser
        - emailpass
        - emailserver
        - emailport
        - emailsender

        These can be provided as part of the payload as dict keys or as
        attributes in the SimpleNamespace object passed in the config kwarg. The
        config object will be checked first, and the payload items will override
        it.

        Finally, the payload must also include the following keys (usually added
        in by a wrapping function):

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
        Returns a dict containing the user_id, email_address, and the
        emailforgotpass_sent_datetime value if email was sent successfully.

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
                'user_id':None,
                'email_address':None,
                'emailforgotpass_sent_datetime':None,
                'messages':["Invalid forgot-password email request."],
            }

    for key in ('email_address',
                'session_token',
                'server_name',
                'server_baseurl',
                'password_forgot_url',
                'verification_token',
                'verification_expiry'):

        if key not in payload:

            LOGGER.error(
                '[%s] Invalid forgot-password request, missing %s.' %
                (payload['reqid'], key)
            )

            return {
                'success':False,
                'failure_reason':(
                    "invalid request: missing '%s' in request" % key
                ),
                'user_id':None,
                'email_address':None,
                'emailforgotpass_sent_datetime':None,
                'messages':([
                    "Invalid forgot-password email request."
                ])
            }

    # now check for the SMTP server config items in the payload or in config
    if config is not None:
        emailsender = getattr(config, "emailsender", None)
        emailuser = getattr(config, "emailuser", None)
        emailpass = getattr(config, "emailpass", None)
        emailserver = getattr(config, "emailserver", None)
        emailport = getattr(config, "emailport", None)
    else:
        emailsender, emailuser, emailpass, emailserver, emailport = (
            None, None, None, None, None
        )

    # override with payload values
    if 'emailsender' in payload:
        emailsender = payload['emailsender']
    if 'emailuser' in payload:
        emailuser = payload['emailuser']
    if 'emailpass' in payload:
        emailpass = payload['emailpass']
    if 'emailserver' in payload:
        emailserver = payload['emailserver']
    if 'emailport' in payload:
        emailport = payload['emailport']

    if (emailsender is None or
        emailserver is None or
        emailport is None):

        LOGGER.error(
            "[%s] Invalid email server settings "
            "provided. Can't send an email." %
            payload['reqid']
        )
        return {
            'success':False,
            'failure_reason':(
                "missing 'emailserver', 'emailsender', 'emailport' in request"
            ),
            'user_id':None,
            'email_address':None,
            'emailforgotpass_sent_datetime':None,
            'messages':([
                "Invalid email server settings provided. Can't send an email."
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
            'failure_reason':(
                "invalid user for forgot-pass email request"
            ),
            'user_id':None,
            'email_address':None,
            'emailforgotpass_sent_datetime':None,
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
            send_forgotpass_email = True
        else:
            send_forgotpass_email = False

    # if we've never sent a forgot-password email before, it's OK to send it
    else:
        send_forgotpass_email = True

    if not send_forgotpass_email:

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
            'failure_reason':(
                "forgot-pass verification email sent less than 24 hours ago"
            ),
            'user_id':None,
            'email_address':None,
            'emailforgotpass_sent_datetime':None,
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
            'failure_reason':(
                "invalid session for forgot-pass request"
            ),
            'user_id':None,
            'email_address':None,
            'emailforgotpass_sent_datetime':None,
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

    # format the verification token and wrap it to 70 chars per line because now
    # it's a bit too long for one line. we'll use a textbox on the verification
    # page to let people to paste this in
    if isinstance(payload['verification_token'], bytes):
        payload['verification_token'] = (
            payload['verification_token'].decode('utf-8')
        )

    formatted_verification_token = '\n'.join(
        textwrap.wrap(payload['verification_token'])
    )

    # generate the email message
    msgtext = FORGOTPASS_VERIFICATION_EMAIL_TEMPLATE.format(
        server_baseurl=payload['server_baseurl'],
        password_forgot_url=payload['password_forgot_url'],
        server_name=payload['server_name'],
        verification_code=formatted_verification_token,
        verification_expiry='%s (UTC time)' % verification_expiry_dt,
        browser_identifier=browser.replace('_','.'),
        ip_address=ip_addr,
        user_email=payload['email_address'],
    )
    recipients = [user_info['email']]
    subject = FORGOTPASS_VERIFICATION_EMAIL_SUBJECT.format(
        server_name=payload['server_name']
    )

    # send the email
    email_sent = send_email(
        emailsender,
        subject,
        msgtext,
        recipients,
        emailserver,
        emailuser,
        emailpass,
        payload['pii_salt'],
        port=emailport
    )

    if email_sent:

        emailforgotpass_sent_datetime = datetime.utcnow()

        # finally, we'll update the users table with the actual
        # emailforgotpass_sent_datetime if sending succeeded.
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
            'email: %s, session_token: %s. '
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
            'emailforgotpass_sent_datetime':emailforgotpass_sent_datetime,
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
            'failure_reason':(
                "forgot-pass verification email "
                "could not be sent because email server issue"
            ),
            'user_id':None,
            'email_address':None,
            'emailforgotpass_sent_datetime':None,
            'messages':([
                "Could not send email to %s for "
                "the user password reset request."
                % recipients
            ])
        }
