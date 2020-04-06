# -*- coding: utf-8 -*-
# handlers.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''These are handlers for the authnzerver.

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

import json
from datetime import datetime, timedelta
import asyncio


class FrontendEncoder(json.JSONEncoder):

    def default(self, obj):

        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, bytes):
            return obj.decode()
        elif isinstance(obj, complex):
            return (obj.real, obj.imag)
        else:
            return json.JSONEncoder.default(self, obj)


# this replaces the default encoder and makes it so Tornado will do the right
# thing when it converts dicts to JSON when a
# tornado.web.RequestHandler.write(dict) is called.
json._default_encoder = FrontendEncoder()

import ipaddress
import tornado.web
import tornado.ioloop

from . import actions
from .messaging import encrypt_message, decrypt_message
from .permissions import pii_hash


#########################
## REQ/RESP VALIDATION ##
#########################

def check_host(remote_ip):
    '''
    This just returns False if the remote_ip != 127.0.0.1

    '''
    try:
        return (ipaddress.ip_address(remote_ip) ==
                ipaddress.ip_address('127.0.0.1'))
    except ValueError:
        return False


#####################################
## AUTH REQUEST HANDLING FUNCTIONS ##
#####################################

#
# this maps request types -> request functions to execute
#
request_functions = {
    # session actions
    'session-new':actions.auth_session_new,
    'session-exists':actions.auth_session_exists,
    'session-delete':actions.auth_session_delete,
    'session-delete-userid':actions.auth_delete_sessions_userid,
    'session-setinfo':actions.auth_session_set_extrainfo,
    'user-login':actions.auth_user_login,
    'user-logout':actions.auth_user_logout,
    'user-passcheck': actions.auth_password_check,
    # user actions
    'user-new':actions.create_new_user,
    'user-changepass':actions.change_user_password,
    'user-delete':actions.delete_user,
    'user-list':actions.list_users,
    'user-edit':actions.edit_user,
    'user-resetpass':actions.verify_password_reset,
    'user-lock':actions.toggle_user_lock,
    # email actions
    'user-signup-sendemail':actions.send_signup_verification_email,
    'user-verify-emailaddr':actions.verify_user_email_address,
    'user-forgotpass-sendemail':actions.send_forgotpass_verification_email,
    # apikey actions
    'apikey-new':actions.issue_new_apikey,
    'apikey-verify':actions.verify_apikey,
    # access and limit check actions
    'user-check-access': actions.check_user_access,
    'user-check-limit': actions.check_user_limit,
}


#######################
## MAIN AUTH HANDLER ##
#######################

class AuthHandler(tornado.web.RequestHandler):
    '''
    This handles the actual auth requests.

    '''

    def initialize(self,
                   config,
                   executor,
                   failed_passchecks):
        '''
        This sets up stuff.

        '''

        self.config = config
        self.authdb = self.config.authdb
        self.fernet_secret = self.config.secret
        self.pii_salt = self.config.piisalt

        self.emailsender = self.config.emailsender
        self.emailserver = self.config.emailserver
        self.emailport = self.config.emailport
        self.emailuser = self.config.emailuser
        self.emailpass = self.config.emailpass

        self.executor = executor
        self.failed_passchecks = failed_passchecks

    async def post(self):
        '''
        Handles the incoming POST request.

        '''

        ipcheck = check_host(self.request.remote_ip)

        if not ipcheck:
            raise tornado.web.HTTPError(status_code=400)

        payload = decrypt_message(self.request.body, self.fernet_secret)
        if not payload:
            raise tornado.web.HTTPError(status_code=401)

        if payload['request'] == 'echo':
            LOGGER.error("This handler can't echo things.")
            raise tornado.web.HTTPError(status_code=400)

        # if we successfully got past host and decryption validation, then
        # process the request
        try:

            # get the request ID
            # this is an integer
            reqid = payload.get('reqid')
            if reqid is None:
                raise ValueError("No request ID provided. "
                                 "Ignoring this request.")

            #
            # dispatch the action handler function
            #

            # inject the request ID into the body of the request so the backend
            # function can report on it
            payload['body']['reqid'] = reqid

            # inject the PII salt into the body of the request as well
            payload['body']['pii_salt'] = self.pii_salt

            # inject the email settings into the body if an email function is
            # called
            if 'sendemail' in payload['request']:
                payload['body']['smtp_sender'] = self.emailsender
                payload['body']['smtp_user'] = self.emailuser
                payload['body']['smtp_pass'] = self.emailpass
                payload['body']['smtp_server'] = self.emailserver
                payload['smtp_port'] = self.emailport

            # run the function associated with the request type
            loop = tornado.ioloop.IOLoop.current()
            response = await loop.run_in_executor(
                self.executor,
                request_functions[payload['request']],
                payload['body']
            )

            #
            # see if the request was user-login. in this case,
            # we'll apply backoff to slow down repeated failed passwords
            #
            if (payload['request'] == 'user-login' and
                response['success'] is False):

                failure_status, failure_count, failure_wait = (
                    await self.handle_failed_logins(payload)
                )

                # if the user is locked for repeated login failures, handle that
                if failure_status == 'locked':
                    response = await self.lockuser_repeated_login_failures(
                        payload,
                        unlock_after_seconds=self.config.userlocktime
                    )
                elif failure_status == 'wait':
                    LOGGER.warning(
                        "[%s] User with email: %s is being rate-limited "
                        "after %s failed login attempts. "
                        "Current wait time: %.1f seconds." %
                        (reqid,
                         pii_hash(payload['body']['email'], self.pii_salt),
                         failure_count,
                         failure_wait)
                    )

            # reset the failed counter to zero for each successful attempt
            elif (payload['request'] == 'user-login' and
                  response['success'] is True):

                self.failed_passchecks.pop(
                    payload['body']['email'],
                    None
                )

            #
            # trim the failed_passchecks dict
            #
            if len(self.failed_passchecks) > 1000:
                self.failed_passchecks.pop(
                    self.failed_passchecks.keys()[0]
                )

            #
            # form the response
            #

            response_dict = {"success": response['success'],
                             "reqid": reqid,
                             "response":response,
                             "messages": response['messages']}

            encrypted_base64 = encrypt_message(
                response_dict,
                self.fernet_secret
            )

            self.set_header('content-type','text/plain; charset=UTF-8')
            self.write(encrypted_base64)
            self.finish()

        except Exception:

            LOGGER.exception('Failed to understand request.')
            raise tornado.web.HTTPError(status_code=400)

    async def handle_failed_logins(self, payload):
        '''
        This handles failed logins.

        - Adds increasing wait times to successive logins if they keep failing.
        - If the number of failed logins exceeds 10, the account is locked for
          one hour, and an unlock action is scheduled on the ioloop.

        '''

        # increment the failure counter and return it
        if (payload['body']['email'] in self.failed_passchecks):
            self.failed_passchecks[payload['body']['email']] += 1
        else:
            self.failed_passchecks[payload['body']['email']] = 1

        failed_pass_count = self.failed_passchecks[
            payload['body']['email']
        ]

        if 0 < failed_pass_count <= self.config.userlocktries:
            # asyncio.sleep for an exponentially increasing period of time
            # until 40.0 seconds ~= 10 tries
            wait_time = 1.5**(failed_pass_count - 1.0)
            if wait_time > 40.0:
                wait_time = 40.0
            await asyncio.sleep(wait_time)
            return ('wait', failed_pass_count, wait_time)

        elif failed_pass_count > self.config.userlocktries:
            return ('locked', failed_pass_count, 0.0)

        else:
            return ('ok', failed_pass_count, 0.0)

    async def lockuser_repeated_login_failures(self,
                                               payload,
                                               unlock_after_seconds=3600):
        '''
        This locks the user account. Also schedules an unlock action for later.

        '''

        # look up the user ID using the email address
        loop = tornado.ioloop.IOLoop.current()
        user_info = await loop.run_in_executor(
            self.executor,
            actions.get_user_by_email,
            {'email':payload['body']['email'],
             'reqid':payload['body']['reqid'],
             'pii_salt':payload['body']['pii_salt']}
        )

        if not user_info['success']:

            LOGGER.error(
                "Could not look up the user ID for email: %s to lock "
                "their account after repeated failed login attempts." %
                pii_hash(payload['body']['email'], payload['body']['pii_salt'])
            )

        else:

            # attempt to lock the user using actions.internal_toggle_user_lock
            locked_info = await loop.run_in_executor(
                self.executor,
                actions.internal_toggle_user_lock,
                {'target_userid':user_info['user_info']['user_id'],
                 'action':'lock',
                 'reqid':payload['body']['reqid'],
                 'pii_salt':payload['body']['pii_salt']}
            )

            if locked_info['success']:

                unlock_after_dt = (datetime.utcnow() +
                                   timedelta(seconds=unlock_after_seconds))

                # schedule the unlock
                loop.call_later(
                    unlock_after_seconds,
                    self.scheduled_user_unlock,
                    user_info['user_info']['user_id'],
                    payload['body']['reqid'],
                    payload['body']['pii_salt']
                )

                LOGGER.warning(
                    "Locked the account for user ID: %s, "
                    "email: %s after repeated "
                    "failed login attempts. "
                    "Unlock scheduled for: %sZ" %
                    (pii_hash(user_info['user_info']['user_id'],
                              payload['body']['pii_salt']),
                     pii_hash(payload['body']['email'],
                              payload['body']['pii_salt']),
                     unlock_after_dt)
                )

        # we'll return a failure here as the response no matter what happens
        # above to deny the login
        return {
            "success": False,
            "user_id":None,
            "messages":[
                "Your user account has been locked "
                "after repeated login failures. "
                "Try again in an hour or "
                "contact the server admins."
            ]
        }

    async def scheduled_user_unlock(self, user_id, reqid, pii_salt):
        '''
        This function is scheduled on the ioloop to unlock the specified user.

        '''

        LOGGER.warning(
            "[%s] Unlocked the account for user ID: %s after "
            "login-failure timeout expired." %
            (reqid, pii_hash(user_id, pii_salt))
        )

        loop = tornado.ioloop.IOLoop.current()
        locked_info = await loop.run_in_executor(
            self.executor,
            actions.internal_toggle_user_lock,
            {'target_userid':user_id,
             'action':'unlock',
             'reqid':reqid,
             'pii_salt':pii_salt}
        )
        return locked_info
