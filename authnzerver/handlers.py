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
from functools import partial


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

import tornado.web
import tornado.ioloop

from . import actions
from .messaging import encrypt_message, decrypt_message
from .permissions import pii_hash


#########################
## REQ/RESP VALIDATION ##
#########################

def check_header_host(allowed_hosts_regex, header_host):
    '''
    This checks if the header_host item is in the allowed_hosts.

    '''
    rematch = allowed_hosts_regex.findall(header_host)
    if rematch is not None:
        return True
    else:
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
    'user-passcheck-nosession':actions.auth_password_check_nosession,
    # user actions
    'user-new':actions.create_new_user,
    'user-changepass':actions.change_user_password,
    'user-delete':actions.delete_user,
    'user-list':actions.list_users,
    'user-lookup-email':actions.get_user_by_email,
    'user-lookup-match':actions.lookup_users,
    'user-edit':actions.edit_user,
    'user-resetpass':actions.verify_password_reset,
    'user-lock':actions.toggle_user_lock,
    # email actions
    'user-sendemail-signup':actions.send_signup_verification_email,
    'user-sendemail-forgotpass':actions.send_forgotpass_verification_email,
    'user-set-emailverified':actions.set_user_emailaddr_verified,
    'user-set-emailsent':actions.set_user_email_sent,
    # apikey actions
    'apikey-new':actions.issue_apikey,
    'apikey-verify':actions.verify_apikey,
    'apikey-revoke':actions.revoke_apikey,
    'apikey-new-nosession':actions.issue_apikey_nosession,
    'apikey-verify-nosession':actions.verify_apikey_nosession,
    'apikey-refresh-nosession':actions.refresh_apikey_nosession,
    'apikey-revoke-nosession':actions.revoke_apikey_nosession,
    'apikey-revokeall-nosession':actions.revoke_all_apikeys_nosession,
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
                   cacheobj,
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
        self.cacheobj = cacheobj
        self.failed_passchecks = failed_passchecks

        self.allowed_hosts_regex = config.allowed_hosts_regex
        self.ratelimits = config.ratelimits

    def ratelimit_request(self, reqid, request_type, request_body):
        """
        This rate-limits the request based on the request type and the
        set ratelimits passed in the config object.

        """

        # increment the global request each time
        all_reqcount = self.cacheobj.increment(
            "all_request_count",
        )

        # check the global request rate
        if all_reqcount > self.ratelimits['burst']:

            all_reqrate, all_reqcount, all_req_t0, all_req_tnow = (
                self.cacheobj.getrate(
                    "all_request_count",
                    60.0,
                )
            )

            if all_reqrate > self.ratelimits['all']:
                LOGGER.error(
                    "[%s] request '%s' is being rate-limited. "
                    "Cache token: 'all_request_count', count: %s. "
                    "Rate: %.3f > limit specified for '%s': %s"
                    % (reqid,
                       request_type,
                       all_reqcount,
                       all_reqrate,
                       'all',
                       self.ratelimits['all'])
                )
                raise tornado.web.HTTPError(status_code=429)

        # check the user- prefixed request
        if request_type.startswith("user-"):

            user_cache_token = (
                request_body.get("email", None) or
                request_body.get("user_id", None) or
                request_body.get("session_token", None) or
                request_body.get("ip_address", None) or
                request_body.get("email_address", None)
            )

            # drop all requests that try to get around rate-limiting
            if not user_cache_token:
                LOGGER.error(
                    "[%s] request: '%s' is missing a payload value "
                    "needed to calculate rate, dropping this request."
                    % (self.reqid, request_type)
                )
                raise tornado.web.HTTPError(status_code=400)

            user_cache_key = f"user-request-{user_cache_token}"

            user_reqcount = self.cacheobj.increment(
                user_cache_key,
            )

            if user_reqcount > self.ratelimits["user"]:

                user_reqrate, user_reqcount, user_req_t0, user_req_tnow = (
                    self.cacheobj.getrate(
                        user_cache_key,
                        60.0,
                    )
                )

                if user_reqrate > self.ratelimits['user']:
                    LOGGER.error(
                        "[%s] request '%s' is being rate-limited. "
                        "Cache token: '%s', count: %s. "
                        "Rate: %.3f > limit specified for '%s': %s"
                        % (reqid,
                           request_type,
                           pii_hash(user_cache_key, self.pii_salt),
                           user_reqcount,
                           user_reqrate,
                           'user',
                           self.ratelimits['user'])
                    )
                    raise tornado.web.HTTPError(status_code=429)

        # check the session- prefixed request
        if request_type.startswith("session-"):

            session_cache_token = (
                request_body.get("user_id", None) or
                request_body.get("session_token", None) or
                request_body.get("ip_address", None)
            )
            if not session_cache_token:
                LOGGER.error(
                    "[%s] request: '%s' is missing a payload value "
                    "needed to calculate rate, dropping this request."
                    % (self.reqid, request_type)
                )
                raise tornado.web.HTTPError(status_code=400)

            session_cache_key = f"session-request-{session_cache_token}"

            session_reqcount = self.cacheobj.increment(
                session_cache_key,
            )

            if session_reqcount > self.ratelimits["session"]:

                (session_reqrate,
                 session_reqcount,
                 session_req_t0,
                 session_req_tnow) = (
                    self.cacheobj.getrate(
                        session_cache_key,
                        60.0,
                    )
                )

                if session_reqrate > self.ratelimits['session']:
                    LOGGER.error(
                        "[%s] request '%s' is being rate-limited. "
                        "Cache token: '%s', count: %s. "
                        "Rate: %.3f > limit specified for '%s': %s"
                        % (reqid,
                           request_type,
                           pii_hash(session_cache_key, self.pii_salt),
                           session_reqcount,
                           session_reqrate,
                           'session',
                           self.ratelimits['session'])
                    )
                    raise tornado.web.HTTPError(status_code=429)

        # check the apikey- prefixed request
        if request_type.startswith("apikey-"):

            # handle API key issuance
            apikey_cache_token = (
                request_body.get("ip_address", None)
            )
            # handle all other API key actions
            if not apikey_cache_token and request_body.get("apikey_dict"):
                apikey_cache_token = request_body["apikey_dict"].get("user_id",
                                                                     None)

            if not apikey_cache_token:
                LOGGER.error(
                    "[%s] request: '%s' is missing a payload value "
                    "needed to calculate rate, dropping this request."
                    % (self.reqid, request_type)
                )
                raise tornado.web.HTTPError(status_code=400)

            apikey_cache_key = f"apikey-request-{apikey_cache_token}"

            apikey_reqcount = self.cacheobj.increment(
                apikey_cache_key,
            )

            if apikey_reqcount > self.ratelimits["apikey"]:

                (apikey_reqrate,
                 apikey_reqcount,
                 apikey_req_t0,
                 apikey_req_tnow) = (
                    self.cacheobj.getrate(
                        apikey_cache_key,
                        60.0,
                    )
                )

                if apikey_reqrate > self.ratelimits['apikey']:
                    LOGGER.error(
                        "[%s] request '%s' is being rate-limited. "
                        "Cache token: '%s', count: %s. "
                        "Rate: %.3f > limit specified for '%s': %s"
                        % (reqid,
                           request_type,
                           pii_hash(apikey_cache_key, self.pii_salt),
                           apikey_reqcount,
                           apikey_reqrate,
                           'apikey',
                           self.ratelimits['apikey'])
                    )
                    raise tornado.web.HTTPError(status_code=429)

    async def send_response(self, response, reqid):
        """
        This handles the response generation.

        """

        response_dict = {"success": response['success'],
                         "response":response,
                         "messages": response['messages'],
                         "reqid":reqid}

        # add the failure reason as a top level item in the response dict
        # if the action failed
        if not response['success'] and 'failure_reason' in response:
            response_dict['failure_reason'] = response['failure_reason']

        encrypted_base64 = encrypt_message(
            response_dict,
            self.fernet_secret
        )

        self.set_header('content-type','text/plain; charset=UTF-8')
        self.write(encrypted_base64)
        self.finish()

    def write_error(self, status_code, **kwargs):
        """
        This writes the error as a response.

        """

        self.set_header('content-type','text/plain; charset=UTF-8')
        if status_code == 400:
            self.write(f"HTTP {status_code}: Could not service this request "
                       f"because of invalid request parameters.")
        elif status_code == 401:
            self.write(f"HTTP {status_code}: Could not service this request "
                       f"because of invalid request authentication token or "
                       f"violation of host restriction.")
        elif status_code == 429:
            self.set_header("Retry-After", "180")
            self.write(f"HTTP {status_code}: Could not service this request "
                       f"because the set rate limit has been exceeded.")
        else:
            self.write(f"HTTP {status_code}: Could not service this request.")

        if not self._finished:
            self.finish()

    async def post(self):
        '''
        Handles the incoming POST request.

        '''

        # check the host
        ipcheck = check_header_host(self.allowed_hosts_regex,
                                    self.request.host)
        if not ipcheck:
            LOGGER.warning(
                "Invalid host in request header: '%s' "
                "did not match the allowed hosts regex: '%s'. Request dropped."
                % (self.request.host, self.allowed_hosts_regex)
            )
            raise tornado.web.HTTPError(status_code=401)

        # decrypt the request
        payload = decrypt_message(self.request.body, self.fernet_secret)
        if not payload:
            raise tornado.web.HTTPError(status_code=401)

        # ignore all requests for echo to this handler
        if payload['request'] == 'echo':
            LOGGER.error("This handler can't echo things.")
            raise tornado.web.HTTPError(status_code=400)

        # get the request ID
        reqid = payload.get('reqid')
        if reqid is None:
            raise ValueError("No request ID provided. "
                             "Ignoring this request.")

        # rate limit the request
        if self.ratelimits:
            self.ratelimit_request(reqid, payload['request'], payload['body'])

        # if we successfully got past host, decryption, rate-limit validation,
        # then process the request
        try:

            #
            # dispatch the action handler function
            #

            # inject the request ID into the body of the request so the backend
            # function can report on it
            payload['body']['reqid'] = reqid

            # inject the PII salt into the body of the request as well
            payload['body']['pii_salt'] = self.pii_salt

            # inject the config object into the backend function call
            # this passes along any secrets or settings from environ
            # directly to those functions
            backend_func = partial(
                request_functions[payload['request']],
                payload['body'],
                config=self.config
            )

            # run the function associated with the request type
            loop = tornado.ioloop.IOLoop.current()
            response = await loop.run_in_executor(
                self.executor,
                backend_func,
            )

            #
            # see if the request was one that requires an email and password. in
            # this case, we'll apply backoff to slow down repeated failed
            # passwords
            #
            passcheck_requests = {'user-login', 'user-passcheck-nosession'}

            if (payload['request'] in passcheck_requests and
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
            elif (payload['request'] in passcheck_requests and
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
            # form and send the the response
            #
            await self.send_response(response, reqid)

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

        backend_func = partial(
            actions.get_user_by_email,
            {'email':payload['body']['email'],
             'reqid':payload['body']['reqid'],
             'pii_salt':payload['body']['pii_salt']},
            config=self.config
        )

        user_info = await loop.run_in_executor(
            self.executor,
            backend_func
        )

        if not user_info['success']:

            LOGGER.error(
                "Could not look up the user ID for email: %s to lock "
                "their account after repeated failed login attempts." %
                pii_hash(payload['body']['email'], payload['body']['pii_salt'])
            )

        else:

            # attempt to lock the user using actions.internal_toggle_user_lock

            backend_func = partial(
                actions.internal_toggle_user_lock,
                {'target_userid':user_info['user_info']['user_id'],
                 'action':'lock',
                 'reqid':payload['body']['reqid'],
                 'pii_salt':payload['body']['pii_salt']},
                config=self.config
            )

            locked_info = await loop.run_in_executor(
                self.executor,
                backend_func
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

        backend_func = partial(
            actions.internal_toggle_user_lock,
            {'target_userid':user_id,
             'action':'unlock',
             'reqid':reqid,
             'pii_salt':pii_salt},
            config=self.config
        )

        locked_info = await loop.run_in_executor(
            self.executor,
            backend_func
        )
        return locked_info
