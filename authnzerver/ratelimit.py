# -*- coding: utf-8 -*-
# ratelimit.py - Waqas Bhatti (waqas.afzal.bhatti@gmail.com) - Jul 2020
# License: MIT - see the LICENSE file for the full text.

"""This module contains RequestHandler mixins that do rate-limiting for the
authnzerver's own API, handle throttling of incorrect password attempts, and
do user locking/unlocking for repeated password check failures.

None of these will work without bits already defined in handlers.AuthHandler or
close derivatives.

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

from datetime import datetime, timedelta
from functools import partial
import json
import asyncio

# this replaces the default encoder and makes it so Tornado will do the right
# thing when it converts dicts to JSON when a
# tornado.web.RequestHandler.write(dict) is called.
from .jsonencoder import FrontendEncoder
json._default_encoder = FrontendEncoder()

import tornado.web
import tornado.ioloop

from .permissions import pii_hash
from . import actions


class RateLimitMixin:
    """
    This class contains a method that rate-limits the authnzerver's own API.

    Requires:

    - self.cacheobj  (from AuthHandler)
    - self.ratelimits (from AuthHandler)
    - self.pii_salt (from AuthHandler)
    - self.request.remote_ip (from tornado.web.RequestHandler)

    """

    def ratelimit_request(self, reqid, request_type, request_body):
        """
        This rate-limits the request based on the request type and the
        set ratelimits passed in the config object.

        """

        # increment the global request each time
        all_reqcount = self.cacheobj.counter_increment(
            "all_request_count",
        )

        # check the global request rate
        if all_reqcount > self.ratelimits['burst']:

            (all_reqrate,
             all_reqcount,
             all_reqcount0,
             all_req_tnow,
             all_req_t0) = (
                self.cacheobj.counter_rate(
                    "all_request_count",
                    60.0,
                    return_allinfo=True
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
                request_body.get("system_id", None) or
                request_body.get("session_token", None) or
                request_body.get("ip_address", None) or
                request_body.get("email_address", None)
            )

            # need special handling for user-lookup-match
            # FIXME: this should really be an internal- prefixed function
            if request_type == 'user-lookup-match':
                user_cache_token = f"user-lookup-{self.request.remote_ip}"

            # drop all requests that try to get around rate-limiting
            if not user_cache_token:
                LOGGER.error(
                    "[%s] request: '%s' is missing a payload value "
                    "needed to calculate rate, dropping this request."
                    % (reqid, request_type)
                )
                raise tornado.web.HTTPError(status_code=400)

            user_cache_key = f"user-request-{user_cache_token}"

            user_reqcount = self.cacheobj.counter_increment(
                user_cache_key,
            )

            if user_reqcount > self.ratelimits["burst"]:

                (user_reqrate,
                 user_reqcount,
                 user_reqcount0,
                 user_req_tnow,
                 user_req_t0) = (
                    self.cacheobj.counter_rate(
                        user_cache_key,
                        60.0,
                        return_allinfo=True
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
        elif request_type.startswith("session-"):

            session_cache_token = (
                request_body.get("user_id", None) or
                request_body.get("session_token", None) or
                request_body.get("ip_address", None)
            )
            if not session_cache_token:
                LOGGER.error(
                    "[%s] request: '%s' is missing a payload value "
                    "needed to calculate rate, dropping this request."
                    % (reqid, request_type)
                )
                raise tornado.web.HTTPError(status_code=400)

            session_cache_key = f"session-request-{session_cache_token}"

            session_reqcount = self.cacheobj.counter_increment(
                session_cache_key,
            )

            if session_reqcount > self.ratelimits["burst"]:

                (session_reqrate,
                 session_reqcount,
                 session_reqcount0,
                 session_req_tnow,
                 session_req_t0) = (
                    self.cacheobj.counter_rate(
                        session_cache_key,
                        60.0,
                        return_allinfo=True
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
        elif request_type.startswith("apikey-"):

            # handle API key issuance
            apikey_cache_token = (
                request_body.get("ip_address", None)
            )
            # handle all other API key actions
            if not apikey_cache_token and request_body.get("apikey_dict"):
                apikey_cache_token = request_body["apikey_dict"].get("uid",
                                                                     None)

            if not apikey_cache_token:
                LOGGER.error(
                    "[%s] request: '%s' is missing a payload value "
                    "needed to calculate rate, dropping this request."
                    % (reqid, request_type)
                )
                raise tornado.web.HTTPError(status_code=400)

            apikey_cache_key = f"apikey-request-{apikey_cache_token}"

            apikey_reqcount = self.cacheobj.counter_increment(
                apikey_cache_key,
            )

            if apikey_reqcount > self.ratelimits["burst"]:

                (apikey_reqrate,
                 apikey_reqcount,
                 apikey_reqcount0,
                 apikey_req_now,
                 apikey_req_t0) = (
                    self.cacheobj.counter_rate(
                        apikey_cache_key,
                        60.0,
                        return_allinfo=True
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

        # check the internal- prefixed request
        elif request_type.startswith("internal-"):

            # the internal request cache token is the request_type and the
            # originating IP address of the internal request
            internal_cache_token = f"{request_type}-{self.request.remote_ip}"
            internal_cache_key = f"internal-request-{internal_cache_token}"

            internal_reqcount = self.cacheobj.counter_increment(
                internal_cache_key,
            )

            # more generous burst allowance for internal requests
            if internal_reqcount > 500:

                (internal_reqrate,
                 internal_reqcount,
                 internal_reqcount0,
                 internal_req_tnow,
                 internal_req_t0) = (
                    self.cacheobj.counter_rate(
                        internal_cache_key,
                        60.0,
                        return_allinfo=True
                    )
                )

                # more generous rate allowance for internal requests
                # 50 reqs/sec/IP address
                if internal_reqrate > 3000:
                    LOGGER.error(
                        "[%s] request '%s' is being rate-limited. "
                        "Cache token: '%s', count: %s. "
                        "Rate: %.3f > limit specified for '%s': %s"
                        % (reqid,
                           request_type,
                           pii_hash(internal_cache_key, self.pii_salt),
                           internal_reqcount,
                           internal_reqrate,
                           'internal',
                           3000)
                    )
                    raise tornado.web.HTTPError(status_code=429)


class UserLockMixin:
    """This class handles user locking/unlocking and slowing down
    repeated password failures.

    """

    async def handle_failed_logins(self, payload):
        """
        This handles failed logins.

        - Adds increasing wait times to successive logins if they keep failing.
        - If the number of failed logins exceeds 10, the account is locked for
          one hour, and an unlock action is scheduled on the ioloop.

        Requires:

        - self.failed_passchecks (from AuthHandler)
        - self.config (from AuthHandler)

        """

        # increment the failure counter and return it
        if payload['body']['email'] in self.failed_passchecks:
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
            return 'wait', failed_pass_count, wait_time

        elif failed_pass_count > self.config.userlocktries:
            return 'locked', failed_pass_count, 0.0

        else:
            return 'ok', failed_pass_count, 0.0

    async def lockuser_repeated_login_failures(self,
                                               payload,
                                               unlock_after_seconds=3600):
        """
        This locks the user account. Also schedules an unlock action for later.

        Requires:

        - self.config (from AuthHandler)
        - self.executor (from AuthHandler)
        - self.scheduled_user_unlock() (from UserLockMixin)

        """

        # look up the user ID using the email address
        loop = tornado.ioloop.IOLoop.current()

        backend_func = partial(
            actions.get_user_by_email,
            {'email': payload['body']['email'],
             'reqid': payload['body']['reqid'],
             'pii_salt': payload['body']['pii_salt']},
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
                {'target_userid': user_info['user_info']['user_id'],
                 'action': 'lock',
                 'reqid': payload['body']['reqid'],
                 'pii_salt': payload['body']['pii_salt']},
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
            "user_id": None,
            "messages": [
                "Your user account has been locked "
                "after repeated login failures. "
                "Try again in an hour or "
                "contact the server admins."
            ]
        }

    async def scheduled_user_unlock(self, user_id, reqid, pii_salt):
        """
        This function is scheduled on the ioloop to unlock the specified user.

        """

        LOGGER.warning(
            "[%s] Unlocked the account for user ID: %s after "
            "login-failure timeout expired." %
            (reqid, pii_hash(user_id, pii_salt))
        )

        loop = tornado.ioloop.IOLoop.current()

        backend_func = partial(
            actions.internal_toggle_user_lock,
            {'target_userid': user_id,
             'action': 'unlock',
             'reqid': reqid,
             'pii_salt': pii_salt},
            config=self.config
        )

        locked_info = await loop.run_in_executor(
            self.executor,
            backend_func
        )
        return locked_info
