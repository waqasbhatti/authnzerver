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

# rate-limit sensitive actions more agressively (these are all per minute)
# these can be overriden by specifying these specific request types in the
# server's ratelimits config variable
AGGRESSIVE_RATE_LIMITS = {
    "user-new": 5,
    "user-login": 10,
    "user-logout": 10,
    "user-edit": 10,
    "user-resetpass": 5,
    "user-changepass": 5,
    "user-sendemail-signup": 2,
    "user-sendemail-forgotpass": 2,
    "user-set-emailsent": 2,
    "apikey-new": 30,
    "apikey-new-nosession": 30,
    "apikey-refresh-nosession": 30,
}


class RateLimitMixin:
    """
    This class contains a method that rate-limits the authnzerver's own API.

    Requires:

    - self.cacheobj  (from AuthHandler)
    - self.ratelimits (from AuthHandler)
    - self.pii_salt (from AuthHandler)
    - self.request.remote_ip (from tornado.web.RequestHandler)

    """

    def ratelimit_request(self,
                          reqid,
                          request_type,
                          frontend_client_ipaddr,
                          request_body=None):
        """
        This rate-limits the request based on the request type and the
        set ratelimits passed in the config object.

        """

        #
        # rate limit per request_type:client_ipaddr key
        #
        client_ipaddr_key = f"{request_type}-{frontend_client_ipaddr}"
        client_req_count = self.cacheobj.counter_increment(
            client_ipaddr_key,
        )

        #
        # email-tied request types are additionally checked per
        # email_addr:request_type pair
        #
        if "email" in request_type and request_body is not None:

            email_addr = request_body.get("email")
            if not email_addr:
                email_addr = request_body.get("email_address")

            if not email_addr:
                LOGGER.error(f"email-tied request type: {request_type} could "
                             f"not be rate-limited because no "
                             f"'email' or 'email_address' key found in "
                             f"request body. failing this request...")
                raise tornado.web.HTTPError(status_code=429)

            client_email_key = f"{request_type}-{email_addr}"
            client_email_count = self.cacheobj.counter_increment(
                client_email_key
            )

            (client_email_reqrate,
             client_email_reqcount,
             client_email_reqcount0,
             client_email_req_tnow,
             client_email_req_t0) = (
                self.cacheobj.counter_rate(
                    client_email_key,
                    60.0,
                    return_allinfo=True
                )
            )

            if request_type in AGGRESSIVE_RATE_LIMITS:

                limit_applied = AGGRESSIVE_RATE_LIMITS[request_type]
                if (client_email_count > limit_applied
                        and client_email_reqrate > limit_applied):
                    LOGGER.error(
                        "[%s] request '%s' is being rate-limited. "
                        "Cache token: '%s', count: %s. "
                        "Rate: %.3f per minute > limit specified for '%s': %s"
                        % (reqid,
                           request_type,
                           pii_hash(client_email_key, self.pii_salt),
                           client_email_reqcount,
                           client_email_reqrate,
                           request_type,
                           limit_applied)
                    )
                    raise tornado.web.HTTPError(status_code=429)

            else:

                limit_applied = self.ratelimits["user"]
                if (client_email_count > limit_applied
                        and client_email_reqrate > limit_applied):
                    LOGGER.error(
                        "[%s] request '%s' is being rate-limited. "
                        "Cache token: '%s', count: %s. "
                        "Rate: %.3f per minute > limit specified for '%s': %s"
                        % (reqid,
                           request_type,
                           pii_hash(client_email_key, self.pii_salt),
                           client_email_reqcount,
                           client_email_reqrate,
                           request_type,
                           limit_applied)
                    )
                    raise tornado.web.HTTPError(status_code=429)

        #
        # all other rate-limits are checked per IP address:request_type pair
        #

        # apply agressive rate limiting to sensitive actions
        if request_type in AGGRESSIVE_RATE_LIMITS:

            (client_ipaddr_reqrate,
             client_ipaddr_reqcount,
             client_ipaddr_reqcount0,
             client_ipaddr_req_tnow,
             client_ipaddr_req_t0) = (
                self.cacheobj.counter_rate(
                    client_ipaddr_key,
                    60.0,
                    return_allinfo=True
                )
            )

            limit_applied = AGGRESSIVE_RATE_LIMITS[request_type]

            if (client_req_count > limit_applied
                    and client_ipaddr_reqrate > limit_applied):
                LOGGER.error(
                    "[%s] request '%s' is being rate-limited. "
                    "Cache token: '%s', count: %s. "
                    "Rate: %.3f per minute > limit specified for '%s': %s"
                    % (reqid,
                       request_type,
                       pii_hash(client_ipaddr_key, self.pii_salt),
                       client_ipaddr_reqcount,
                       client_ipaddr_reqrate,
                       request_type,
                       limit_applied)
                )
                raise tornado.web.HTTPError(status_code=429)

        # apply specific rate limiting to explicitly specified
        # API actions in the ratelimits config var
        elif request_type in self.ratelimits:

            (client_ipaddr_reqrate,
             client_ipaddr_reqcount,
             client_ipaddr_reqcount0,
             client_ipaddr_req_tnow,
             client_ipaddr_req_t0) = (
                self.cacheobj.counter_rate(
                    client_ipaddr_key,
                    60.0,
                    return_allinfo=True
                )
            )

            limit_applied = self.ratelimits[request_type]

            if (client_req_count > limit_applied
                    and client_ipaddr_reqrate > limit_applied):
                LOGGER.error(
                    "[%s] request '%s' is being rate-limited. "
                    "Cache token: '%s', count: %s. "
                    "Rate: %.3f per minute > limit specified for '%s': %s"
                    % (reqid,
                       request_type,
                       pii_hash(client_ipaddr_key, self.pii_salt),
                       client_ipaddr_reqcount,
                       client_ipaddr_reqrate,
                       request_type,
                       limit_applied)
                )
                raise tornado.web.HTTPError(status_code=429)

        # all other ratelimits are applied according to the
        # API action groups defined in the ratelimits config var
        else:

            # only apply rate-limits after burst is exceeded
            if client_req_count > self.ratelimits['burst']:

                (client_ipaddr_reqrate,
                 client_ipaddr_reqcount,
                 client_ipaddr_reqcount0,
                 client_ipaddr_req_tnow,
                 client_ipaddr_req_t0) = (
                    self.cacheobj.counter_rate(
                        client_ipaddr_key,
                        60.0,
                        return_allinfo=True
                    )
                )

                #
                # specific rate-limiting per request type
                #
                if request_type.startswith('user-'):
                    limit_name, limit_applied = (
                        'user', self.ratelimits['user']
                    )
                elif request_type.startswith('session-'):
                    limit_name, limit_applied = (
                        'session', self.ratelimits['session']
                    )
                elif request_type.startswith('apikey-'):
                    limit_name, limit_applied = (
                        'apikey', self.ratelimits['apikey']
                    )
                # internal- prefixed requests have a more generous ratelimit
                elif request_type.startswith('internal-'):
                    limit_name, limit_applied = (
                        'internal', 3000
                    )
                # all other requests are limited by frontend client IP addr
                else:
                    limit_name, limit_applied = (
                        'ipaddr', self.ratelimits['ipaddr']
                    )

                if client_ipaddr_reqrate > limit_applied:
                    LOGGER.error(
                        "[%s] request '%s' is being rate-limited. "
                        "Cache token: '%s', count: %s. "
                        "Rate: %.3f per minute > limit specified for '%s': %s"
                        % (reqid,
                           request_type,
                           pii_hash(client_ipaddr_key, self.pii_salt),
                           client_ipaddr_reqcount,
                           client_ipaddr_reqrate,
                           limit_name,
                           limit_applied)
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
            wait_time = 1.5 ** (failed_pass_count - 1.0)
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

        await loop.run_in_executor(
            self.executor,
            backend_func
        )
