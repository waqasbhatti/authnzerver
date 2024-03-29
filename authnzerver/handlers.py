# -*- coding: utf-8 -*-
# handlers.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""These are handlers for the authnzerver.

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

import json
from functools import partial

# this replaces the default encoder and makes it so Tornado will do the right
# thing when it converts dicts to JSON when a
# tornado.web.RequestHandler.write(dict) is called.
from .jsonencoder import FrontendEncoder

json._default_encoder = FrontendEncoder()

import tornado.web
import tornado.ioloop

from .messaging import encrypt_message, decrypt_message
from .permissions import pii_hash
from .ratelimit import RateLimitMixin, UserLockMixin
from .apischema import validate_and_get_function


#######################
## MAIN AUTH HANDLER ##
#######################


class AuthHandler(tornado.web.RequestHandler, RateLimitMixin, UserLockMixin):
    """
    This handles the actual auth requests.

    """

    def initialize(self, config, executor, cacheobj, failed_passchecks):
        """
        This sets up stuff.

        """

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

    async def send_response(self, response, reqid):
        """
        This handles the response generation.

        """

        response_dict = {
            "success": response["success"],
            "response": response,
            "messages": response["messages"],
            "reqid": reqid,
        }

        # add the failure reason as a top level item in the response dict
        # if the action failed
        if not response["success"] and "failure_reason" in response:
            response_dict["failure_reason"] = response["failure_reason"]

        encrypted_base64 = encrypt_message(response_dict, self.fernet_secret)

        self.set_header("content-type", "text/plain; charset=UTF-8")
        self.write(encrypted_base64)
        await self.finish()

    def write_error(self, status_code, **kwargs):
        """
        This writes the error as a response.

        """

        self.set_header("content-type", "text/plain; charset=UTF-8")
        if status_code == 400:
            self.write(
                f"HTTP {status_code}: Could not service this request "
                f"because of invalid request parameters."
            )
        elif status_code == 401:
            self.write(
                f"HTTP {status_code}: Could not service this request "
                f"because of invalid request authentication token or "
                f"violation of host restriction."
            )
        elif status_code == 429:
            self.set_header("Retry-After", "180")
            self.write(
                f"HTTP {status_code}: Could not service this request "
                f"because the set rate limit has been exceeded."
            )
        else:
            self.write(f"HTTP {status_code}: Could not service this request.")

        if not self._finished:
            self.finish()

    async def post(self):
        """
        Handles the incoming POST request.

        """

        # decrypt the request
        payload = decrypt_message(self.request.body, self.fernet_secret)
        if not payload:
            raise tornado.web.HTTPError(status_code=401)

        # ignore all requests for echo to this handler
        if payload["request"] == "echo":
            LOGGER.error("This handler can't echo things.")
            raise tornado.web.HTTPError(status_code=400)

        # get the request ID
        reqid = payload.get("reqid")
        if reqid is None:
            raise ValueError(
                "No request ID provided. " "Ignoring this request."
            )

        # rate limit the request if this is turned on
        if self.ratelimits:
            # get the frontend client IP addr
            frontend_client_ipaddr = payload.get("client_ipaddr")

            if not frontend_client_ipaddr:
                LOGGER.error(
                    "[%s] request: '%s' is missing a payload "
                    "value: 'client_ipaddr' "
                    "needed to calculate rate, dropping this request."
                    % (reqid, payload["request"])
                )
                raise tornado.web.HTTPError(status_code=400)

            self.ratelimit_request(
                reqid,
                payload["request"],
                frontend_client_ipaddr,
                request_body=payload["body"],
            )

        # if we successfully got past host, decryption, rate-limit validation,
        # then process the request
        try:

            #
            # dispatch the action handler function
            #

            # inject the request ID into the body of the request so the backend
            # function can report on it
            payload["body"]["reqid"] = reqid

            # inject the PII salt into the body of the request as well
            payload["body"]["pii_salt"] = self.pii_salt

            #
            # validate the request and choose the function to dispatch
            #
            handler_func, problems, validate_msgs = validate_and_get_function(
                payload["request"], payload["body"]
            )

            if handler_func is None:
                problems["failure_reason"] = "invalid request parameters"
                response = {
                    "success": False,
                    "response": problems,
                    "messages": [validate_msgs],
                }
            else:
                # inject the config object into the backend function call
                # this passes along any secrets or settings from environ
                # directly to those functions
                backend_func = partial(
                    handler_func, payload["body"], config=self.config
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
            passcheck_requests = {"user-login", "user-passcheck-nosession"}

            if (
                payload["request"] in passcheck_requests
                and response["success"] is False
            ):

                (
                    failure_status,
                    failure_count,
                    failure_wait,
                ) = await self.handle_failed_logins(payload)

                # if the user is locked for repeated login failures, handle that
                if failure_status == "locked":
                    response = await self.lockuser_repeated_login_failures(
                        payload, unlock_after_seconds=self.config.userlocktime
                    )
                elif failure_status == "wait":
                    LOGGER.warning(
                        "[%s] User with email: %s is being rate-limited "
                        "after %s failed login attempts. "
                        "Current wait time: %.1f seconds."
                        % (
                            reqid,
                            pii_hash(payload["body"]["email"], self.pii_salt),
                            failure_count,
                            failure_wait,
                        )
                    )

            # reset the failed counter to zero for each successful attempt
            elif (
                payload["request"] in passcheck_requests
                and response["success"] is True
            ):

                self.failed_passchecks.pop(payload["body"]["email"], None)

            #
            # trim the failed_passchecks dict
            #
            if len(self.failed_passchecks) > 1000:
                self.failed_passchecks.pop(self.failed_passchecks.keys()[0])

            #
            # form and send the response
            #
            await self.send_response(response, reqid)

        except Exception:

            LOGGER.exception("Failed to understand request.")
            raise tornado.web.HTTPError(status_code=400)
