# -*- coding: utf-8 -*-
# healthcheck.py - Waqas Bhatti (waqas.afzal.bhatti@gmail.com) - Jul 2020
# License: MIT - see the LICENSE file for the full text.

"""These are handlers to respond to health-check requests.

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
from time import monotonic

# this replaces the default encoder and makes it so Tornado will do the right
# thing when it converts dicts to JSON when a
# tornado.web.RequestHandler.write(dict) is called.
from .jsonencoder import FrontendEncoder
json._default_encoder = FrontendEncoder()

import tornado.web
import tornado.ioloop

from .ratelimit import RateLimitMixin
from .actions import database_health_check


class HealthCheckHandler(tornado.web.RequestHandler,
                         RateLimitMixin):
    """
    This handles health check endpoints.

    """

    def initialize(self,
                   config,
                   executor,
                   cacheobj):
        """
        This sets up some config.

        """

        self.config = config
        self.executor = executor
        self.cacheobj = cacheobj

        self.pii_salt = self.config.piisalt
        self.nworkers = self.config.workers
        self.ratelimits = self.config.ratelimits

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

    async def get(self):
        """This responds to a health-check request.

        Returns 200 if the server is up and all the background workers report
        their DB connection is good.

        """

        self.ratelimit_request(101010,
                               "apikey-healthcheck",
                               {"ip_address":self.request.remote_ip})

        loop = tornado.ioloop.IOLoop.current()

        backend_func = partial(
            database_health_check,
            config=self.config
        )

        health_checks = {}

        healthcheck_start = monotonic()
        healthcheck_clock = 0.0
        max_healthcheck_time = 5.0

        while healthcheck_clock < max_healthcheck_time:

            # this round-robin schedules the tasks on all the workers
            health_check = await loop.run_in_executor(
                self.executor,
                backend_func
            )
            health_checks[health_check['process']] = (
                "ok" if health_check['success']
                else health_check["failure_reason"]
            )

            healthcheck_clock = monotonic() - healthcheck_start
            if len(health_checks) == self.nworkers:
                break

        all_workers_ok = (all(health_checks[key] for key in health_checks)
                          and len(health_checks) == self.nworkers)

        retdict = {
            "Expected-Workers":self.nworkers,
            "Workers":health_checks,
            "Check-Time": healthcheck_clock,
            "Health-Ok":all_workers_ok
        }

        if all_workers_ok:
            self.set_status(200)
        else:
            self.set_status(500)
        self.write(retdict)
        self.finish()
