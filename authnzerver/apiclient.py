# -*- coding: utf-8 -*-
# apiclient.py - Waqas Bhatti (waqas.afzal.bhatti@gmail.com) - Aug 2020
# License: MIT - see the LICENSE file for the full text.

"""
This contains an auto-generated API client for the authnzerver.

"""

from functools import partial

from authnzerver.apischema import schema, validate_api_request
from authnzerver.client import Authnzerver


class APIClient:

    def dynamic_api_function(self, api_action, *args, **kwargs):
        """
        This validates an API action, then fires the API call.

        """

        request_schema = schema.get(api_action, None)
        if not request_schema:
            raise ValueError(
                f"Requested action: '{api_action}' is not a "
                f"valid authnzerver action."
            )

        request_payload = {}
        for schema_arg, func_arg in zip(request_schema["args"], args):
            request_payload[schema_arg["name"]] = func_arg

        for schema_kwarg in request_schema["kwargs"]:
            if schema_kwarg["name"] in kwargs:
                request_payload[schema_kwarg["name"]] = (
                    kwargs[schema_kwarg["name"]]
                )

        request_valid, problems, messages = validate_api_request(
            api_action,
            request_payload,
        )

        if not request_valid:
            raise ValueError(
                f"Requested action: '{api_action}' "
                f"has invalid arguments: {problems}."
            )

        resp = self.srv.request(api_action, request_payload)
        return resp

    async def async_dynamic_api_function(self, api_action, *args, **kwargs):
        """
        This validates an API action, then fires the API call.

        """

        request_schema = schema.get(api_action, None)
        if not request_schema:
            raise ValueError(
                f"Requested action: '{api_action}' is not a "
                f"valid authnzerver action."
            )

        request_payload = {}
        for schema_arg, func_arg in zip(request_schema["args"], args):
            request_payload[schema_arg["name"]] = func_arg

        for schema_kwarg in request_schema["kwargs"]:
            if schema_kwarg["name"] in kwargs:
                request_payload[schema_kwarg["name"]] = (
                    kwargs[schema_kwarg["name"]]
                )

        request_valid, problems, messages = validate_api_request(
            api_action,
            request_payload,
        )

        if not request_valid:
            raise ValueError(
                f"Requested action: '{api_action}' "
                f"has invalid arguments: {problems}."
            )

        return await self.srv.async_request(api_action, request_payload)

    def __init__(self,
                 authnzerver_url=None,
                 authnzerver_secret=None,
                 asynchronous=False):
        """
        Makes a new APIClient.

        """

        self.srv = Authnzerver(authnzerver_url=authnzerver_url,
                               authnzerver_secret=authnzerver_secret)

        #
        # create dynamic functions for all API actions in the schema
        #

        if asynchronous:
            for action in schema:
                function_to_use = partial(self.async_dynamic_api_function,
                                          action)
                setattr(self, action.replace('-', '_'), function_to_use)

        else:
            for action in schema:
                function_to_use = partial(self.dynamic_api_function, action)
                setattr(self, action.replace('-', '_'), function_to_use)
