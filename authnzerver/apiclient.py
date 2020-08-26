# -*- coding: utf-8 -*-
# apiclient.py - Waqas Bhatti (waqas.afzal.bhatti@gmail.com) - Aug 2020
# License: MIT - see the LICENSE file for the full text.

"""
This contains an auto-generated API client for the authnzerver.

"""

from functools import partial
from textwrap import dedent

from authnzerver.apischema import schema, validate_api_request
from authnzerver.client import Authnzerver


class APIClient:
    """An API client for the authnzerver.

    This auto-generates class methods to call for each API action available in
    the authnzerver API schema.

    Parameters
    ----------

    authnzerver_url : str
        The URL of the authnzerver to connect to.

    authnzerver_secret : str
        The shared secret key for the authnzerver.

    asynchronous : bool, optional, default=False
        If True, generates awaitable async methods for all API actions.

    use_kwargs : bool, option, default=False
        If this is True, all arguments for the auto-generated API methods
        will be keyword arguments instead of regular arguments for required
        parameters and keyword arguments for optional ones.

    Notes
    -----

    Since the class methods and their docstrings are dynamically generated, a
    simple ``help()`` call won't work to show docstrings.

    If you're using IPython or the Jupyter notebook, using a ``?`` at the end of
    the method name works as expected::

        # create a new client
        srv = APIClient(authnzerver_url=..., authnzerver_secret=...)

        # get help on the user_new() method
        srv.user_new?

    In a normal Python shell, however, you must use the following pattern to get
    help on an APIClient method::

        # create a new client
        srv = APIClient(authnzerver_url=..., authnzerver_secret=...)

        # get help on the user_new() method
        print(srv.user_new.__doc__)

    """

    def dynamic_api_function(self, api_action, use_kwargs, *args, **kwargs):
        """
        Validates an API action, then fires the API call.

        """

        request_schema = schema.get(api_action, None)
        if not request_schema:
            raise ValueError(
                f"Requested action: '{api_action}' is not a "
                f"valid authnzerver action."
            )

        request_payload = {}

        if use_kwargs:
            for schema_arg in request_schema["args"]:
                if schema_arg["name"] in kwargs:
                    request_payload[schema_arg["name"]] = (
                        kwargs[schema_arg["name"]]
                    )
        else:
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

    async def async_dynamic_api_function(self, api_action, use_kwargs,
                                         *args, **kwargs):
        """
        Validates an API action, then fires the API call.

        This version is async.

        """

        request_schema = schema.get(api_action, None)
        if not request_schema:
            raise ValueError(
                f"Requested action: '{api_action}' is not a "
                f"valid authnzerver action."
            )

        request_payload = {}

        if use_kwargs:
            for schema_arg in request_schema["args"]:
                if schema_arg["name"] in kwargs:
                    request_payload[schema_arg["name"]] = (
                        kwargs[schema_arg["name"]]
                    )
        else:
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

    def dynamic_docstring(self, action, use_kwargs=False):
        """
        This adds a docstring to the dynamically generated function.

        """

        docstring_template = dedent(
            """\
            {docsentence}
            {kwarg_note}
            Parameters
            ----------
            {param_list}
            Returns
            -------
            response : AuthnzerverResponse namedtuple
                Returns a namedtuple object, which has the following attributes:

                - success (bool): True if request succeeded, False otherwise.
                - response (dict or None): The response dict from authnzerver.
                - messages (list of str): End-user messages from authnzerver.
                - headers (dict): Authnzerver HTTP response headers.
                - status_code (int): The HTTP response code from authnzerver.
                - failure_reason (str): Internal detailed failure reason.

            """
        )

        param_template = dedent(
            """\
            {param_name} : {param_types}{optional_note}
                {param_description}
            """
        )

        param_list = []
        for arg in schema[action]["args"]:

            param_types = arg["type"]
            if isinstance(param_types, (list, tuple)):
                param_types = ", ".join(param_types)
            else:
                param_types = arg["type"]

            param_list.append(
                param_template.format(
                    param_name=arg["name"],
                    param_types=param_types,
                    param_description=arg["doc"],
                    optional_note="",
                )
            )

        for kwarg in schema[action]["kwargs"]:
            param_types = arg["type"]
            if isinstance(param_types, (list, tuple)):
                param_types = ", ".join(param_types)
            else:
                param_types = arg["type"]

            param_list.append(
                param_template.format(
                    param_name=kwarg["name"],
                    param_types=param_types,
                    param_description=kwarg["doc"],
                    optional_note=", optional",
                )
            )

        if use_kwargs:
            kwarg_note = (
                "\nAll parameters can be specified as keyword arguments.\n"
            )
        else:
            kwarg_note = ""

        docstring = docstring_template.format(
            docsentence=schema[action]["doc"],
            param_list="\n".join(param_list),
            kwarg_note=kwarg_note
        )

        return docstring

    def __init__(self,
                 authnzerver_url=None,
                 authnzerver_secret=None,
                 asynchronous=False,
                 use_kwargs=False):
        """
        Makes a new APIClient.

        Parameters
        ----------

        authnzerver_url : str
            The URL of the authnzerver to connect to.

        authnzerver_secret : str
            The shared secret key for the authnzerver.

        asynchronous : bool, optional, default=False
            If True, generates awaitable async methods for all API actions.

        use_kwargs : bool, option, default=False
            If this is True, all arguments for the auto-generated API methods
            will be keyword arguments instead of regular arguments for required
            parameters and keyword arguments for optional ones.

        """

        self.srv = Authnzerver(authnzerver_url=authnzerver_url,
                               authnzerver_secret=authnzerver_secret)

        #
        # create dynamic functions for all API actions in the schema
        #

        if asynchronous:
            for action in schema:
                function_to_use = partial(
                    self.async_dynamic_api_function,
                    action,
                    use_kwargs,
                )
                method_name = action.replace('-', '_')
                method_docstring = self.dynamic_docstring(action,
                                                          use_kwargs=use_kwargs)
                function_to_use.__doc__ = method_docstring
                function_to_use.__name__ = method_name
                setattr(self, method_name, function_to_use)

        else:
            for action in schema:
                function_to_use = partial(
                    self.dynamic_api_function,
                    action,
                    use_kwargs,
                )
                method_name = action.replace('-', '_')
                method_docstring = self.dynamic_docstring(action,
                                                          use_kwargs=use_kwargs)
                function_to_use.__doc__ = method_docstring
                function_to_use.__name__ = method_name
                setattr(self, method_name, function_to_use)
