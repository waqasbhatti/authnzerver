# -*- coding: utf-8 -*-

"""This module contains an authnzerver client, useful for frontend servers.


"""

#############
## LOGGING ##
#############

import logging
from typing import Union

LOGGER = logging.getLogger(__name__)


#############
## IMPORTS ##
#############

import json
import os
from collections import namedtuple
from secrets import token_urlsafe

from tornado.httpclient import (
    HTTPClient,
    AsyncHTTPClient,
    HTTPRequest,
    HTTPClientError,
)
from cryptography.fernet import Fernet

from .messaging import encrypt_message, decrypt_message

from .jsonencoder import FrontendEncoder

# this replaces the default encoder and makes it so Tornado will do the right
# thing when it converts dicts to JSON when a
# tornado.web.RequestHandler.write(dict) is called.
json._default_encoder = FrontendEncoder()


# the response object
AuthnzerverResponse = namedtuple(
    "AuthnzerverResponse",
    [
        "success",
        "response",
        "messages",
        "headers",
        "status_code",
        "failure_reason",
    ],
)


class Authnzerver:
    """An authnzerver client class, capable of async and sync calls.

    To do anything useful, an *authnzerver_url* and *authnzerver_token* are
    required. By default, this object will populate these from the
    environment using the following variables:

    - AUTHNZERVER_URL -> authnzerver_url
    - AUTHNZERVER_SECRET -> authnzerver_secret

    These are overridden by whatever you provide in the *authnzerver_url*
    and *authnzerver_secret* kwargs.

    If *tls_certfile* and *tls_keyfile* are both provided, they will be used
    to set up a TLS-enabled connection to the authnzerver.

    """

    def __init__(
        self,
        authnzerver_url: str = None,
        authnzerver_secret: bytes = None,
        tls_certfile: str = None,
        tls_keyfile: str = None,
    ):
        """Makes a new Authnzerver client object."""

        if authnzerver_url is None:
            self.authnzerver_url = os.environ.get("AUTHNZERVER_URL", None)
        else:
            self.authnzerver_url = authnzerver_url

        if self.authnzerver_url:
            self.authnzerver_url = self.authnzerver_url.strip().strip('"')

        if authnzerver_secret is None:
            self.authnzerver_secret = os.environ.get(
                "AUTHNZERVER_SECRET", None
            )
        else:
            self.authnzerver_secret = authnzerver_secret

        # check the Fernet key
        if self.authnzerver_secret:
            self.authnzerver_secret = self.authnzerver_secret.strip().strip(
                '"'
            )
            try:
                Fernet(self.authnzerver_secret)
            except Exception:
                LOGGER.error(
                    "The provided authnzerver_secret is "
                    "not a valid Fernet key. "
                    "Check base64 padding. You can use either "
                    "cryptography.Fernet.generate_key() or "
                    "base64.urlsafe_b64encode(secrets.token_bytes())"
                    ".decode('utf-8') to "
                    "generate a compatible secret key."
                )
                raise

        # get the cert file and key
        self.tls_certfile = tls_certfile
        self.tls_keyfile = tls_keyfile

    def request(
        self,
        request_type: str,
        request_body: dict,
        request_id: Union[str, int] = None,
    ) -> AuthnzerverResponse:
        """This does a synchronous request to the authnzerver.

        Parameters
        ----------

        request_type : str
            This should be one of the request types defined in the authnzerver
            `HTTP API <https://authnzerver.readthedocs.io/en/latest/api.html>`_.

        request_body : dict
            A dict with the appropriate items needed for *request_type*. This
            should also contain a key: "client_ipaddr" with the IP address of
            the frontend server's client. This is used for rate-limiting
            authnzerver API actions per IP address per minute.

        request_id : str or int, optional
            If *request_id* is None, a random 8-byte request ID will be
            generated for you. Use *request_id* to track authnzerver requests
            throughout the response handling cycle of your frontend server.

        Returns
        -------

        namedtuple
            Returns an *AuthnzerverResponse* named-tuple with the following
            attributes::

                (success, response, messages, headers,
                 status_code, failure_reason)

            where:

            - *success* is a boolean indicating if the request was successful.

            - *response* is a dict containing the full response from the
              authnzerver.

            - *messages* is a list of strings containing any messages that are
              appropriate to pass on to the end-user.

            - *headers* is a dict containing the response headers from the
              authnzerver.

            - *status_code* is the HTTP status code of the authnzerver
              request. Use this to figure out if your request was being
              rate-limited (check for 429).

            - *failure_reason* is None if the request was successful, but if it
              wasn't, contains the reason why the request might have failed;
              including details of any exceptions encountered. This MUST NOT be
              disclosed to an end-user of the frontend server.

        """

        httpclient = HTTPClient()

        if request_id is None:
            request_id = token_urlsafe(8)

        if "client_ipaddr" not in request_body:
            raise KeyError(
                "Expected key 'client_ipaddr' in request_body. "
                "Set this to the frontend client's IP address "
                "to enable rate-limiting."
            )

        message_dict = {
            "request": request_type,
            "body": request_body,
            "reqid": request_id,
            "client_ipaddr": request_body["client_ipaddr"],
        }

        # encrypt the message
        encrypted_request = encrypt_message(
            message_dict, self.authnzerver_secret
        )

        # set up the request
        request_obj = HTTPRequest(
            self.authnzerver_url,
            method="POST",
            body=encrypted_request,
            connect_timeout=5.0,
            request_timeout=5.0,
            client_key=self.tls_keyfile,
            client_cert=self.tls_certfile,
        )

        # fire the request
        try:
            authnzerver_response = httpclient.fetch(
                request_obj,
            )

            # decrypt the message
            decrypted_response = decrypt_message(
                authnzerver_response.body,
                self.authnzerver_secret,
                request_id,
            )

            if decrypted_response is None:
                return AuthnzerverResponse(
                    False,
                    None,
                    [
                        "This request could not be completed.",
                        "There was a problem communicating with "
                        "the auth server.",
                    ],
                    dict(authnzerver_response.headers),
                    authnzerver_response.code,
                    "could not decrypt authnzerver response",
                )

            returned_reqid = decrypted_response["reqid"]

            if returned_reqid != request_id:
                return AuthnzerverResponse(
                    False,
                    None,
                    [
                        "This request could not be completed.",
                        "There was a problem communicating with "
                        "the auth server.",
                    ],
                    dict(authnzerver_response.headers),
                    authnzerver_response.code,
                    "authnzerver returned incorrect request ID",
                )

            #
            # otherwise, return the response
            #

            success = decrypted_response.pop("success")
            messages = decrypted_response.pop("messages", None)
            headers = dict(authnzerver_response.headers)

            # some cleanup of the response dict
            response_dict = decrypted_response["response"]
            response_dict.pop("success", None)
            response_dict.pop("messages", None)
            response_dict.pop("failure_reason", None)

            status_code = authnzerver_response.code
            failure_reason = decrypted_response.pop("failure_reason", None)

            return AuthnzerverResponse(
                success,
                response_dict,
                messages,
                headers,
                status_code,
                failure_reason,
            )

        # non-200 response
        except HTTPClientError as e:

            authnzerver_response = e.response

            return AuthnzerverResponse(
                False,
                None,
                [
                    "This request could not be completed.",
                    "There was a problem communicating with the auth server.",
                ],
                dict(authnzerver_response.headers),
                authnzerver_response.code,
                authnzerver_response.body.decode("utf-8"),
            )

        # handle other exceptions
        except Exception as e:

            return AuthnzerverResponse(
                False,
                None,
                [
                    "This request could not be completed.",
                    "There was a problem communicating with the auth server.",
                ],
                None,
                None,
                "ran into an exception in request to authnzerver: %r" % e,
            )

        finally:
            httpclient.close()

    async def async_request(
        self,
        request_type: str,
        request_body: dict,
        request_id: Union[str, int] = None,
    ):
        """This does an  asynchronous request to the authnzerver.

        Parameters
        ----------

        request_type : str
            This should be one of the request types defined in the authnzerver
            `HTTP API <https://authnzerver.readthedocs.io/en/latest/api.html>`_.

        request_body : dict
            A dict with the appropriate items needed for *request_type*. This
            should also contain a key: "client_ipaddr" with the IP address of
            the frontend server's client. This is used for rate-limiting
            authnzerver API actions per IP address per minute.

        request_id : str or int, optional
            If *request_id* is None, a random 8-byte request ID will be
            generated for you. Use *request_id* to track authnzerver requests
            throughout the response handling cycle of your frontend server.

        Returns
        -------

        namedtuple
            Returns an *AuthnzerverResponse* named tuple with the following
            attributes::

                (success, response, messages,
                 headers, status_code, failure_reason)

            where:

            - *success* is a boolean indicating if the request was successful.

            - *response* is a dict containing the full response from the
              authnzerver.

            - *messages* is a list of strings containing any messages that are
              appropriate to pass on to the end-user.

            - *headers* is a dict containing the response headers from the
              authnzerver.

            - *status_code* is the HTTP status code of the authnzerver
              request. Use this to figure out if your request was being
              rate-limited (check for 429).

            - *failure_reason* is None if the request was successful, but if it
              wasn't, contains the reason why the request might have failed;
              including details of any exceptions encountered. This MUST NOT be
              disclosed to an end-user of the frontend server.

        """

        async_httpclient = AsyncHTTPClient()

        if request_id is None:
            request_id = token_urlsafe(8)

        if "client_ipaddr" not in request_body:
            raise KeyError(
                "Expected key 'client_ipaddr' in request_body. "
                "Set this to the frontend client's IP address "
                "to enable rate-limiting."
            )

        message_dict = {
            "request": request_type,
            "body": request_body,
            "reqid": request_id,
            "client_ipaddr": request_body["client_ipaddr"],
        }

        # encrypt the message
        encrypted_request = encrypt_message(
            message_dict, self.authnzerver_secret
        )

        # set up the request
        request_obj = HTTPRequest(
            self.authnzerver_url,
            method="POST",
            body=encrypted_request,
            connect_timeout=5.0,
            request_timeout=5.0,
            client_key=self.tls_keyfile,
            client_cert=self.tls_certfile,
        )

        # fire the request
        try:
            authnzerver_response = await async_httpclient.fetch(
                request_obj,
            )

            # decrypt the message
            decrypted_response = decrypt_message(
                authnzerver_response.body,
                self.authnzerver_secret,
                request_id,
            )

            if decrypted_response is None:
                return AuthnzerverResponse(
                    False,
                    None,
                    [
                        "This request could not be completed.",
                        "There was a problem communicating with "
                        "the auth server.",
                    ],
                    dict(authnzerver_response.headers),
                    authnzerver_response.code,
                    "could not decrypt authnzerver response",
                )

            returned_reqid = decrypted_response["reqid"]

            if returned_reqid != request_id:
                return AuthnzerverResponse(
                    False,
                    None,
                    [
                        "This request could not be completed.",
                        "There was a problem communicating with "
                        "the auth server.",
                    ],
                    dict(authnzerver_response.headers),
                    authnzerver_response.code,
                    "authnzerver returned incorrect request ID",
                )

            #
            # otherwise, return the response
            #

            success = decrypted_response.pop("success")
            messages = decrypted_response.pop("messages", None)
            headers = dict(authnzerver_response.headers)

            # some cleanup of the response dict
            response_dict = decrypted_response["response"]
            response_dict.pop("success", None)
            response_dict.pop("messages", None)
            response_dict.pop("failure_reason", None)

            status_code = authnzerver_response.code
            failure_reason = decrypted_response.pop("failure_reason", None)

            return AuthnzerverResponse(
                success,
                response_dict,
                messages,
                headers,
                status_code,
                failure_reason,
            )

        # non-200 response
        except HTTPClientError as e:

            authnzerver_response = e.response

            return AuthnzerverResponse(
                False,
                None,
                [
                    "This request could not be completed.",
                    "There was a problem communicating with the auth server.",
                ],
                dict(authnzerver_response.headers),
                authnzerver_response.code,
                authnzerver_response.body.decode("utf-8"),
            )

        # handle other exceptions
        except Exception as e:

            return AuthnzerverResponse(
                False,
                None,
                [
                    "This request could not be completed.",
                    "There was a problem communicating with the auth server.",
                ],
                None,
                None,
                "ran into an exception in request to authnzerver: %r" % e,
            )

        finally:
            async_httpclient.close()
