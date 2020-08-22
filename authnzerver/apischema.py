# -*- coding: utf-8 -*-
# apischema.py - Waqas Bhatti (waqas.afzal.bhatti@gmail.com) - Aug 2020
# License: MIT - see the LICENSE file for the full text.

"""
This contains the API schema for all actions.

"""

#
# this maps request types to their required args, kwargs
#
schema = {

    # session actions
    "session-new": {
        "doc": "Create a new user session.",
        "args": [
            {"name": "ip_address",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "user_agent",
             "doc": "The user agent (browser) of the user.",
             "type": "str"},
            {"name": "user_id",
             "doc": "The user ID of the user. None means an anonymous user.",
             "type": ("int", "None")},
            {"name": "expires",
             "doc": "The datetime (ISO format str) when the session expires.",
             "type": "str"},
            {"name": "extra_info_json",
             "doc": "Arbitrary extra info to store as dict for this session.",
             "type": ("dict", "None")},
        ],
        "kwargs": [
        ],
    },
    "session-exists": {
        "doc": "Check if a session exists, and get its info if it does.",
        "args": [
            {"name": "session_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "session-delete": {
        "doc": "Delete an active session.",
        "args": [
            {"name": "session_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "session-delete-userid": {
        "doc": "Delete all sessions for user_id (optional: skip current).",
        "args": [
            {"name": "session_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "keep_current_session",
             "doc": "The IP address of the user to create a session for.",
             "type": "bool"},
        ],
        "kwargs": [
        ]
    },
    "user-login": {
        "doc": "Process log-in for a user.",
        "args": [
            {"name": "session_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "email",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "password",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-logout": {
        "doc": "Process log-out for a user..",
        "args": [
            {"name": "session_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
        ],
        "kwargs": [
        ]
    },
    "user-passcheck": {
        "doc": "Check the password for a user with an active session.",
        "args": [
            {"name": "session_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "password",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-passcheck-nosession": {
        "doc": "Check the password for a user (no active session required).",
        "args": [
            {"name": "email",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "password",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},

        ],
        "kwargs": [
        ]
    },

    # user actions
    "user-new": {
        "doc": "Create a new user given a full_name, email, and password.",
        "args": [
            {"name": "full_name",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "email",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "password",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
            {"name": "extra_info",
             "doc": "The IP address of the user to create a session for.",
             "type": ("dict", "None")},
            {"name": "verify_retry_wait",
             "doc": "The IP address of the user to create a session for.",
             "type": ("int", "None")}
        ]
    },
    "user-changepass": {
        "doc": "Change the password for a user with an active session.",
        "args": [
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "session_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "full_name",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "email",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "current_password",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "new_password",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-changepass-nosession": {
        "doc": "Change the password for a user (no active session required).",
        "args": [
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "full_name",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "email",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "current_password",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "new_password",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-delete": {
        "doc": "Delete a user.",
        "args": [
            {"name": "email",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "password",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-list": {
        "doc": "Delete a user.",
        "args": [
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": ("int", "None")},
        ],
        "kwargs": [
        ]
    },
    "user-lookup-email": {
        "doc": "Delete a user.",
        "args": [
            {"name": "email",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-lookup-match": {
        "doc": "Delete a user.",
        "args": [
            {"name": "by",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "match",
             "doc": "The IP address of the user to create a session for.",
             "type": "Any"},
        ],
        "kwargs": [
        ]
    },
    "user-edit": {
        "doc": "Delete a user.",
        "args": [
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "session_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "target_userid",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "update_dict",
             "doc": "The IP address of the user to create a session for.",
             "type": "dict"},
        ],
        "kwargs": [
        ]
    },
    "user-resetpass": {
        "doc": "Delete a user.",
        "args": [
            {"name": "email_address",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "new_password",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "session_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-resetpass-nosession": {
        "doc": "Delete a user.",
        "args": [
            {"name": "email_address",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "new_password",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "required_active",
             "doc": "The IP address of the user to create a session for.",
             "type": "bool"},
        ],
        "kwargs": [
        ]
    },
    "user-lock": {
        "doc": "Delete a user.",
        "args": [
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "session_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "target_userid",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "action",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-validatepass": {
        "doc": "Delete a user.",
        "args": [
            {"name": "password",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "email",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "full_name",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "min_pass_length",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "max_unsafe_similarity",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
        ],
        "kwargs": [
        ]
    },

    # email actions
    "user-sendemail-signup": {
        "doc": "Delete a user.",
        "args": [
            {"name": "email_address",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "session_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "created_info",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "server_name",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "server_baseurl",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "server_verify_url",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "verification_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "verification_expiry",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
        ],
        "kwargs": [
            {"name": "emailuser",
             "doc": "The IP address of the user to create a session for.",
             "type": ("str", "None")},
            {"name": "emailpass",
             "doc": "The IP address of the user to create a session for.",
             "type": ("str", "None")},
            {"name": "emailserver",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "emailport",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "emailsender",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ]
    },
    "user-sendemail-forgotpass": {
        "doc": "Delete a user.",
        "args": [
            {"name": "email_address",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "session_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "created_info",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "server_name",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "server_baseurl",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "password_forgot_url",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "verification_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "verification_expiry",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
        ],
        "kwargs": [
            {"name": "emailuser",
             "doc": "The IP address of the user to create a session for.",
             "type": ("str", "None")},
            {"name": "emailpass",
             "doc": "The IP address of the user to create a session for.",
             "type": ("str", "None")},
            {"name": "emailserver",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "emailport",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "emailsender",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ]
    },
    "user-set-emailverified": {
        "doc": "Delete a user.",
        "args": [
            {"name": "email",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-set-emailsent": {
        "doc": "Delete a user.",
        "args": [
            {"name": "email",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "email_type",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },

    # apikey actions
    "apikey-new": {
        "doc": "Delete a user.",
        "args": [
            {"name": "issuer",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "audience",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "subject",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "apiversion",
             "doc": "The IP address of the user to create a session for.",
             "type": ("str", "int")},
            {"name": "expires_days",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "not_valid_before",
             "doc": "The IP address of the user to create a session for.",
             "type": ("float", "int")},
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "ip_address",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "user_agent",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "session_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-verify": {
        "doc": "Delete a user.",
        "args": [
            {"name": "apikey_dict",
             "doc": "The IP address of the user to create a session for.",
             "type": "dict"},
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-revoke": {
        "doc": "Delete a user.",
        "args": [
            {"name": "apikey_dict",
             "doc": "The IP address of the user to create a session for.",
             "type": "dict"},
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-new-nosession": {
        "doc": "Delete a user.",
        "args": [
            {"name": "issuer",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "audience",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "subject",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "apiversion",
             "doc": "The IP address of the user to create a session for.",
             "type": ("str", "int")},
            {"name": "expires_seconds",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "not_valid_before",
             "doc": "The IP address of the user to create a session for.",
             "type": ("float", "int")},
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "ip_address",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "refresh_expires",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "refresh_nbf",
             "doc": "The IP address of the user to create a session for.",
             "type": ("float", "int")},
        ],
        "kwargs": [
        ]
    },
    "apikey-verify-nosession": {
        "doc": "Delete a user.",
        "args": [
            {"name": "apikey_dict",
             "doc": "The IP address of the user to create a session for.",
             "type": "dict"},
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-revoke-nosession": {
        "doc": "Delete a user.",
        "args": [
            {"name": "apikey_dict",
             "doc": "The IP address of the user to create a session for.",
             "type": "dict"},
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-revokeall-nosession": {
        "doc": "Delete a user.",
        "args": [
            {"name": "apikey_dict",
             "doc": "The IP address of the user to create a session for.",
             "type": "dict"},
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-refresh-nosession": {
        "doc": "Delete a user.",
        "args": [
            {"name": "apikey_dict",
             "doc": "The IP address of the user to create a session for.",
             "type": "dict"},
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "refresh_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "ip_address",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "expires_seconds",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "not_valid_before",
             "doc": "The IP address of the user to create a session for.",
             "type": ("int", "float")},
            {"name": "refresh_expires",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "refresh_nbf",
             "doc": "The IP address of the user to create a session for.",
             "type": ("int", "float")},
        ],
        "kwargs": [
        ]
    },

    # access and limit check actions
    "user-check-access": {
        "doc": "Delete a user.",
        "args": [
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "action",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "target_name",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "target_owner",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "target_visibility",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "target_sharedwith",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-check-limit": {
        "doc": "Delete a user.",
        "args": [
            {"name": "user_id",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "limit_name",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "value_to_check",
             "doc": "The IP address of the user to create a session for.",
             "type": "Any"},
        ],
        "kwargs": [
        ]
    },

    # actions that should only be used internally by a frontend server, meaning
    # not take or pass along any end-user input
    "internal-user-lock": {
        "doc": "Delete a user.",
        "args": [
            {"name": "target_userid",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "action",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "internal-user-edit": {
        "doc": "Delete a user.",
        "args": [
            {"name": "target_userid",
             "doc": "The IP address of the user to create a session for.",
             "type": "int"},
            {"name": "update_dict",
             "doc": "The IP address of the user to create a session for.",
             "type": "dict"},
        ],
        "kwargs": [
        ]
    },
    "internal-session-edit": {
        "doc": "Delete a user.",
        "args": [
            {"name": "target_session_token",
             "doc": "The IP address of the user to create a session for.",
             "type": "str"},
            {"name": "update_dict",
             "doc": "The IP address of the user to create a session for.",
             "type": "dict"},
        ],
        "kwargs": [
        ]
    },
}


def apply_typedef(item, typedef):
    """
    This applies isinstance() to item based on typedef.

    """

    if isinstance(typedef, (tuple, list)):
        typedef_strlist = list(typedef)

    elif isinstance(typedef, str):
        typedef_strlist = [typedef]

    else:
        return False

    typedef_ok = []
    for x in typedef_strlist:
        if x == "str":
            typedef_ok.append(isinstance(item, str))
        elif x == "float":
            typedef_ok.append(isinstance(item, float))
        elif x == "int":
            typedef_ok.append(isinstance(item, int))
        elif x == "dict":
            typedef_ok.append(isinstance(item, dict))
        elif x == "list":
            typedef_ok.append(isinstance(item, list))
        elif x == "bool":
            typedef_ok.append(item is True or item is False)
        elif x == "Any":
            typedef_ok.append(item is not None)
        elif x == "None":
            typedef_ok.append(True)
        else:
            typedef_ok.append(False)

    return any(typedef_ok)


def validate_api_request(request_type, request_payload):
    """Validates the incoming request.

    Checks to see if the request_type can be found in the schema, then checks
    its request_payload dict to see if all items required are present and are
    the correct type.

    Returns a 3-element tuple with the first element being True if the request
    successfully validates, False otherwise. The second element in the tuple is
    a list of missing or invalid request payload items for the request type. The
    third element in the tuple is a message.

    """

    if request_type not in schema:

        return (False,
                None,
                f"request '{request_type}' is not a valid request type")

    request_args = schema[request_type]["args"]
    request_kwargs = schema[request_type]["kwargs"]

    invalid_params = []
    request_valid = True

    # check the args first
    for arg in request_args:

        payload_item, payload_type = arg["name"], arg["type"]

        if payload_item not in request_payload:

            invalid_params.append(
                {"param": payload_item,
                 "problem": "missing",
                 "required_type": payload_type,
                 "required_param": True}
            )
            request_valid = False

            # skip to the top of the loop for the next arg check
            continue

        #
        # otherwise, the payload item in the request_payload dict
        # figure out if it's the right type
        #
        typedef_ok = apply_typedef(request_payload[payload_item],
                                   payload_type)
        if not typedef_ok:
            invalid_params.append(
                {"param": payload_item,
                 "problem": "incorrect type",
                 "required_type": payload_type,
                 "required_param": True}
            )
            request_valid = False

    # check the kwargs next
    # check the args first
    for kwarg in request_kwargs:

        payload_item, payload_type = kwarg["name"], kwarg["type"]

        if request_payload.get(payload_item, None):

            typedef_ok = apply_typedef(request_payload[payload_item],
                                       payload_type)
            if not typedef_ok:
                invalid_params.append(
                    {"param": payload_item,
                     "problem": "incorrect type",
                     "required_type": payload_type,
                     "required_param": False}
                )
                request_valid = False

    #
    # return bad if request is not valid
    #
    if not request_valid:
        return (False,
                {"problems": invalid_params},
                f"request '{request_type}' has invalid parameter types")

    #
    # otherwise, the request is valid, return OK
    #
    return (True,
            None,
            f"request '{request_type}' validated successfully")
