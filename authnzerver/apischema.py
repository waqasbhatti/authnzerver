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
        "args": [
            {"name": "ip_address", "type": "str"},
            {"name": "user_agent", "type": "str"},
            {"name": "user_id", "type": ("int", "None")},
            {"name": "expires", "type": "str"},
            {"name": "extra_info_json", "type": ("dict", "None")},
        ],
        "kwargs": [
        ],
        # FIXME: maybe implement the permissions layer on API calls this way
        "permissions": {
            "check": False,
            "target": "session",
            "action": "create",
        }
    },
    "session-exists": {
        "args": [
            {"name": "session_token", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "session-delete": {
        "args": [
            {"name": "session_token", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "session-delete-userid": {
        "args": [
            {"name": "session_token", "type": "str"},
            {"name": "user_id", "type": "int"},
            {"name": "keep_current_session", "type": bool},
        ],
        "kwargs": [
        ]
    },
    "user-login": {
        "args": [
            {"name": "session_token", "type": "str"},
            {"name": "email", "type": "str"},
            {"name": "password", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-logout": {
        "args": [
            {"name": "session_token", "type": "str"},
            {"name": "user_id", "type": "int"},
        ],
        "kwargs": [
        ]
    },
    "user-passcheck": {
        "args": [
            {"name": "session_token", "type": "str"},
            {"name": "password", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-passcheck-nosession": {
        "args": [
            {"name": "email", "type": "str"},
            {"name": "password", "type": "str"},

        ],
        "kwargs": [
        ]
    },

    # user actions
    "user-new": {
        "args": [
            {"name": "full_name", "type": "str"},
            {"name": "email", "type": "str"},
            {"name": "password", "type": "str"},
        ],
        "kwargs": [
            {"name": "extra_info", "type": ("dict", "None")},
            {"name": "verify_retry_wait", "type": ("int", "None")}
        ]
    },
    "user-changepass": {
        "args": [
            {"name": "user_id", "type": "int"},
            {"name": "session_token", "type": "str"},
            {"name": "full_name", "type": "str"},
            {"name": "email", "type": "str"},
            {"name": "current_password", "type": "str"},
            {"name": "new_password", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-changepass-nosession": {
        "args": [
            {"name": "user_id", "type": "int"},
            {"name": "full_name", "type": "str"},
            {"name": "email", "type": "str"},
            {"name": "current_password", "type": "str"},
            {"name": "new_password", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-delete": {
        "args": [
            {"name": "email", "type": "str"},
            {"name": "user_id", "type": "int"},
            {"name": "password", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-list": {
        "args": [
            {"name": "user_id", "type": ("int", "None")},
        ],
        "kwargs": [
        ]
    },
    "user-lookup-email": {
        "args": [
            {"name": "email", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-lookup-match": {
        "args": [
            {"name": "by", "type": "str"},
            {"name": "match", "type": "Any"},
        ],
        "kwargs": [
        ]
    },
    "user-edit": {
        "args": [
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
            {"name": "session_token", "type": "str"},
            {"name": "target_userid", "type": "int"},
            {"name": "update_dict", "type": "dict"},
        ],
        "kwargs": [
        ]
    },
    "user-resetpass": {
        "args": [
            {"name": "email_address", "type": "str"},
            {"name": "new_password", "type": "str"},
            {"name": "session_token", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-resetpass-nosession": {
        "args": [
            {"name": "email_address", "type": "str"},
            {"name": "new_password", "type": "str"},
            {"name": "required_active", "type": bool},
        ],
        "kwargs": [
        ]
    },
    "user-lock": {
        "args": [
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
            {"name": "session_token", "type": "str"},
            {"name": "target_userid", "type": "int"},
            {"name": "action", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-validatepass": {
        "args": [
            {"name": "password", "type": "str"},
            {"name": "email", "type": "str"},
            {"name": "full_name", "type": "str"},
            {"name": "min_pass_length", "type": "int"},
            {"name": "max_unsafe_similarity", "type": "int"},
        ],
        "kwargs": [
        ]
    },

    # email actions
    "user-sendemail-signup": {
        "args": [
            {"name": "email_address", "type": "int"},
            {"name": "session_token", "type": "str"},
            {"name": "created_info", "type": "str"},
            {"name": "server_name", "type": "str"},
            {"name": "server_baseurl", "type": "str"},
            {"name": "server_verify_url", "type": "str"},
            {"name": "verification_token", "type": "str"},
            {"name": "verification_expiry", "type": "int"},
        ],
        "kwargs": [
            {"name": "emailuser", "type": ("str", "None")},
            {"name": "emailpass", "type": ("str", "None")},
            {"name": "emailserver", "type": "str"},
            {"name": "emailport", "type": "int"},
            {"name": "emailsender", "type": "str"},
        ]
    },
    "user-sendemail-forgotpass": {
        "args": [
            {"name": "email_address", "type": "int"},
            {"name": "session_token", "type": "str"},
            {"name": "created_info", "type": "str"},
            {"name": "server_name", "type": "str"},
            {"name": "server_baseurl", "type": "str"},
            {"name": "password_forgot_url", "type": "str"},
            {"name": "verification_token", "type": "str"},
            {"name": "verification_expiry", "type": "int"},
        ],
        "kwargs": [
            {"name": "emailuser", "type": ("str", "None")},
            {"name": "emailpass", "type": ("str", "None")},
            {"name": "emailserver", "type": "str"},
            {"name": "emailport", "type": "int"},
            {"name": "emailsender", "type": "str"},
        ]
    },
    "user-set-emailverified": {
        "args": [
            {"name": "email", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-set-emailsent": {
        "args": [
            {"name": "email", "type": "str"},
            {"name": "email_type", "type": "str"},
        ],
        "kwargs": [
        ]
    },

    # apikey actions
    "apikey-new": {
        "args": [
            {"name": "issuer", "type": "str"},
            {"name": "audience", "type": "str"},
            {"name": "subject", "type": "str"},
            {"name": "apiversion", "type": ("str", "int")},
            {"name": "expires_days", "type": "int"},
            {"name": "not_valid_before", "type": ("float", "int")},
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
            {"name": "ip_address", "type": "str"},
            {"name": "user_agent", "type": "str"},
            {"name": "session_token", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-verify": {
        "args": [
            {"name": "apikey_dict", "type": "dict"},
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-revoke": {
        "args": [
            {"name": "apikey_dict", "type": "dict"},
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-new-nosession": {
        "args": [
            {"name": "issuer", "type": "str"},
            {"name": "audience", "type": "str"},
            {"name": "subject", "type": "str"},
            {"name": "apiversion", "type": ("str", "int")},
            {"name": "expires_seconds", "type": "int"},
            {"name": "not_valid_before", "type": ("float", "int")},
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
            {"name": "ip_address", "type": "str"},
            {"name": "refresh_expires", "type": "int"},
            {"name": "refresh_nbf", "type": ("float", "int")},
        ],
        "kwargs": [
        ]
    },
    "apikey-verify-nosession": {
        "args": [
            {"name": "apikey_dict", "type": "dict"},
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-revoke-nosession": {
        "args": [
            {"name": "apikey_dict", "type": "dict"},
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-revokeall-nosession": {
        "args": [
            {"name": "apikey_dict", "type": "dict"},
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-refresh-nosession": {
        "args": [
            {"name": "apikey_dict", "type": "dict"},
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
            {"name": "refresh_token", "type": "str"},
            {"name": "ip_address", "type": "str"},
            {"name": "expires_seconds", "type": "int"},
            {"name": "not_valid_before", "type": ("int", "float")},
            {"name": "refresh_expires", "type": "int"},
            {"name": "refresh_nbf", "type": ("int", "float")},
        ],
        "kwargs": [
        ]
    },

    # access and limit check actions
    "user-check-access": {
        "args": [
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
            {"name": "action", "type": "str"},
            {"name": "target_name", "type": "str"},
            {"name": "target_owner", "type": "int"},
            {"name": "target_visibility", "type": "str"},
            {"name": "target_sharedwith", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-check-limit": {
        "args": [
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
            {"name": "limit_name", "type": "str"},
            {"name": "value_to_check", "type": "Any"},
        ],
        "kwargs": [
        ]
    },

    # actions that should only be used internally by a frontend server, meaning
    # not take or pass along any end-user input
    "internal-user-lock": {
        "args": [
            {"name": "target_userid", "type": "int"},
            {"name": "action", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "internal-user-edit": {
        "args": [
            {"name": "target_userid", "type": "int"},
            {"name": "update_dict", "type": "dict"},
        ],
        "kwargs": [
        ]
    },
    "internal-session-edit": {
        "args": [
            {"name": "target_session_token", "type": "str"},
            {"name": "update_dict", "type": "dict"},
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
