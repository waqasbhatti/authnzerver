# -*- coding: utf-8 -*-
# apischema.py - Waqas Bhatti (waqas.afzal.bhatti@gmail.com) - Aug 2020
# License: MIT - see the LICENSE file for the full text.

"""
This contains the API schema for all actions.

"""

from . import actions

#
# this maps request types -> request functions to execute
#
schema = {

    # session actions
    "session-new": {
        "function": actions.auth_session_new,
        "args": [
            {"name": "ip_address", "type": "str"},
            {"name": "user_agent", "type": "str"},
            {"name": "user_id", "type": ("int", "none")},
            {"name": "expires", "type": "str"},
            {"name": "extra_info_json", "type": ("dict", "none")},
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
        "function": actions.auth_session_exists,
        "args": [
            {"name": "session_token", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "session-delete": {
        "function": actions.auth_session_delete,
        "args": [
            {"name": "session_token", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "session-delete-userid": {
        "function": actions.auth_delete_sessions_userid,
        "args": [
            {"name": "session_token", "type": "str"},
            {"name": "user_id", "type": "int"},
            {"name": "keep_current_session", "type": bool},
        ],
        "kwargs": [
        ]
    },
    "user-login": {
        "function": actions.auth_user_login,
        "args": [
            {"name": "session_token", "type": "str"},
            {"name": "email", "type": "str"},
            {"name": "password", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-logout": {
        "function": actions.auth_user_logout,
        "args": [
            {"name": "session_token", "type": "str"},
            {"name": "user_id", "type": "int"},
        ],
        "kwargs": [
        ]
    },
    "user-passcheck": {
        "function": actions.auth_password_check,
        "args": [
            {"name": "session_token", "type": "str"},
            {"name": "password", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-passcheck-nosession": {
        "function": actions.auth_password_check_nosession,
        "args": [
            {"name": "email", "type": "str"},
            {"name": "password", "type": "str"},

        ],
        "kwargs": [
        ]
    },

    # user actions
    "user-new": {
        "function": actions.create_new_user,
        "args": [
            {"name": "full_name", "type": "str"},
            {"name": "email", "type": "str"},
            {"name": "password", "type": "str"},
            {"name": "etra_info", "type": ("dict", "none")},
            {"name": "verify_retry_wait", "type": ("int", "none")}
        ],
        "kwargs": [
        ]
    },
    "user-changepass": {
        "function": actions.change_user_password,
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
        "function": actions.change_user_password_nosession,
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
        "function": actions.delete_user,
        "args": [
            {"name": "email", "type": "str"},
            {"name": "user_id", "type": "int"},
            {"name": "password", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-list": {
        "function": actions.list_users,
        "args": [
            {"name": "user_id", "type": ("int", "none")},
        ],
        "kwargs": [
        ]
    },
    "user-lookup-email": {
        "function": actions.get_user_by_email,
        "args": [
            {"name": "email", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-lookup-match": {
        "function": actions.lookup_users,
        "args": [
            {"name": "by", "type": "str"},
            {"name": "match", "type": "any"},
        ],
        "kwargs": [
        ]
    },
    "user-edit": {
        "function": actions.edit_user,
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
        "function": actions.verify_password_reset,
        "args": [
            {"name": "email_address", "type": "str"},
            {"name": "new_password", "type": "str"},
            {"name": "session_token", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-resetpass-nosession": {
        "function": actions.verify_password_reset_nosession,
        "args": [
            {"name": "email_address", "type": "str"},
            {"name": "new_password", "type": "str"},
            {"name": "required_active", "type": bool},
        ],
        "kwargs": [
        ]
    },
    "user-lock": {
        "function": actions.toggle_user_lock,
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
        "function": actions.validate_password,
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
        "function": actions.send_signup_verification_email,
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
            {"name": "emailuser", "type": ("str", "none")},
            {"name": "emailpass", "type": ("str", "none")},
            {"name": "emailserver", "type": "str"},
            {"name": "emailport", "type": "int"},
            {"name": "emailsender", "type": "str"},
        ]
    },
    "user-sendemail-forgotpass": {
        "function": actions.send_forgotpass_verification_email,
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
            {"name": "emailuser", "type": ("str", "none")},
            {"name": "emailpass", "type": ("str", "none")},
            {"name": "emailserver", "type": "str"},
            {"name": "emailport", "type": "int"},
            {"name": "emailsender", "type": "str"},
        ]
    },
    "user-set-emailverified": {
        "function": actions.set_user_emailaddr_verified,
        "args": [
            {"name": "email", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-set-emailsent": {
        "function": actions.set_user_email_sent,
        "args": [
            {"name": "email", "type": "str"},
            {"name": "email_type", "type": "str"},
        ],
        "kwargs": [
        ]
    },

    # apikey actions
    "apikey-new": {
        "function": actions.issue_apikey,
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
        "function": actions.verify_apikey,
        "args": [
            {"name": "apikey_dict", "type": "dict"},
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-revoke": {
        "function": actions.revoke_apikey,
        "args": [
            {"name": "apikey_dict", "type": "dict"},
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-new-nosession": {
        "function": actions.issue_apikey_nosession,
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
        "function": actions.verify_apikey_nosession,
        "args": [
            {"name": "apikey_dict", "type": "dict"},
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-revoke-nosession": {
        "function": actions.revoke_apikey_nosession,
        "args": [
            {"name": "apikey_dict", "type": "dict"},
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-revokeall-nosession": {
        "function": actions.revoke_all_apikeys_nosession,
        "args": [
            {"name": "apikey_dict", "type": "dict"},
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-refresh-nosession": {
        "function": actions.refresh_apikey_nosession,
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
        "function": actions.check_user_access,
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
        "function": actions.check_user_limit,
        "args": [
            {"name": "user_id", "type": "int"},
            {"name": "user_role", "type": "str"},
            {"name": "limit_name", "type": "str"},
            {"name": "value_to_check", "type": "any"},
        ],
        "kwargs": [
        ]
    },

    # actions that should only be used internally by a frontend server, meaning
    # not take or pass along any end-user input
    "internal-user-lock": {
        "function": actions.internal_toggle_user_lock,
        "args": [
            {"name": "target_userid", "type": "int"},
            {"name": "action", "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "internal-user-edit": {
        "function": actions.internal_edit_user,
        "args": [
            {"name": "target_userid", "type": "int"},
            {"name": "update_dict", "type": "dict"},
        ],
        "kwargs": [
        ]
    },
    "internal-session-edit": {
        "function": actions.internal_edit_session,
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
        elif x == "bool":
            typedef_ok.append(item is True or item is False)
        elif x == "any":
            typedef_ok.append(item is not None)
        elif x == "none":
            typedef_ok.append(True)
        else:
            typedef_ok.append(False)

    return any(typedef_ok)


def validate_api_request(request_type,
                         request_payload):
    """Validates the incoming request.

    Checks to see if the request_type can be found in the schema, then checks
    its request_payload dict to see if all items required are present and are
    the correct type.

    Returns a 3-element tuple with the first element being the function name if
    successfully validates, None otherwise. The second element in the tuple is a
    list of missing or invalid request payload items for the request type. The
    third element in the tuple is a message.

    """

    if request_type not in schema:
        return (None,
                None,
                f"request '{request_type}' is not a valid request type")

    request_args = schema[request_type]["args"]
    request_kwargs = schema[request_type]["kwargs"]
    request_function = schema[request_type]["function"]

    invalid_items = []
    request_valid = True

    # check the args first
    for arg in request_args:

        payload_item, payload_type = arg["name"], arg["type"]

        if payload_item not in request_payload:

            invalid_items.append(
                {"item": payload_item,
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
            invalid_items.append(
                {"item": payload_item,
                 "problem": "incorrect type",
                 "required_type": payload_type,
                 "required_param": True}
            )
            request_valid = False

    # check the kwargs next
    # check the args first
    for kwarg in request_kwargs:

        payload_item, payload_type = kwarg["name"], kwarg["type"]

        typedef_ok = apply_typedef(request_payload[payload_item],
                                   payload_type)
        if not typedef_ok:
            invalid_items.append(
                {"item": payload_item,
                 "problem": "incorrect type",
                 "required_type": payload_type,
                 "required_param": False}
            )
            request_valid = False

    if not request_valid:
        return (None,
                invalid_items,
                f"request '{request_type}' has invalid parameter types")

    #
    # otherwise, the request is valid, return the function
    #
    return (request_function,
            None,
            f"request '{request_type}' validated successfully")
