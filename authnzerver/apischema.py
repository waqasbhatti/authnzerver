# -*- coding: utf-8 -*-
# apischema.py - Waqas Bhatti (waqas.afzal.bhatti@gmail.com) - Aug 2020
# License: MIT - see the LICENSE file for the full text.

"""
This contains the API schema for all actions.

"""

from authnzerver.modtools import object_from_string

#
# this maps request types to their required args, kwargs
#
schema = {

    # session actions
    "session-new": {
        "function": "authnzerver.actions.auth_session_new",
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
        "function": "authnzerver.actions.auth_session_exists",
        "doc": "Check if a session exists, and get its info if it does.",
        "args": [
            {"name": "session_token",
             "doc": "The session token to check and return info for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "session-delete": {
        "function": "authnzerver.actions.auth_session_delete",
        "doc": "Delete an active session.",
        "args": [
            {"name": "session_token",
             "doc": "The session token of the session to delete.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "session-delete-userid": {
        "function": "authnzerver.actions.auth_delete_sessions_userid",
        "doc": "Delete all sessions for user_id (optional: skip current).",
        "args": [
            {"name": "session_token",
             "doc": "The current session's session token.",
             "type": "str"},
            {"name": "user_id",
             "doc": "User ID of the user whose sessions will be deleted.",
             "type": "int"},
            {"name": "keep_current_session",
             "doc": "True if the current session should be spared deletion.",
             "type": "bool"},
        ],
        "kwargs": [
        ]
    },
    "user-login": {
        "function": "authnzerver.actions.auth_user_login",
        "doc": "Process log-in for a user.",
        "args": [
            {"name": "session_token",
             "doc": "The session token identifying the session invoking login.",
             "type": "str"},
            {"name": "email",
             "doc": "The email address of the user attempting to login.",
             "type": "str"},
            {"name": "password",
             "doc": "The password of the user attempting to login.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-logout": {
        "function": "authnzerver.actions.auth_user_logout",
        "doc": "Process log-out for a user.",
        "args": [
            {"name": "session_token",
             "doc": "The session token of the user logging out.",
             "type": "str"},
            {"name": "user_id",
             "doc": "The user ID of the user logging out.",
             "type": "int"},
        ],
        "kwargs": [
        ]
    },
    "user-passcheck": {
        "function": "authnzerver.actions.auth_password_check",
        "doc": "Check the password for a user with an active session.",
        "args": [
            {"name": "session_token",
             "doc": "The session token of the user invoking password check.",
             "type": "str"},
            {"name": "password",
             "doc": "The password to check against the stored value.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-passcheck-nosession": {
        "function": "authnzerver.actions.auth_password_check_nosession",
        "doc": "Check the password for a user (no active session required).",
        "args": [
            {"name": "email",
             "doc": "The email address of the user to the check password for.",
             "type": "str"},
            {"name": "password",
             "doc": "The password to check against the stored value.",
             "type": "str"},

        ],
        "kwargs": [
        ]
    },

    # user actions
    "user-new": {
        "function": "authnzerver.actions.create_new_user",
        "doc": "Create a new user given a full_name, email, and password.",
        "args": [
            {"name": "full_name",
             "doc": "The full name of the user creating an account.",
             "type": "str"},
            {"name": "email",
             "doc": "The email address of the user creating an account.",
             "type": "str"},
            {"name": "password",
             "doc": "The password that the user wants to use for login.",
             "type": "str"},
        ],
        "kwargs": [
            {"name": "extra_info",
             "doc": "Dict of arbitrary key-value information about the user.",
             "type": ("dict", "None")},
            {"name": "verify_retry_wait",
             "doc": "Time in hours a user must wait to retry a failed signup.",
             "type": ("int", "None")}
        ]
    },
    "user-changepass": {
        "function": "authnzerver.actions.change_user_password",
        "doc": "Change the password for a user with an active session.",
        "args": [
            {"name": "user_id",
             "doc": "The user ID of the user changing their password.",
             "type": "int"},
            {"name": "session_token",
             "doc": "The session token of an active session of the user.",
             "type": "str"},
            {"name": "full_name",
             "doc": "The full name of the user.",
             "type": "str"},
            {"name": "email",
             "doc": "The email address of the user.",
             "type": "str"},
            {"name": "current_password",
             "doc": "The current password of the user.",
             "type": "str"},
            {"name": "new_password",
             "doc": "The new password the user wants to change to.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-changepass-nosession": {
        "function": "authnzerver.actions.change_user_password_nosession",
        "doc": "Change the password for a user (no active session required).",
        "args": [
            {"name": "user_id",
             "doc": "The user ID of the user changing their password.",
             "type": "int"},
            {"name": "full_name",
             "doc": "The full name of the user.",
             "type": "str"},
            {"name": "email",
             "doc": "The email address of the user.",
             "type": "str"},
            {"name": "current_password",
             "doc": "The current password the user.",
             "type": "str"},
            {"name": "new_password",
             "doc": "The new password the user wants to change to.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-delete": {
        "function": "authnzerver.actions.delete_user",
        "doc": "Delete a user (called by the user themselves).",
        "args": [
            {"name": "email",
             "doc": "Email address of the user that is deleting their account.",
             "type": "str"},
            {"name": "user_id",
             "doc": "User ID of the user being deleted.",
             "type": "int"},
            {"name": "password",
             "doc": "Password of user being deleted to verify deletion action.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-list": {
        "function": "authnzerver.actions.list_users",
        "doc": "Get info for a user with a specific user_id or list all users.",
        "args": [
            {"name": "user_id",
             "doc": "The user ID to look up or None to list all users.",
             "type": ("int", "None")},
        ],
        "kwargs": [
        ]
    },
    "user-lookup-email": {
        "function": "authnzerver.actions.get_user_by_email",
        "doc": "Find a user with the specified email address.",
        "args": [
            {"name": "email",
             "doc": "The email address of the user to look up.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-lookup-match": {
        "function": "authnzerver.actions.lookup_users",
        "doc": "Find a user by arbitrarily matching on their properties.",
        "args": [
            {"name": "by",
             "doc": "A user property to match (must be an existing DB column).",
             "type": "str"},
            {"name": "match",
             "doc": "The property's value to match in the look up.",
             "type": "Any"},
        ],
        "kwargs": [
        ]
    },
    "user-edit": {
        "function": "authnzerver.actions.edit_user",
        "doc": "Edit a user's information.",
        "args": [
            {"name": "user_id",
             "doc": "The user ID of the user initiating the edit.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The role of the user initiating the edit.",
             "type": "str"},
            {"name": "session_token",
             "doc": "The session token of the user initiating the edit.",
             "type": "str"},
            {"name": "target_userid",
             "doc": "The user ID of the user being edited.",
             "type": "int"},
            {"name": "update_dict",
             "doc": "A dict of the user's properties that will be updated.",
             "type": "dict"},
        ],
        "kwargs": [
        ]
    },
    "user-resetpass": {
        "function": "authnzerver.actions.verify_password_reset",
        "doc": "Reset a user's password.",
        "args": [
            {"name": "email_address",
             "doc": "The email address of the user initiating the reset.",
             "type": "str"},
            {"name": "new_password",
             "doc": "The new password that the user wants to use.",
             "type": "str"},
            {"name": "session_token",
             "doc": "The session token of the session tied to the user.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-resetpass-nosession": {
        "function": "authnzerver.actions.verify_password_reset_nosession",
        "doc": "Reset a user's password (no active session required).",
        "args": [
            {"name": "email_address",
             "doc": "The email address of the user initiating the reset.",
             "type": "str"},
            {"name": "new_password",
             "doc": "The new password the user wants.",
             "type": "str"},
            {"name": "required_active",
             "doc": "True if user must be active for password to go through.",
             "type": "bool"},
        ],
        "kwargs": [
        ]
    },
    "user-lock": {
        "function": "authnzerver.actions.toggle_user_lock",
        "doc": "Toggle the locked/unlocked state for a user.",
        "args": [
            {"name": "user_id",
             "doc": "The user ID of the user initiating the lock toggle.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The role of the user initiating the lock toggle.",
             "type": "str"},
            {"name": "session_token",
             "doc": "Session token of active session for the initiating user.",
             "type": "str"},
            {"name": "target_userid",
             "doc": "The user ID of the user whose lock state will be toggled.",
             "type": "int"},
            {"name": "action",
             "doc": "Action to perform for lock state: 'lock' or 'unlock'.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-validatepass": {
        "function": "authnzerver.actions.validate_password",
        "doc": "Make sure a password presented by a user is secure.",
        "args": [
            {"name": "password",
             "doc": "The password that is being tested.",
             "type": "str"},
            {"name": "email",
             "doc": "The user's email address.",
             "type": "str"},
            {"name": "full_name",
             "doc": "The user's full name.",
             "type": "str"},
            {"name": "min_pass_length",
             "doc": "Minimum number of characters needed for password.",
             "type": "int"},
            {"name": "max_unsafe_similarity",
             "doc": "Max allowed similarity between password and unsafe items.",
             "type": "int"},
        ],
        "kwargs": [
        ]
    },

    # email actions
    "user-sendemail-signup": {
        "function": "authnzerver.actions.send_signup_verification_email",
        "doc": ("Send a verification email to a user who has "
                "signed up for a new account."),
        "args": [
            {"name": "email_address",
             "doc": "The email address to send the email to.",
             "type": "int"},
            {"name": "session_token",
             "doc": "The session token of the user making the request.",
             "type": "str"},
            {"name": "created_info",
             "doc": "The returned dict from the user-new API action.",
             "type": "str"},
            {"name": "server_name",
             "doc": "The name of the frontend server to include in the email.",
             "type": "str"},
            {"name": "server_baseurl",
             "doc": "The base URL of the frontend server.",
             "type": "str"},
            {"name": "server_verify_url",
             "doc": ("URL fragment (without base URL) "
                     "for signup verification page."),
             "type": "str"},
            {"name": "verification_token",
             "doc": "The verification token to put in the email.",
             "type": "str"},
            {"name": "verification_expiry",
             "doc": "Time in seconds after which the token expires.",
             "type": "int"},
        ],
        "kwargs": [
            {"name": "emailuser",
             "doc": "User name of the SMTP server account for sending email.",
             "type": ("str", "None")},
            {"name": "emailpass",
             "doc": "Password of SMTP server account for sending email.",
             "type": ("str", "None")},
            {"name": "emailserver",
             "doc": "SMTP server address to use for sending email.",
             "type": "str"},
            {"name": "emailport",
             "doc": "The SMTP port to use for connecting to email server.",
             "type": "int"},
            {"name": "emailsender",
             "doc": "Name and email address of email sender in RFC822 format.",
             "type": "str"},
        ]
    },
    "user-sendemail-forgotpass": {
        "function": "authnzerver.actions.send_forgotpass_verification_email",
        "doc": ("Send a verification email to a user who has "
                "forgotten their password."),
        "args": [
            {"name": "email_address",
             "doc": "The email address to send the email to.",
             "type": "int"},
            {"name": "session_token",
             "doc": "The session token of the user making the request.",
             "type": "str"},
            {"name": "server_name",
             "doc": "The name of the frontend server to include in the email.",
             "type": "str"},
            {"name": "server_baseurl",
             "doc": "The base URL of the frontend server.",
             "type": "str"},
            {"name": "password_forgot_url",
             "doc": ("URL fragment (without base URL) for "
                     "password-reset verification page."),
             "type": "str"},
            {"name": "verification_token",
             "doc": "The verification token to put in the email.",
             "type": "str"},
            {"name": "verification_expiry",
             "doc": "Time in seconds after which the token expires.",
             "type": "int"},
        ],
        "kwargs": [
            {"name": "emailuser",
             "doc": "User name of the SMTP server account for sending email.",
             "type": ("str", "None")},
            {"name": "emailpass",
             "doc": "Password of SMTP server account for sending email.",
             "type": ("str", "None")},
            {"name": "emailserver",
             "doc": "SMTP server address to use for sending email.",
             "type": "str"},
            {"name": "emailport",
             "doc": "The SMTP port to use for connecting to email server.",
             "type": "int"},
            {"name": "emailsender",
             "doc": "Name and email address of email sender in RFC822 format.",
             "type": "str"},
        ]
    },
    "user-set-emailverified": {
        "function": "authnzerver.actions.set_user_emailaddr_verified",
        "doc": "Set the email_verified flag for a newly created user.",
        "args": [
            {"name": "email",
             "doc": "Email address of the user to set the flag for.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-set-emailsent": {
        "function": "authnzerver.actions.set_user_email_sent",
        "doc": "Set the email_sent flags for a user.",
        "args": [
            {"name": "email",
             "doc": "Email address of the user to set the flag for.",
             "type": "str"},
            {"name": "email_type",
             "doc": "The type of email that was sent: 'signup', 'forgotpass'.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },

    # apikey actions
    "apikey-new": {
        "function": "authnzerver.actions.issue_apikey",
        "doc": "Create a new API key tied to a user and session.",
        "args": [
            {"name": "issuer",
             "doc": "Name of entity issuing the API key.",
             "type": "str"},
            {"name": "audience",
             "doc": "The server this API key is meant for.",
             "type": "str"},
            {"name": "subject",
             "doc": "The specific URL endpoint this API key is meant for.",
             "type": "str"},
            {"name": "apiversion",
             "doc": "The version of the API this API key is valid for.",
             "type": ("str", "int")},
            {"name": "expires_days",
             "doc": "Number of days after which the API key expire.",
             "type": "int"},
            {"name": "not_valid_before",
             "doc": "Time in seconds after now after which API key is valid.",
             "type": ("float", "int")},
            {"name": "user_id",
             "doc": "The user ID of the user this API key is tied to.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The role of the user this API key is tied to.",
             "type": "str"},
            {"name": "ip_address",
             "doc": "The IP address of the user this API key is tied to.",
             "type": "str"},
            {"name": "user_agent",
             "doc": "The user agent (browser) of user this API key is tied to.",
             "type": "str"},
            {"name": "session_token",
             "doc": "Session token of active session this API key is tied to.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-verify": {
        "function": "authnzerver.actions.verify_apikey",
        "doc": "Verify the presented API key.",
        "args": [
            {"name": "apikey_dict",
             "doc": "The API key claims to verify.",
             "type": "dict"},
            {"name": "user_id",
             "doc": "User ID of the user presenting the API key.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The role of the user presenting the API key.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-revoke": {
        "function": "authnzerver.actions.revoke_apikey",
        "doc": "Revoke the presented API key.",
        "args": [
            {"name": "apikey_dict",
             "doc": "The claims of the API key being presented.",
             "type": "dict"},
            {"name": "user_id",
             "doc": "The user ID of the user presenting the API key.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The role of the user presenting the API key.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-new-nosession": {
        "function": "authnzerver.actions.issue_apikey_nosession",
        "doc": "Create a new no-session API key.",
        "args": [
            {"name": "issuer",
             "doc": "The entity that will be set as the API key issuer.",
             "type": "str"},
            {"name": "audience",
             "doc": "The service this API key is being issued for.",
             "type": "str"},
            {"name": "subject",
             "doc": "The specific API endpoint URL this API key is valid for.",
             "type": "str"},
            {"name": "apiversion",
             "doc": "The version of the API this API key is valid for.",
             "type": ("str", "int")},
            {"name": "expires_seconds",
             "doc": "Time in seconds after which the API key expires.",
             "type": "int"},
            {"name": "not_valid_before",
             "doc": "Seconds after now after which the API key becomes valid.",
             "type": ("float", "int")},
            {"name": "user_id",
             "doc": "The user ID of the user that will be tied to this key.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The role of the user that will be tied to this key.",
             "type": "str"},
            {"name": "ip_address",
             "doc": "The IP address of the user that will be tied to this key.",
             "type": "str"},
            {"name": "refresh_expires",
             "doc": "Time (in sec) after which API key refresh token expires.",
             "type": "int"},
            {"name": "refresh_nbf",
             "doc": "Seconds after now after which the refresh token is valid.",
             "type": ("float", "int")},
        ],
        "kwargs": [
        ]
    },
    "apikey-verify-nosession": {
        "function": "authnzerver.actions.verify_apikey_nosession",
        "doc": "Verify the presented no-session API key.",
        "args": [
            {"name": "apikey_dict",
             "doc": "The claims of the API key being presented.",
             "type": "dict"},
            {"name": "user_id",
             "doc": "The user ID of the user presenting the API key.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The role of the user presenting the API key.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-revoke-nosession": {
        "function": "authnzerver.actions.revoke_apikey_nosession",
        "doc": "Revoke the presented no-session API key.",
        "args": [
            {"name": "apikey_dict",
             "doc": "The claims of the API key being presented.",
             "type": "dict"},
            {"name": "user_id",
             "doc": "The user ID of the user presenting the API key.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The role of the user presenting the API key.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-revokeall-nosession": {
        "function": "authnzerver.actions.revoke_all_apikeys_nosession",
        "doc": "Revoke all keys tied to presented no-session API key claims.",
        "args": [
            {"name": "apikey_dict",
             "doc": "The claims of the API key being presented.",
             "type": "dict"},
            {"name": "user_id",
             "doc": "The user ID of the user presenting the API key.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The role of the user presenting the API key.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "apikey-refresh-nosession": {
        "function": "authnzerver.actions.refresh_apikey_nosession",
        "doc": "Refresh the presented no-session API key.",
        "args": [
            {"name": "apikey_dict",
             "doc": "The existing API key's claims as a dict.",
             "type": "dict"},
            {"name": "user_id",
             "doc": "The user ID of the user presenting the existing API key.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The role of the user.",
             "type": "str"},
            {"name": "refresh_token",
             "doc": "The refresh token of the API key being presented.",
             "type": "str"},
            {"name": "ip_address",
             "doc": "The IP address of the user presenting the API key.",
             "type": "str"},
            {"name": "expires_seconds",
             "doc": "The new API key's expiry time in seconds from now.",
             "type": "int"},
            {"name": "not_valid_before",
             "doc": "Time in seconds after which the new key becomes valid.",
             "type": ("int", "float")},
            {"name": "refresh_expires",
             "doc": "The new API key's refresh token expiry time in seconds.",
             "type": "int"},
            {"name": "refresh_nbf",
             "doc": "The new key's refresh token not-valid-before time in sec.",
             "type": ("int", "float")},
        ],
        "kwargs": [
        ]
    },

    # access and limit check actions
    "user-check-access": {
        "function": "authnzerver.actions.check_user_access",
        "doc": ("Check if an action can be performed on a resource based "
                "on the permissions policy."),
        "args": [
            {"name": "user_id",
             "doc": "The user_id of the user to check access for.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The role of the user.",
             "type": "str"},
            {"name": "action",
             "doc": "The action being performed on the resource.",
             "type": "str"},
            {"name": "target_name",
             "doc": "The name of the resource the user is acting on.",
             "type": "str"},
            {"name": "target_owner",
             "doc": "The user_id of the resource's owner.",
             "type": "int"},
            {"name": "target_visibility",
             "doc": "The visibility status of the resource.",
             "type": "str"},
            {"name": "target_sharedwith",
             "doc": "A CSV string of user_ids the resource is shared with.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "user-check-limit": {
        "function": "authnzerver.actions.check_user_limit",
        "doc": "Check a permissions policy limit for a user.",
        "args": [
            {"name": "user_id",
             "doc": "The user_id of the user to check limit for.",
             "type": "int"},
            {"name": "user_role",
             "doc": "The role of the user.",
             "type": "str"},
            {"name": "limit_name",
             "doc": "The name of the permissions policy limit.",
             "type": "str"},
            {"name": "value_to_check",
             "doc": "The value to check against the limit definition.",
             "type": "Any"},
        ],
        "kwargs": [
        ]
    },

    # actions that should only be used internally by a frontend server, meaning
    # not take or pass along any end-user input
    "internal-user-lock": {
        "function": "authnzerver.actions.internal_toggle_user_lock",
        "doc": "Toggle a lock/unlock for a user.",
        "args": [
            {"name": "target_userid",
             "doc": "The user_id of the user to lock/unlock.",
             "type": "int"},
            {"name": "action",
             "doc": "The toggle action to take, one of 'lock', 'unlock'.",
             "type": "str"},
        ],
        "kwargs": [
        ]
    },
    "internal-user-delete": {
        "function": "authnzerver.actions.internal_delete_user",
        "doc": "Delete a user.",
        "args": [
            {"name": "target_userid",
             "doc": "The user_id of the user to delete.",
             "type": "int"},
        ],
        "kwargs": [
        ]
    },
    "internal-user-edit": {
        "function": "authnzerver.actions.internal_edit_user",
        "doc": "Edit a user's information.",
        "args": [
            {"name": "target_userid",
             "doc": "The user_id of the user to edit.",
             "type": "int"},
            {"name": "update_dict",
             "doc": "The dict to use for updating the user's information.",
             "type": "dict"},
        ],
        "kwargs": [
        ]
    },
    "internal-session-edit": {
        "function": "authnzerver.actions.internal_edit_session",
        "doc": "Edit an active session's extra_info_json dict.",
        "args": [
            {"name": "target_session_token",
             "doc": "The session token of the session to edit.",
             "type": "str"},
            {"name": "update_dict",
             "doc": "The dict to use when updating extra_info_json.",
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


def validate_and_get_function(request_type, request_payload):
    """Validates the request and returns the function needed to fulfill it.

    Checks to see if the request_type can be found in the schema, then checks
    its request_payload dict to see if all items required are present and are
    the correct type.

    Returns a 3-element tuple with the first element being the function name if
    successfully validates, None otherwise. The second element in the tuple is a
    list of missing or invalid request payload items for the request type. The
    third element in the tuple is a message.

    """

    # validate the request
    request_ok, problems, message = validate_api_request(request_type,
                                                         request_payload)

    if request_ok:
        return (
            object_from_string(schema[request_type]['function']),
            problems,
            message
        )
    else:
        return (None, problems, message)
