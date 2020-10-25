# -*- coding: utf-8 -*-
# apifunctions.py - Waqas Bhatti (waqas.afzal.bhatti@gmail.com) - Aug 2020
# License: MIT - see the LICENSE file for the full text.

"""
This contains functions that map to API actions.

"""

from . import actions

#
# this maps request types -> request functions to execute
#

functions = {
    # session actions
    'session-new': actions.auth_session_new,
    'session-exists': actions.auth_session_exists,
    'session-delete': actions.auth_session_delete,
    'session-delete-userid': actions.auth_delete_sessions_userid,
    'user-login': actions.auth_user_login,
    'user-logout': actions.auth_user_logout,
    'user-passcheck': actions.auth_password_check,
    'user-passcheck-nosession': actions.auth_password_check_nosession,

    # user actions
    'user-new': actions.create_new_user,
    'user-changepass': actions.change_user_password,
    'user-changepass-nosession': actions.change_user_password_nosession,
    'user-delete': actions.delete_user,
    'user-list': actions.list_users,
    'user-lookup-email': actions.get_user_by_email,
    'user-lookup-match': actions.lookup_users,
    'user-edit': actions.edit_user,
    'user-resetpass': actions.verify_password_reset,
    'user-resetpass-nosession': actions.verify_password_reset_nosession,
    'user-lock': actions.toggle_user_lock,
    'user-validatepass': actions.validate_password,

    # email actions
    'user-sendemail-signup': actions.send_signup_verification_email,
    'user-sendemail-forgotpass': actions.send_forgotpass_verification_email,
    'user-set-emailverified': actions.set_user_emailaddr_verified,
    'user-set-emailsent': actions.set_user_email_sent,

    # apikey actions
    'apikey-new': actions.issue_apikey,
    'apikey-verify': actions.verify_apikey,
    'apikey-revoke': actions.revoke_apikey,
    'apikey-new-nosession': actions.issue_apikey_nosession,
    'apikey-verify-nosession': actions.verify_apikey_nosession,
    'apikey-refresh-nosession': actions.refresh_apikey_nosession,
    'apikey-revoke-nosession': actions.revoke_apikey_nosession,
    'apikey-revokeall-nosession': actions.revoke_all_apikeys_nosession,

    # access and limit check actions
    'user-check-access': actions.check_user_access,
    'user-check-limit': actions.check_user_limit,

    # actions that should only be used internally by a frontend server, meaning
    # not take or pass along any end-user input
    'internal-user-lock': actions.internal_toggle_user_lock,
    'internal-user-delete': actions.internal_delete_user,
    'internal-user-edit': actions.internal_edit_user,
    'internal-session-edit': actions.internal_edit_session,
}
