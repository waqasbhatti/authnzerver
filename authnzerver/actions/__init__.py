# -*- coding: utf-8 -*-
# actions.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''
This contains functions to drive auth actions.

'''

#############
## LOGGING ##
#############

import logging

# get a logger
LOGGER = logging.getLogger(__name__)
log_sub = '{'
log_fmt = '[{levelname:1.1} {asctime} {module}:{lineno}] {message}'
log_date_fmt = '%y%m%d %H:%M:%S'
logging.basicConfig(
    level=logging.INFO,
    style=log_sub,
    format=log_fmt,
    datefmt=log_date_fmt,
)


#############
## IMPORTS ##
#############

from .user import (
    create_new_user,
    delete_user,
)

from .session import (
    internal_edit_session,
    auth_session_new,
    auth_session_exists,
    auth_session_delete,
    auth_kill_old_sessions,
    auth_delete_sessions_userid,
)

from .loginlogout import (
    auth_user_login,
    auth_user_logout,
)

from .passwords import (
    validate_password
)

from .passcheck import (
    auth_password_check,
    auth_password_check_nosession,
)

from .passreset import (
    verify_password_reset,
    verify_password_reset_nosession
)

from .passchange import (
    change_user_password,
    change_user_password_nosession,
)

from .apikey import (
    issue_apikey,
    verify_apikey,
    revoke_apikey
)
from .apikey_nosession import (
    issue_apikey as issue_apikey_nosession,
    verify_apikey as verify_apikey_nosession,
    refresh_apikey as refresh_apikey_nosession,
    revoke_apikey as revoke_apikey_nosession,
    revoke_all_apikeys as revoke_all_apikeys_nosession,
)

from .admin import (
    list_users,
    edit_user,
    get_user_by_email,
    lookup_users,
    toggle_user_lock,
    internal_toggle_user_lock,
    internal_edit_user,
)

from .email import (
    send_signup_verification_email,
    set_user_emailaddr_verified,
    set_user_email_sent,
    send_forgotpass_verification_email,
    send_email,
)

from .access import (
    check_user_access,
    check_user_limit
)

from .healthcheck import database_health_check
