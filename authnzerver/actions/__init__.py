#!/usr/bin/env python
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

from .apikey import (
    issue_new_apikey,
    verify_apikey
)

from .admin import (
    list_users,
    edit_user,
    toggle_user_lock,
    internal_toggle_user_lock,
)

from .email import (
    send_signup_verification_email,
    verify_user_email_address,
    send_forgotpass_verification_email,
    authnzerver_send_email,
)

from .session import (
    auth_session_new,
    auth_session_exists,
    auth_session_set_extrainfo,
    auth_session_delete,
    auth_password_check,
    auth_user_login,
    auth_user_logout,
    auth_kill_old_sessions,
    auth_delete_sessions_userid,
)

from .user import (
    create_new_user,
    change_user_password,
    delete_user,
    verify_password_reset,
)

from .access import check_user_access, check_user_limit
