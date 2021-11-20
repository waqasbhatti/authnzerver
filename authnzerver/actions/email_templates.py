# -*- coding: utf-8 -*-
# email_templates.py - Waqas Bhatti (waqas.afzal.bhatti@gmail.com) - Jul 2020
# License: MIT - see the LICENSE file for the full text.
"""
This contains simple default verification email templates.

"""

SIGNUP_VERIFICATION_EMAIL_SUBJECT = (
    "[{server_name}] Please verify your account sign up request"
)
SIGNUP_VERIFICATION_EMAIL_TEMPLATE = """\
Hello,

This is an automated message from the {server_name} at: {server_baseurl}.

We received an account sign up request for: {user_email}. This request
was made using the browser:

{browser_identifier}

from the IP address: {ip_address}.

Please enter this code:

{verification_code}

into the account verification form at: {server_baseurl}{account_verify_url}

to verify that you made this request. This code will expire on

{verification_expiry}

You will also need to enter your email address and password
to log in.

If you do not recognize the browser and IP address above or did not
initiate this request, someone else may have used your email address
in error. Feel free to ignore this email.

You can see your IP address here: https://www.google.com/search?q=my+ip+address

Thanks,
{server_name} admins
{server_baseurl}
"""


FORGOTPASS_VERIFICATION_EMAIL_SUBJECT = (
    "[{server_name}] Please verify your password reset request"
)
FORGOTPASS_VERIFICATION_EMAIL_TEMPLATE = """\
Hello,

This is an automated message from the {server_name} at: {server_baseurl}.

We received a password reset request for: {user_email}. This request
was initiated using the browser:

{browser_identifier}

from the IP address: {ip_address}.

Please enter this code:

{verification_code}

into the password reset form at: {server_baseurl}{password_forgot_url}

to verify that you made this request. This code will expire on

{verification_expiry}

If you do not recognize the browser and IP address above or did not
initiate this request, someone else may have used your email address
in error. Feel free to ignore this email.

You can see your IP address here: https://www.google.com/search?q=my+ip+address

Thanks,
{server_name} admins
{server_baseurl}
"""


CHANGEPASS_VERIFICATION_EMAIL_SUBJECT = (
    "[{server_name}] Please verify your password change request"
)
CHANGEPASS_VERIFICATION_EMAIL_TEMPLATE = """\
Hello,

This is an automated message from the {server_name} at: {server_baseurl}.

We received a password change request for: {user_email}. This request
was initiated using the browser:

{browser_identifier}

from the IP address: {ip_address}.

Please enter this code:

{verification_code}

into the account verification form at: {server_baseurl}{password_change_url}

to verify that you made this request. This code will expire on

{verification_expiry}

If you do not recognize the browser and IP address above or did not
initiate this request, someone else may have used your email address
in error. Feel free to ignore this email.

You can see your IP address here: https://www.google.com/search?q=my+ip+address

Thanks,
{server_name} admins
{server_baseurl}
"""
