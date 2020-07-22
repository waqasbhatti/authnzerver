# -*- coding: utf-8 -*-

"""This module handles generation of various tokens.

"""

#############
## LOGGING ##
#############

import logging
LOGGER = logging.getLogger(__name__)


#############
## IMPORTS ##
#############

import json
from datetime import datetime
from secrets import token_urlsafe

from .jsonencoder import FrontendEncoder
# this replaces the default encoder and makes it so Tornado will do the right
# thing when it converts dicts to JSON when a
# tornado.web.RequestHandler.write(dict) is called.
json._default_encoder = FrontendEncoder()


################################
## ENCRYPTION RELATED IMPORTS ##
################################

from .messaging import encrypt_message, decrypt_message


##################################################
## USER VERIFICATION AND FORGOT PASSWORD TOKENS ##
##################################################

def generate_email_token(
        ip_address,
        user_agent,
        email_address,
        session_token,
        session_cookie_key,
):
    """This generates a token useful for verifying email addresses.

    Also used for forgot-password emails.

    This encodes the user's IP address, user agent, email address, and session
    token into the token generated. The token is encrypted using the Fernet
    scheme and the session cookie (the key used to sign the frontend's cookies)
    to keep things simple.

    """

    token_payload = {
        'iat':datetime.utcnow(),
        'ipa':ip_address,
        'usa':user_agent,
        'ema':email_address,
        'stk':session_token,
        'tid':token_urlsafe(16),
    }

    return encrypt_message(token_payload, session_cookie_key)


def verify_email_token(
        token,
        ip_address,
        user_agent,
        session_token,
        email_address,
        session_cookie_key,
        match_returned_items=('ipa','ema'),
        ttl_seconds=900,
        reqid=None,
):
    """This verifies the token returned by the user.

    By default, it requires that the token be returned no more than 15 minutes
    after it's been issued. It also tries to match the specified items in
    ``match_returned_items`` to the current values provided as args::

        'ipa' -> ip_address
        'usa' -> user_agent
        'stk' -> session_token
        'ema' -> email_address

    """

    decrypted_token = decrypt_message(
        token,
        session_cookie_key,
        ttl=ttl_seconds,
        reqid=reqid,
    )

    # if the decryption or TTL test fails, return False
    if decrypted_token is None:
        return False

    # otherwise, check the items in the token itself
    if isinstance(match_returned_items, (tuple, list)):

        if ('ipa' in match_returned_items and
            ip_address != decrypted_token['ipa']):
            return False

        if ('ema' in match_returned_items and
            email_address != decrypted_token['ema']):
            return False

        if ('usa' in match_returned_items and
            user_agent != decrypted_token['usa']):
            return False

        if ('stk' in match_returned_items and
            session_token != decrypted_token['stk']):
            return False

    # if we make it to here, all is well
    return True
