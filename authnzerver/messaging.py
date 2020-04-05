# -*- coding: utf-8 -*-

'''This module handles the serialization-deserialization of messages between the
authnzerver and any frontends.

'''

#############
## LOGGING ##
#############

import logging
LOGGER = logging.getLogger(__name__)


#############
## IMPORTS ##
#############

import json
from base64 import b64encode, b64decode

################################
## ENCRYPTION RELATED IMPORTS ##
################################

from cryptography.fernet import Fernet, InvalidToken


######################
## MESSAGE HANDLING ##
######################

def encrypt_message(message_dict, key):
    '''
    This encrypts the message using the Fernet scheme.

    '''

    frn = Fernet(key)
    json_bytes = json.dumps(message_dict).encode()
    json_encrypted_bytes = frn.encrypt(json_bytes)
    request_base64 = b64encode(json_encrypted_bytes)
    return request_base64


def decrypt_message(message,
                    key,
                    reqid=None,
                    ttl=None):
    '''
    This decrypts the message using the Fernet scheme.

    '''
    frn = Fernet(key)

    try:

        response_bytes = b64decode(message)
        decrypted = frn.decrypt(response_bytes, ttl=ttl)
        return json.loads(decrypted)

    except InvalidToken:

        LOGGER.error(
            '%sMessage could not be decrypted because '
            'the token is invalid or has expired.' %
            '[%s] ' % (reqid if reqid else '')
        )
        return None

    except Exception as e:

        LOGGER.error(
            '%sCould not understand encrypted message, '
            ' exception was: %r' % ('[%s] ' % (reqid if reqid else ''), e)
        )
        return None
