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
from datetime import datetime
import secrets
import time


class FrontendEncoder(json.JSONEncoder):

    def default(self, obj):

        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, bytes):
            return obj.decode()
        elif isinstance(obj, complex):
            return (obj.real, obj.imag)
        else:
            return json.JSONEncoder.default(self, obj)


# this replaces the default encoder and makes it so Tornado will do the right
# thing when it converts dicts to JSON when a
# tornado.web.RequestHandler.write(dict) is called.
json._default_encoder = FrontendEncoder()


################################
## ENCRYPTION RELATED IMPORTS ##
################################

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag


#################################################
## FERNET SYMMETRIC ENCRYPTED MESSAGE HANDLING ##
#################################################

def encrypt_message(message_dict, key):
    '''
    Encrypts a message dict using the Fernet from the PyCA cryptography package.

    Parameters
    ----------

    message_dict : dict
        A dict containing items that will be encrypted.

    key : bytes
        This is a 32-byte encryption key in URL-safe base64 format. Generate one
        using::

            import os, base64
            fernet_key = base64.urlsafe_b64encode(os.urandom(32))

    Returns
    -------

    encrypted_message : bytes
        Returns the encrypted message as base64 encoded bytes.

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
    Decrypts a Fernet-encrypted message back to a message dict.

    Parameters
    ----------

    message : bytes
        The encrypted message to decrypt.

    key : bytes
        This is the 32-byte encryption key in URL-safe base64 format. Must be
        the same one as used for encrypting the message (i.e. this is a
        pre-shared secret key)

    reqid : str or int or None
        A request ID used to track a decryption request. This will appear in any
        logging messages emitted by this function to allow tracking of requests
        and correlation.

    ttl : int or None
        The age in seconds that the encrypted message must not exceed in order
        for it to be considered valid. This is useful for time-stamped
        verification tokens. If None, the message will not be checked for
        expiry.

    Returns
    -------

    message_dict : dict or None
        Returns the decrypted message dict. If the message expired or if the
        message failed to decrypt because of an invalid key or if it was
        tampered with, returns None instead.

    '''

    frn = Fernet(key)

    try:

        response_bytes = b64decode(message)
        decrypted = frn.decrypt(response_bytes, ttl=ttl)
        return json.loads(decrypted)

    except InvalidToken:

        LOGGER.error(
            '%sMessage could not be decrypted because '
            'it is invalid/was tampered with, or has expired.' %
            ('[%s] ' % reqid if reqid else '')
        )
        return None

    except Exception as e:

        LOGGER.error(
            '%sCould not understand encrypted message, '
            ' exception was: %r' % ('[%s] ' % (reqid if reqid else ''), e)
        )
        return None


#################################################
## CHACHA SYMMETRIC ENCRYPTED MESSAGE HANDLING ##
#################################################

CHACHA_VERSION = 1


def chacha_encrypt_message(
        message_dict,
        key,
        nonce=None,
):
    '''
    Encrypts a dict using the ChaCha20-Poly1305 symmetric cipher.

    Parameters
    ----------

    message_dict : dict
        A dict containing items that will be encrypted.

    key : bytes
        This is a 32-byte encryption key. Generate one using::

            import secrets
            key = secrets.token_bytes(32)

    nonce : bytes or None
        This is a 12-byte nonce used for encryption. This MUST NOT be re-used
        with the same key if you want the message to remain secret. If None, a
        random 12-byte value will be used.

    Returns
    -------

    encrypted_message : bytes
        Returns the encrypted message as base64 encoded bytes.

    Notes
    -----

    The encrypted message is generated in the following format::

        <nonce base64><encrypted message dict + ttl AAD in base64>

    '''

    if not nonce:
        nonce = secrets.token_bytes(12)
    elif nonce and len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 nonce must be 96 bits == 12 bytes")

    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 key must be 256 bits == 32 bytes")

    chacha = ChaCha20Poly1305(key)
    current_time = time.time()

    chacha_dict = {'message':message_dict,
                   'iat':current_time,
                   'ver':CHACHA_VERSION}
    message_json_bytes = json.dumps(chacha_dict).encode()
    json_encrypted_bytes = chacha.encrypt(
        nonce,
        message_json_bytes,
        None
    )

    encrypted_message = nonce + json_encrypted_bytes
    message_base64 = b64encode(encrypted_message)
    return message_base64


def chacha_decrypt_message(
        message,
        key,
        reqid=None,
        ttl=None
):
    '''
    Decrypts a ChaCha20-Poly1305-encrypted message back to a message dict.

    Parameters
    ----------

    message : bytes
        The encrypted message to decrypt.

    key : bytes
        This is the 32-byte encryption key. Must be the same one as used for
        encrypting the message (i.e. this is a pre-shared secret key)

    reqid : str or int or None
        A request ID used to track a decryption request. This will appear in any
        logging messages emitted by this function to allow tracking of requests
        and correlation.

    ttl : int or None
        The age in seconds that the encrypted message must not exceed in order
        for it to be considered valid. This is useful for time-stamped
        verification tokens. If None, the message will not be checked for
        expiry.

    Returns
    -------

    message_dict : dict or None
        Returns the decrypted message dict. If the message expired or if the
        message failed to decrypt because of an invalid key or if it was
        tampered with, returns None instead.

    '''

    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 key must be 256 bits == 32 bytes")

    chacha = ChaCha20Poly1305(key)
    current_time = time.time()

    message_bytes = b64decode(message)
    nonce, encrypted_message = message_bytes[:12], message_bytes[12:]

    try:

        decrypted_bytes = chacha.decrypt(nonce, encrypted_message, None)
        chacha_dict = json.loads(decrypted_bytes)

        # check the TTL if requested
        current_time = time.time()

        if ttl is not None and ttl > 0.0:
            if (chacha_dict['iat'] + ttl) < current_time:
                raise InvalidTag

        if chacha_dict['ver'] != CHACHA_VERSION:
            raise InvalidTag

        return chacha_dict['message']

    except InvalidTag:

        LOGGER.error(
            '%sMessage could not be decrypted because '
            'it is invalid/was tampered with, or has expired.' %
            ('[%s] ' % reqid if reqid else '')
        )
        return None

    except Exception as e:

        LOGGER.error(
            '%sCould not understand encrypted message, '
            ' exception was: %r' % ('[%s] ' % (reqid if reqid else ''), e)
        )
        return None
