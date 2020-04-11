# -*- coding: utf-8 -*-
# handlers.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''These are handlers for the authnzerver.

'''

#############
## LOGGING ##
#############

import logging

# get a logger
LOGGER = logging.getLogger(__name__)


#############
## IMPORTS ##
#############

import json
from datetime import datetime


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

import ipaddress

import multiprocessing as mp


import tornado.web
import tornado.ioloop

from sqlalchemy.sql import select

from . import authdb
from .messaging import encrypt_message, decrypt_message


#########################
## REQ/RESP VALIDATION ##
#########################

def check_host(remote_ip):
    '''
    This just returns False if the remote_ip != 127.0.0.1

    '''
    try:
        return (ipaddress.ip_address(remote_ip) ==
                ipaddress.ip_address('127.0.0.1'))
    except ValueError:
        return False


def auth_echo(payload):
    '''
    This just echoes back the payload.

    '''

    # this checks if the database connection is live
    currproc = mp.current_process()
    engine = getattr(currproc, 'authdb_engine', None)
    if not engine:
        currproc.authdb_engine, currproc.authdb_conn, currproc.authdb_meta = (
            authdb.get_auth_db(
                currproc.auth_db_path,
                echo=False
            )
        )

    permissions = currproc.authdb_meta.tables['roles']
    s = select([permissions])
    result = currproc.authdb_engine.execute(s)
    # add the result to the outgoing payload
    serializable_result = [dict(x) for x in result]
    payload['dbtest'] = serializable_result
    result.close()

    LOGGER.info('responding from process: %s' % currproc.name)
    return payload


class EchoHandler(tornado.web.RequestHandler):
    '''
    This just echoes back whatever we send.

    Useful to see if the encryption is working as intended.

    '''

    def initialize(self,
                   authdb,
                   fernet_secret,
                   executor):
        '''
        This sets up stuff.

        '''

        self.authdb = authdb
        self.fernet_secret = fernet_secret
        self.executor = executor

    async def post(self):
        '''
        Handles the incoming POST request.

        '''

        ipcheck = check_host(self.request.remote_ip)

        if not ipcheck:
            raise tornado.web.HTTPError(status_code=400)

        payload = decrypt_message(self.request.body,
                                  self.fernet_secret,
                                  'debug-request')
        if not payload:
            raise tornado.web.HTTPError(status_code=401)

        if payload['request'] != 'echo':
            LOGGER.error("this handler can only echo things. "
                         "invalid request: %s" % payload['request'])
            raise tornado.web.HTTPError(status_code=400)

        # if we successfully got past host and decryption validation, then
        # process the request
        try:

            loop = tornado.ioloop.IOLoop.current()
            response_dict = await loop.run_in_executor(
                self.executor,
                auth_echo,
                payload
            )

            if response_dict is not None:
                encrypted_base64 = encrypt_message(
                    response_dict,
                    self.fernet_secret
                )

                self.set_header('content-type','text/plain; charset=UTF-8')
                self.write(encrypted_base64)
                self.finish()

            else:
                raise tornado.web.HTTPError(status_code=401)

        except Exception:

            LOGGER.exception('failed to understand request')
            raise tornado.web.HTTPError(status_code=400)
