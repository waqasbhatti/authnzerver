#!/usr/bin/env python
# -*- coding: utf-8 -*-
# indexhandlers.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Apr 2018

'''
These are Tornado handlers for the index pages.

'''

####################
## SYSTEM IMPORTS ##
####################

import os
import os.path
import logging
import numpy as np
from datetime import datetime

# for generating encrypted token information
from cryptography.fernet import Fernet


######################################
## CUSTOM JSON ENCODER FOR FRONTEND ##
######################################

# we need this to send objects with the following types to the frontend:
# - bytes
# - ndarray
import json

class FrontendEncoder(json.JSONEncoder):

    def default(self, obj):

        if isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, bytes):
            return obj.decode()
        elif isinstance(obj, complex):
            return (obj.real, obj.imag)
        elif (isinstance(obj, (float, np.float64, np.float_)) and
              not np.isfinite(obj)):
            return None
        elif isinstance(obj, (np.int8, np.int16, np.int32, np.int64)):
            return int(obj)
        else:
            return json.JSONEncoder.default(self, obj)

# this replaces the default encoder and makes it so Tornado will do the right
# thing when it converts dicts to JSON when a
# tornado.web.RequestHandler.write(dict) is called.
json._default_encoder = FrontendEncoder()



#############
## LOGGING ##
#############

# get a logger
LOGGER = logging.getLogger(__name__)



#####################
## TORNADO IMPORTS ##
#####################

import tornado.ioloop
import tornado.httpserver
import tornado.web

from tornado.escape import xhtml_escape
from tornado import gen
from tornado.httpclient import AsyncHTTPClient
import markdown


###################
## LOCAL IMPORTS ##
###################

from .basehandler import BaseHandler



#####################
## MAIN INDEX PAGE ##
#####################

class IndexHandler(BaseHandler):
    '''This handles the index page.

    This page shows the current project.

    '''

    def initialize(self,
                   currentdir,
                   templatepath,
                   assetpath,
                   executor,
                   basedir,
                   siteinfo,
                   authnzerver,
                   session_expiry,
                   fernetkey,
                   ratelimit,
                   cachedir):
        '''
        handles initial setup.

        '''

        self.currentdir = currentdir
        self.templatepath = templatepath
        self.assetpath = assetpath
        self.executor = executor
        self.basedir = basedir
        self.siteinfo = siteinfo
        self.authnzerver = authnzerver
        self.session_expiry = session_expiry
        self.fernetkey = fernetkey
        self.ferneter = Fernet(fernetkey)
        self.httpclient = AsyncHTTPClient(force_instance=True)
        self.ratelimit = ratelimit
        self.cachedir = cachedir



    def get(self):
        '''This handles GET requests to the index page.

        '''

        self.render(
            'index.html',
            flash_messages=self.render_flash_messages(),
            user_account_box=self.render_user_account_box(),
            page_title='viz-inspect',
            siteinfo=self.siteinfo,
            current_user=self.current_user,
        )
