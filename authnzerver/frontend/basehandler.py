#!/usr/bin/env python
# -*- coding: utf-8 -*-
# basehandler.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Sep 2018

'''
This is the handler from which all other request handlers inherit. It knows
how to authenticate a user.

'''

####################
## SYSTEM IMPORTS ##
####################

import logging
import numpy as np
from datetime import datetime, timedelta
import random
from textwrap import dedent as twd
from base64 import b64encode, b64decode
import re

from cryptography.fernet import Fernet, InvalidToken



######################################
## CUSTOM JSON ENCODER FOR FRONTEND ##
######################################

# we need this to send objects with the following types to the frontend:
# - bytes
# - ndarray
# - datetime
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

import tornado.web
from tornado.escape import utf8, native_str
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.web import _time_independent_equals
from tornado import gen
from tornado import httputil

###################
## LOCAL IMPORTS ##
###################

from ..external.cookies import cookies
from ..authnzerver.actions import authnzerver_send_email
from ..authnzerver.authdb import check_role_limits
from ..authnzerver import cache


#######################
## UTILITY FUNCTIONS ##
#######################

def decrypt_response(response_base64, fernetkey):
    '''
    This decrypts the incoming response from authnzerver.

    '''

    frn = Fernet(fernetkey)

    try:

        response_bytes = b64decode(response_base64)
        decrypted = frn.decrypt(response_bytes)
        return json.loads(decrypted)

    except InvalidToken:

        LOGGER.error('invalid response could not be decrypted')
        return None

    except Exception as e:

        LOGGER.exception('could not understand incoming response')
        return None


def encrypt_request(request_dict, fernetkey):
    '''
    This encrypts the outgoing request to authnzerver.

    '''

    frn = Fernet(fernetkey)
    json_bytes = json.dumps(request_dict).encode()
    json_encrypted_bytes = frn.encrypt(json_bytes)
    request_base64 = b64encode(json_encrypted_bytes)
    return request_base64


########################
## BASE HANDLER CLASS ##
########################

class BaseHandler(tornado.web.RequestHandler):

    normal_account_box = twd('''\
    <div class="user-signin-box">
    <a class="nav-item nav-link"
    title="Sign in to your user account"
    href="/users/login">
    Sign in
    </a>
    </div>
    <div class="user-signup-box">
    <a class="nav-item nav-link"
    title="Sign up for a user account"
    href="/users/new">
    Sign up
    </a>
    </div>
    ''')


    nosignup_account_box = twd('''\
    <div class="user-signin-box">
    <a class="nav-item nav-link"
    title="Sign in to your user account"
    href="/users/login">
    Sign in
    </a>
    </div>
    ''')


    admin_account_box = twd('''\
    <div class="superuser-admin-box">
    <a class="nav-item nav-link admin-portal-link"
    title="Admin portal"
    href="/admin">
    Admin
    </a>
    </div>
    <div class="user-prefs-box">
    <a class="nav-item nav-link user-prefs-link"
    title="Change user preferences"
    href="/users/home">
    {current_user}
    </a>
    </div>
    <div class="user-signout-box">
    <button type="submit" class="btn btn-secondary btn-sm">
    Sign out
    </button>
    </div>
    ''')


    signedin_account_box = twd('''\
    <div class="user-prefs-box">
    <a class="nav-item nav-link user-prefs-link"
    title="Change user preferences"
    href="/users/home">
    {current_user}
    </a>
    </div>
    <div class="user-signout-box">
    <button type="submit" class="btn btn-secondary btn-sm">
    Sign out
    </button>
    </div>
    ''')


    def initialize(self,
                   authnzerver,
                   fernetkey,
                   executor,
                   session_expiry,
                   siteinfo,
                   ratelimit,
                   cachedir):
        '''
        This just sets up some stuff.

        '''

        self.authnzerver = authnzerver
        self.fernetkey = fernetkey
        self.ferneter = Fernet(fernetkey)
        self.executor = executor
        self.session_expiry = session_expiry
        self.httpclient = AsyncHTTPClient(force_instance=True)
        self.siteinfo = siteinfo
        self.ratelimit = ratelimit
        self.cachedir = cachedir

        # initialize this to None
        # we'll set this later in self.prepare()
        self.current_user = None

        # apikey verification info
        self.apikey_verified = False
        self.apikey_info = None



    def save_flash_messages(self, messages, alert_type):
        '''
        This saves the flash messages to a secure cookie.

        '''

        if isinstance(messages,list):

            outmsg = json.dumps({
                'text':messages,
                'type':alert_type
            })

        elif isinstance(messages,str):

            outmsg = json.dumps({
                'text':[messages],
                'type':alert_type
            })

        else:
            outmsg = ''

        self.set_secure_cookie(
            'server_messages',
            outmsg,
            httponly=True,
            secure=self.csecure,
            samesite='lax',
        )


    def render_flash_messages(self,
                              message_now_text=None,
                              message_now_type=None):
        '''
        This renders any flash messages to a Bootstrap alert.

        alert_type is one of: warning, danger, info, primary, secondary, success

        '''

        if getattr(self, 'flash_messages', None) and self.flash_messages:

            messages = json.loads(self.flash_messages)
            message_text = messages['text']
            alert_type = messages['type']

            flash_msg = twd(
                '''\
                <div class="mt-2 alert alert-{alert_type}
                alert-dismissible fade show" role="alert">
                {flash_messages}
                <button type="button"
                class="close" data-dismiss="alert" aria-label="Close">
                <span aria-hidden="true">&times;</span>
                </button>
                </div>'''.format(
                    flash_messages='<br>'.join(message_text),
                    alert_type=alert_type,
                )
            )
            return flash_msg

        elif message_now_text is not None and message_now_type is not None:

            flash_msg = twd(
                '''\
                <div class="mt-2 alert alert-{alert_type}
                alert-dismissible fade show" role="alert">
                {flash_messages}
                <button type="button"
                class="close" data-dismiss="alert" aria-label="Close">
                <span aria-hidden="true">&times;</span>
                </button>
                </div>'''.format(
                    flash_messages=message_now_text,
                    alert_type=message_now_type,
                )
            )
            return flash_msg

        else:
            return ''


    def render_blocked_message(self):
        '''
        This renders the template indicating that the user is blocked.

        '''
        self.set_status(403)
        self.render(
            'errorpage.html',
            error_message=(
                "Sorry, it appears that you're not authorized to "
                "view the page you were trying to get to. "
                "If you believe this is in error, please contact "
                "the admins of this LCC-Server instance."
            ),
            page_title="403 - You cannot access this page.",
            siteinfo=self.siteinfo,
        )


    def render_user_account_box(self):
        '''
        This renders the user login/logout box.

        '''

        current_user = self.current_user

        # the user is not logged in - so the anonymous session is in play
        if current_user and current_user['user_role'] == 'anonymous':

            user_account_box = self.normal_account_box


        # normal authenticated user
        elif current_user and current_user['user_role'] == 'authenticated':

            user_account_box = self.signedin_account_box.format(
                current_user=current_user['email']
            )

        # super users and staff
        elif current_user and current_user['user_role'] in ('superuser',
                                                            'staff'):

            user_account_box = self.admin_account_box.format(
                current_user=current_user['email']
            )

        # anything else will be shown the usual box because either the user is
        # locked or this is a complete new session
        else:

            user_account_box = self.normal_account_box

        return user_account_box



    def set_cookie(self, name, value, domain=None, expires=None, path="/",
                   expires_days=None, **kwargs):
        """Sets an outgoing cookie name/value with the given options.

        Newly-set cookies are not immediately visible via `get_cookie`;
        they are not present until the next request.

        expires may be a numeric timestamp as returned by `time.time`,
        a time tuple as returned by `time.gmtime`, or a
        `datetime.datetime` object.

        Additional keyword arguments are set on the cookies.Morsel
        directly.

        https://docs.python.org/3/library/http.cookies.html#http.cookies.Morsel

        ---

        Taken from Tornado's web module:

        https://github.com/tornadoweb/tornado/blob/
        627eafb3ce21a777981c37a5867b5f1956a4dc16/tornado/web.py#L528

        The main reason for bundling this in here is to allow use of the
        SameSite attribute for cookies via our vendored cookies library.

        """
        # The cookie library only accepts type str, in both python 2 and 3
        name = native_str(name)
        value = native_str(value)
        if re.search(r"[\x00-\x20]", name + value):
            # Don't let us accidentally inject bad stuff
            raise ValueError("Invalid cookie %r: %r" % (name, value))
        if not hasattr(self, "_new_cookie"):
            self._new_cookie = cookies.SimpleCookie()
        if name in self._new_cookie:
            del self._new_cookie[name]
        self._new_cookie[name] = value
        morsel = self._new_cookie[name]
        if domain:
            morsel["domain"] = domain
        if expires_days is not None and not expires:
            expires = datetime.utcnow() + timedelta(
                days=expires_days)
        if expires:
            morsel["expires"] = httputil.format_timestamp(expires)
        if path:
            morsel["path"] = path
        for k, v in kwargs.items():
            if k == 'max_age':
                k = 'max-age'

            # skip falsy values for httponly and secure flags because
            # SimpleCookie sets them regardless
            if k in ['httponly', 'secure'] and not v:
                continue

            morsel[k] = v


    @gen.coroutine
    def authnzerver_request(self,
                            request_type,
                            request_body):
        '''
        This talks to the authnzerver.

        '''

        reqid = random.randint(0,10000)

        req = {'request':request_type,
               'body':request_body,
               'reqid':reqid}

        encrypted_req = yield self.executor.submit(
            encrypt_request,
            req,
            self.fernetkey
        )
        auth_req = HTTPRequest(
            self.authnzerver,
            method='POST',
            body=encrypted_req
        )
        encrypted_resp = yield self.httpclient.fetch(
            auth_req, raise_error=False
        )

        if encrypted_resp.code != 200:

            return False, None, None

        else:

            respdict = yield self.executor.submit(
                decrypt_response,
                encrypted_resp.body,
                self.fernetkey
            )

            success = respdict['success']
            response = respdict['response']
            messages = respdict['response']['messages']

            return success, response, messages



    @gen.coroutine
    def new_session_token(self,
                          user_id=2,
                          expires_days=7,
                          extra_info=None):
        '''
        This is a shortcut function to request a new session token.

        Also sets the server_session cookie.

        '''

        user_agent = self.request.headers.get('User-Agent')
        if not user_agent:
            user_agent = 'no-user-agent'

        # ask authnzerver for a session cookie
        ok, resp, msgs = yield self.authnzerver_request(
            'session-new',
            {'ip_address': self.request.remote_ip,
             'client_header': user_agent,
             'user_id': user_id,
             'expires': (datetime.utcnow() +
                         timedelta(days=expires_days)),
             'extra_info_json':extra_info}
        )

        if ok:

            # get the expiry date from the response
            cookie_expiry = datetime.strptime(
                resp['expires'].replace('Z',''),
                '%Y-%m-%dT%H:%M:%S.%f'
            )
            expires_days = cookie_expiry - datetime.utcnow()
            expires_days = expires_days.days

            LOGGER.info(
                'new session cookie for %s expires at %s, in %s days' %
                (resp['session_token'],
                 resp['expires'],
                 expires_days)
            )

            self.set_secure_cookie(
                'server_session',
                resp['session_token'],
                expires_days=expires_days,
                httponly=True,
                secure=self.csecure,
                samesite='lax',
            )

            return resp['session_token']

        else:

            self.current_user = None
            self.clear_all_cookies()
            LOGGER.error('could not talk to the backend authnzerver. '
                         'Will fail this request.')
            raise tornado.web.HTTPError(statuscode=401)



    @gen.coroutine
    def email_current_user(self,
                           subject,
                           template,
                           items):
        '''
        This sends an email in the background.

        '''

        if (self.siteinfo['email_server'] is not None and
            (self.current_user['user_role'] in
             ('superuser', 'staff', 'authenticated'))):

            formatted_text = template.format(**items)

            email_sent = yield self.executor.submit(
                authnzerver_send_email,
                'Server admin <%s>' % self.siteinfo['email_sender'],
                subject,
                formatted_text,
                [self.current_user['email']],
                self.siteinfo['email_server'],
                self.siteinfo['email_user'],
                self.siteinfo['email_pass']
            )

            return email_sent

        else:

            return False


    @gen.coroutine
    def check_auth_header_apikey(self):
        '''
        This checks the API key.

        '''
        try:

            authorization = self.request.headers.get('Authorization')

            if authorization:

                # this is the key to verify the signature, check against TTL =
                # self.session_expiry, and Fernet decrypt to present to the
                # backend
                key = authorization.split()[1].strip()

                # do the Fernet decrypt using TTL = self.session_expiry
                decrypted_bytes = self.ferneter.decrypt(
                    key.encode(),
                    ttl=self.session_expiry*86400.0
                )

                # if decrypt OK, JSON load the apikey dict
                apikey_dict = json.loads(decrypted_bytes)

                # check if the current ip_address matches the the value stored
                # in the dict. if not, fail this request immediately. if it
                # does, send the dict on to the backend for additional
                # verification.

                ipaddr_ok = (
                    self.request.remote_ip == apikey_dict['ipa']
                )
                apiversion_ok = self.apiversion == apikey_dict['ver']

                # pass dict to the backend
                if ipaddr_ok and apiversion_ok:

                    verify_ok, resp, msgs = yield self.authnzerver_request(
                        'apikey-verify',
                        {'apikey_dict':apikey_dict}
                    )

                    # check if backend agrees it's OK
                    if verify_ok:

                        retdict = {
                            'status':'ok',
                            'message':msgs,
                            'result': apikey_dict
                        }

                        self.apikey_verified = True
                        self.apikey_dict = apikey_dict
                        return retdict

                    else:

                        self.set_status(401)
                        retdict = {
                            'status':'failed',
                            'message':msgs,
                            'result': None
                        }
                        self.apikey_verified = False
                        self.apikey_dict = None
                        return retdict

                # if the key doesn't pass initial verification, fail this
                # request immediately
                else:

                    message = ('Provided API key IP address = %s, '
                               'API version = %s, does not match '
                               'current request IP address = %s or '
                               'the current LCC-Server API version = %s.' %
                               (apikey_dict['ipa'], apikey_dict['ver'],
                                self.request.remote_ip, self.apiversion))

                    LOGGER.error(message)
                    self.set_status(401)
                    retdict = {
                        'status':'failed',
                        'message':(
                            "Your API key appears to be invalid or has expired."
                        ),
                        'result':None
                    }
                    self.apikey_verified = False
                    self.apikey_dict = None
                    return retdict

            else:

                LOGGER.error(
                    'no Authorization header key found for API key auth.'
                )
                retdict = {
                    'status':'failed',
                    'message':('No credentials provided or '
                               'they could not be parsed safely'),
                    'result':None
                }

                self.apikey_verified = False
                self.apikey_dict = None
                self.set_status(401)
                return retdict

        except Exception as e:

            LOGGER.exception('could not verify API key.')
            retdict = {
                'status':'failed',
                'message':'Your API key appears to be invalid or has expired.',
                'result':None
            }

            self.apikey_verified = False
            self.apikey_info = None
            self.set_status(401)
            return retdict



    def tornado_check_xsrf_cookie(self):
        '''This is the original Tornado XSRF token checker.

        From: http://www.tornadoweb.org
              /en/stable/_modules/tornado/web.html
              #RequestHandler.check_xsrf_cookie

        Modified a bit to not immediately raise 403s since we want to return
        JSON all the time.

        '''

        token = (self.get_argument("_xsrf", None) or
                 self.request.headers.get("X-Xsrftoken") or
                 self.request.headers.get("X-Csrftoken"))

        if not token:

            retdict = {
                'status':'failed',
                'message':("'_xsrf' argument missing from POST'"),
                'result':None
            }

            self.set_status(401)
            return retdict

        _, token, _ = self._decode_xsrf_token(token)
        _, expected_token, _ = self._get_raw_xsrf_token()

        if not token:

            retdict = {
                'status':'failed',
                'message':("'_xsrf' argument missing from POST"),
                'result':None
            }

            self.set_status(401)
            return retdict


        if not _time_independent_equals(utf8(token),
                                        utf8(expected_token)):

            retdict = {
                'status':'failed',
                'message':("XSRF cookie does not match POST argument"),
                'result':None
            }

            self.set_status(401)
            return retdict

        else:

            retdict = {
                'status':'ok',
                'message':("Successful XSRF cookie match to POST argument"),
                'result': None
            }
            LOGGER.warning(retdict['message'])
            return retdict



    def check_xsrf_cookie(self):
        '''This overrides the usual Tornado XSRF checker.

        We use this because we want the same endpoint to support POSTs from an
        API or from the browser.

        '''

        xsrf_auth = (self.get_argument("_xsrf", None) or
                     self.request.headers.get("X-Xsrftoken") or
                     self.request.headers.get("X-Csrftoken"))

        if xsrf_auth:

            LOGGER.info('using tornado XSRF auth...')
            self.xsrf_type = 'session'
            self.keycheck = self.tornado_check_xsrf_cookie()

        elif self.request.headers.get("Authorization"):

            LOGGER.info('using API Authorization header auth. '
                        'passing through to the prepare function...')
            self.xsrf_type = 'apikey'

        else:

            LOGGER.info('No Authorization key found in request header.')
            self.xsrf_type = 'unknown'
            self.keycheck = {
                'status':'failed',
                'message':(
                    'Unknown authorization type, neither API key or session.'
                ),
                'result':None
            }



    @gen.coroutine
    def prepare(self):
        '''This async talks to the authnzerver to get info on the current user.

        1. check the server_session cookie and see if it's not expired.

        2. if can get cookie, talk to authnzerver to get the session info and
           populate the self.current_user variable with the session dict.

        3. if cannot get cookie, then ask authnzerver for a new session token by
           giving it the remote_ip, client_header, and an expiry date. set the
           cookie with this session token and set self.current_user variable
           with session dict.

        Using API keys:

        1. If the Authorization: Bearer <token> pattern is present in the
           header, assume that we're using API key authentication.

        2. If using the provided API key, check if it's unexpired and is
           associated with a valid user account.

        3. If it is, go ahead and populate the self.current_user with the user
           information. The API key random token will be used as the
           session_token.

        4. If it's not and we've assumed that we're using the API key method,
           fail the request.

        '''

        # localhost secure cookies over HTTP don't work anymore
        if self.request.remote_ip != '127.0.0.1':
            self.csecure = True
        else:
            self.csecure = False

        # check if there's an authorization header in the request
        authorization = self.request.headers.get('Authorization')

        # if there's no authorization header in the request,
        # we'll assume that we're using normal session tokens
        if not authorization:

            # check the session cookie
            session_token = self.get_secure_cookie(
                'server_session',
                max_age_days=self.session_expiry
            )

            # get the flash messages if any
            self.flash_messages = self.get_secure_cookie(
                'server_messages'
            )
            # clear the server_messages cookie so we can re-use it later
            self.clear_cookie('server_messages')

            # if a session token is found in the cookie, we'll see who it
            # belongs to
            if session_token is not None:

                ok, resp, msgs = yield self.authnzerver_request(
                    'session-exists',
                    {'session_token': session_token}
                )

                # if we found the session successfully, set the current_user
                # attribute for this request
                if ok:

                    self.current_user = resp['session_info']
                    self.user_id = self.current_user['user_id']
                    self.user_role = self.current_user['user_role']

                    if self.ratelimit:

                        # increment the rate counter for this session token
                        reqcount = yield self.executor.submit(
                            cache.cache_increment,
                            session_token,
                            cache_dirname=self.cachedir

                        )

                        # rate limit only after 25 requests have been counted
                        if reqcount > 25:

                            # check the rate for this session token
                            request_rate, keycount, time_zero = (
                                yield self.executor.submit(
                                    cache.cache_getrate,
                                    session_token,
                                    cache_dirname=self.cachedir
                                )
                            )
                            rate_ok = check_role_limits(self.user_role,
                                                        rate_60sec=request_rate)
                            self.request_rate_60sec = request_rate

                        else:
                            rate_ok = True
                            self.request_rate_60sec = reqcount

                        if not rate_ok:

                            LOGGER.error(
                                'session token: %s: current rate = %s exceeds '
                                'their allowed rate for their role = %s'
                                % (session_token,
                                   request_rate,
                                   self.user_role)
                            )
                            self.set_status(429)
                            self.set_header('Retry-After','120')
                            self.write({
                                'status':'failed',
                                'result':{
                                    'rate':self.request_rate_60sec,
                                },
                                'message':(
                                    'You have exceeded your API request rate.'
                                )
                            })
                            raise tornado.web.Finish()

                else:

                    # if the session token provided did not match any existing
                    # session in the DB, we'll clear all the cookies and
                    # redirect the user to us again.
                    self.current_user = None
                    self.clear_all_cookies()

                    # does it make sense to redirect us back to ourselves?
                    # this will actually cause two redirects, one to set new
                    # session cookies and the next one to actually read them

                    # FIXME: this will put clients that don't understand
                    # sessions into an infinite redirect loop. this is
                    # hilarious, but is it OK? wget, curl and requests appear to
                    # smart enough to accept the set-cookie response header
                    self.redirect(self.request.uri)

            # if the session token is not set, then create a new session
            else:

                session_token = yield self.new_session_token(
                    user_id=2,
                    expires_days=self.session_expiry,
                    extra_info={}
                )

                # immediately get back the session object for the current user
                # so we don't have to redirect to get the session info from the
                # cookie
                ok, resp, msgs = yield self.authnzerver_request(
                    'session-exists',
                    {'session_token': session_token}
                )

                # if we found the session successfully, set the current_user
                # attribute for this request
                if ok:

                    self.current_user = resp['session_info']
                    self.user_id = self.current_user['user_id']
                    self.user_role = self.current_user['user_role']

                    if self.ratelimit:

                        # increment the rate counter for this session token. we
                        # just increase the count to 1 since this is the first
                        # time we've seen this user.
                        yield self.executor.submit(
                            cache.cache_increment,
                            session_token,
                            cache_dirname=self.cachedir
                        )

                else:

                    # if the session token provided did not match any existing
                    # session in the DB, we'll clear all the cookies and
                    # redirect the user to us again.
                    self.current_user = None
                    self.clear_all_cookies()

                    # does it make sense to redirect us back to ourselves?
                    # this will actually cause two redirects, one to set new
                    # session cookies and the next one to actually read them

                    # FIXME: this will put clients that don't understand
                    # sessions into an infinite redirect loop. this is
                    # hilarious, but is it OK? wget, curl and requests appear to
                    # smart enough to accept the set-cookie response header
                    self.redirect(self.request.uri)


        # if using the API Key
        else:

            LOGGER.info('checking the API key in prepare function.')

            # check if the API key is valid
            apikey_info = yield self.check_auth_header_apikey()

            if not apikey_info['status'] == 'ok':

                message = apikey_info['message']

                self.keycheck = {
                    'status':'failed',
                    'message': message,
                    'result':None
                }

                self.write({
                    'status':'failed',
                    'message':message,
                    'result':None
                })
                raise tornado.web.Finish()

            # if API key auth succeeds, fill in the current_user dict with info
            # from there
            else:

                message = apikey_info['message']
                self.keycheck = {
                    'status':'ok',
                    'message': message,
                    'result':apikey_info['result']
                }

                #
                # set up the current_user object for this API key request
                #

                user_agent = self.request.headers.get('User-Agent')
                if not user_agent:
                    user_agent = 'no-user-agent'

                # - user_id
                # - email
                # - is_active
                # - user_role
                # - ip_address <- get from the current self.request
                # - client_header <- get from the current self.request
                # - session_token <- set this to the API key itself
                # - created <- set this to the API key created time
                # - expires <- set this to the API key expiry time
                self.current_user = {
                    'user_id':self.apikey_dict['uid'],
                    'email':None,
                    'is_active':True,
                    'user_role':self.apikey_dict['rol'],
                    'ip_address':self.request.remote_ip,
                    'client_header':user_agent,
                    'session_token':self.apikey_dict['tkn'],
                    'created':self.apikey_dict['iat'],
                    'expires':self.apikey_dict['exp'],
                }
                self.user_id = self.current_user['user_id']
                self.user_role = self.current_user['user_role']

                if self.ratelimit:

                    # increment the rate counter for this session token
                    reqcount = yield self.executor.submit(
                        cache.cache_increment,
                        self.apikey_dict['tkn'],
                        cache_dirname=self.cachedir

                    )

                    # rate limit only after 25 requests have been counted
                    if reqcount > 25:

                        # check the rate for this session token
                        request_rate, keycount, time_zero = (
                            yield self.executor.submit(
                                cache.cache_getrate,
                                self.apikey_dict['tkn'],
                                cache_dirname=self.cachedir
                            )
                        )
                        rate_ok = check_role_limits(self.user_role,
                                                    rate_60sec=request_rate)

                        self.request_rate_60sec = request_rate

                    else:
                        rate_ok = True
                        self.request_rate_60sec = reqcount

                    if not rate_ok:

                        LOGGER.error(
                            'API key: %s: current rate = %s exceeds '
                            'their allowed rate for their role = %s. '
                            'total reqs = %s, time_zero = %s'
                            % (self.apikey_dict['tkn'],
                               request_rate,
                               self.user_role,
                               keycount, time_zero)
                        )
                        self.set_status(429)
                        self.set_header('Retry-After','120')
                        self.write({
                            'status':'failed',
                            'result':{
                                'rate':self.request_rate_60sec,
                            },
                            'message':(
                                'You have exceeded your API request rate.'
                            )
                        })
                        raise tornado.web.Finish()


    def on_finish(self):
        '''
        This just cleans up the httpclient.

        '''

        self.httpclient.close()
