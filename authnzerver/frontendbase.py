#!/usr/bin/env python
# -*- coding: utf-8 -*-
# frontendbase.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Sep 2018

'''This is an example Tornado BaseHandler that knows how to authenticate users
and verify API keys using HTTP and the pre-shared secret key to talk to the
authnzerver.

It runs the authentication/authorization workflow in a background
ProcessPoolExecutor or ThreadPoolExecutor.

'''

####################
## SYSTEM IMPORTS ##
####################

import logging
from datetime import datetime, timedelta
import random
from base64 import b64encode, b64decode
import re
from hmac import compare_digest

from cryptography.fernet import Fernet, InvalidToken


######################################
## CUSTOM JSON ENCODER FOR FRONTEND ##
######################################

# we need this to send objects with the following types to the frontend:
# - bytes
# - datetime
import json


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
from tornado import gen
from tornado import httputil


###################
## LOCAL IMPORTS ##
###################

from authnzerver.external.cookies import cookies
from authnzerver.actions import authnzerver_send_email
from authnzerver.authdb import check_role_limits
from authnzerver import cache


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

    except Exception:

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

    def initialize(
            self,
            authnzerver,
            fernetkey,
            executor,
            session_settings,
            api_settings,
            email_settings,
            cachedir,
    ):
        '''
        This just sets up some stuff.

        Parameters
        ----------

        authnzerver : str
            The address of the backend authnzerver to talk to.

        fernetkey : str
            The key to use to encrypt communication between this frontend and
            the backend authnzerver.

        executor : Executor instance
            A concurrent.futures.ProcessPoolExecutor or
            concurrent.futures.ThreadPoolExecutor instance that will run
            background queries to the authnzerver.

        session_settings : dict
            This is a dict containing various session settings::

                {'expiry_days': number of days after which user sessions expire,
                 'cookie_name': the name of the cookie to use for sessions,
                 'cookie_secure': whether the session cookie has secure=true}

        api_settings : dict
            This is a dict containing various API settings::

                {'maxrate_60sec': number of requests allowed per 60 seconds,
                 'version': the API version to match against for requests,
                 'expiry_days': the number of days an API key is valid for,
                 'issuer': the API key issuer to match against}

        email_settings : dict
            This is a dict containing various email server settings::

                {'email_server': the address of the email server to use,
                 'email_port': the SMTP port of the email server,
                 'email_user': the SMTP user name to use to login,
                 'email_pass': the SMTP password to use to login}

        cachedir : str
            The directory to be used for the cache and rate-limit data.

        '''

        self.authnzerver = authnzerver
        self.fernetkey = fernetkey
        self.ferneter = Fernet(fernetkey)
        self.executor = executor
        self.httpclient = AsyncHTTPClient(force_instance=True)

        self.cachedir = cachedir
        self.email_settings = email_settings

        self.session_expiry = session_settings['expiry_days']
        self.session_cookie_name = session_settings['cookie_name']
        self.session_cookie_secure = session_settings['cookie_secure']

        self.apikey_apiversion = api_settings['version']
        self.apikey_expiry = api_settings['expiry_days']
        self.apikey_issuer = api_settings['issuer']
        self.ratelimit = api_settings['maxrate_60sec']

        # initialize this to None
        # we'll set this later in self.prepare()
        self.current_user = None

        # apikey verification info
        self.apikey_verified = False
        self.apikey_dict = None

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
    def authnzerver_request(self, request_type, request_body):
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
    def new_session_token(self, user_id, expires_days=None, extra_info=None):
        '''
        This is a shortcut function to request a new session token.

        Also sets the session cookie.

        '''

        if not expires_days:
            expires_days = self.session_expiry

        user_agent = self.request.headers.get('User-Agent')
        if not user_agent or len(user_agent.strip()) == 0:
            user_agent = 'no-user-agent'

        # ask authnzerver for a session cookie
        ok, resp, msgs = yield self.authnzerver_request(
            'session-new',
            {'ip_address': self.request.remote_ip,
             'user_agent': user_agent,
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
                self.session_cookie_name,
                resp['session_token'],
                expires_days=expires_days,
                httponly=True,
                secure=self.session_cookie_secure,
                samesite='lax',
            )

            return resp['session_token']

        else:

            self.current_user = None
            self.clear_all_cookies()
            LOGGER.error('Could not talk to the backend authnzerver. '
                         'Will fail this request.')
            raise tornado.web.HTTPError(statuscode=401)

    @gen.coroutine
    def email_current_user(self,
                           sender_name_address,
                           email_subject,
                           email_body):
        '''This sends an email to the current user.

        You must provide a dict called email_settings to the BaseHandler's
        constructor for this function to work properly. This will look something
        like::

                {'email_server': the address of the email server to use,
                 'email_port': the SMTP port of the email server,
                 'email_user': the SMTP user name to use to login,
                 'email_pass': the SMTP password to use to login}

        Parameters
        ----------

        sender_name_address : str
            This is the email sender string to use in the usual form::

                "Sender Name <sender@email.example.org>"

        email_subject : str
            The subject of the email message.

        email_body : str
            The body of the email message.

        Returns
        -------

        bool:
            If message sending succeeded, will return True, otherwise False.

        '''

        if (self.email_settings['email_server'] is not None and
            (self.current_user['user_role'] in
             ('superuser', 'staff', 'authenticated'))):

            email_sent = yield self.executor.submit(
                authnzerver_send_email,
                sender_name_address,
                email_subject,
                email_body,
                [self.current_user['email']],
                self.email_settings['email_server'],
                self.email_settings['email_user'],
                self.email_settings['email_pass'],
                port=self.email_settings['email_port']
            )
            return email_sent

        else:
            return False

    @gen.coroutine
    def check_auth_header_apikey(self):
        '''
        This checks the API key provided in the header of the HTTP request.

        '''
        try:

            authorization = self.request.headers.get('Authorization')

            if authorization:

                # this is the key to verify the signature, check against TTL =
                # self.session_expiry, and Fernet decrypt to present to the
                # backend
                key = authorization.split()[1].strip()

                # do the Fernet decrypt using TTL = self.apikey_expiry
                decrypted_bytes = self.ferneter.decrypt(
                    key.encode(),
                    ttl=self.apikey_expiry*86400.0
                )

                # if decrypt OK, JSON load the apikey dict
                apikey_dict = json.loads(decrypted_bytes)

                # check if the current ip_address matches the the value stored
                # in the dict. if not, fail this request immediately. if it
                # does, send the dict on to the backend for additional
                # verification.

                # check the apikey IP address against the current one
                ipaddr_ok = (
                    self.request.remote_ip == apikey_dict['ipa']
                )

                # check the apikey version against the current one
                apiversion_ok = self.apikey_apiversion == apikey_dict['ver']

                # check the apikey audience against the host of our server
                audience_ok = self.request.host == apikey_dict['aud']

                # check the apikey subject against the current URL or if it's
                # 'all', allow it in
                if isinstance(apikey_dict['sub'], (tuple, list)):
                    subject_ok = (
                        self.request.uri in apikey_dict['sub']
                    )
                elif (isinstance(apikey_dict['sub'], str) and
                      apikey_dict['sub'] == 'all'):
                    subject_ok = True
                else:
                    subject_ok = False

                # check the issuer (this is usually the authnzerver's name or
                # actual address)
                issuer_ok = self.apikey_issuer == apikey_dict['iss']

                # pass apikey dict to the backend to check for:
                # 1. not-before,
                # 2. expiry again,
                # 3. match to the user ID
                # 4. match to the user role,
                # 5. match to the actual apikey token
                if (ipaddr_ok and
                    apiversion_ok and
                    audience_ok and
                    subject_ok and
                    issuer_ok):

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

                    message = (
                        'One of the provided API key IP address = %s, '
                        'API version = %s, subject = %s, audience = %s '
                        'do not match the '
                        'current request IP address = %s, '
                        'current API version = %s, '
                        'current request subject = %s, '
                        'current request audience = %s' %
                        (apikey_dict['ipa'],
                         apikey_dict['ver'],
                         apikey_dict['sub'],
                         apikey_dict['aud'],
                         self.request.remote_ip,
                         self.apikey_apiversion,
                         self.request.host,
                         self.request.uri)
                    )

                    LOGGER.error(message)
                    self.set_status(401)
                    retdict = {
                        'status':'failed',
                        'message':message,
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

        except Exception:

            LOGGER.exception('could not verify API key.')
            retdict = {
                'status':'failed',
                'message':'Your API key appears to be invalid or has expired.',
                'result':None
            }

            self.apikey_verified = False
            self.apikey_dict = None
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

        if not compare_digest(utf8(token), utf8(expected_token)):

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

        If no Authorization key is present in the header, then we assume it's a
        POST requiring an XSRF token. If there is an Authorization key in
        header, then we assume API key authentication is required. POSTs without
        either a valid Authorization header key or a valid XSRF token will be
        denied.

        You can use something like the following code at the top of every POST
        handler that derives from BaseHandler in your app to verify that the
        POST request either contained an Authorization header key or had a valid
        XSRF token::

            if not self.keycheck['status'] == 'ok':

                self.set_status(403)
                retdict = {
                    'status':'failed',
                    'result':None,
                    'message':"Sorry, you don't have access."
                }
                self.write(retdict)
                raise tornado.web.Finish()

        If you want to enforce that an endpoint accept only valid XSRF tokens
        for POST authentication (e.g. it's not meant to be an API endpoint), you
        can use something like the following in your POST handler that derives
        from BaseHandler::

            if ((not self.keycheck['status'] == 'ok') or
                (not self.xsrf_type == 'session')):

                self.set_status(403)
                retdict = {
                    'status':'failed',
                    'result':None,
                    'message':("Sorry, you don't have access. "
                               "API keys are not allowed for this endpoint.")
                }
                self.write(retdict)
                raise tornado.web.Finish()

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

        1. check the lccserver_session cookie and see if it's not expired.

        2. if can get cookie, talk to authnzerver to get the session info and
           populate the self.current_user variable with the session dict.

        3. if cannot get cookie, then ask authnzerver for a new session token by
           giving it the remote_ip, user_agent, and an expiry date. set the
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
            self.session_cookie_secure = True
        else:
            self.session_cookie_secure = False

        # check if there's an authorization header in the request
        authorization = self.request.headers.get('Authorization')

        # if there's no authorization header in the request,
        # we'll assume that we're using normal session tokens
        if not authorization:

            # check the session cookie
            session_token = self.get_secure_cookie(
                self.session_cookie_name,
                max_age_days=self.session_expiry
            )

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

            # if the session token is not set, then create a new anonymous user
            # session
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

            # check if the API key is valid
            apikey_check = yield self.check_auth_header_apikey()

            if not apikey_check['status'] == 'ok':

                message = apikey_check['message']

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

                message = apikey_check['message']
                self.keycheck = {
                    'status':'ok',
                    'message': message,
                    'result':apikey_check['result']
                }

                #
                # set up the current_user object for this API key request
                #

                user_agent = self.request.headers.get('User-Agent')
                if (not user_agent or
                    (user_agent and len(user_agent.strip()) == 0)):
                    user_agent = 'no-user-agent-provided'

                # - user_id
                # - email
                # - is_active
                # - user_role
                # - ip_address <- get from the current self.request
                # - user_agent <- get from the current self.request
                # - session_token <- set this to the API key itself
                # - created <- set this to the API key created time
                # - expires <- set this to the API key expiry time
                self.current_user = {
                    'user_id':self.apikey_dict['uid'],
                    'email':None,
                    'is_active':True,
                    'user_role':self.apikey_dict['rol'],
                    'ip_address':self.request.remote_ip,
                    'user_agent':user_agent,
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
