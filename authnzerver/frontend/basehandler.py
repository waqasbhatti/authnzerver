# -*- coding: utf-8 -*-

'''This is the base handler all other request handlers inherit from.

'''

#############
## LOGGING ##
#############

import logging
LOGGER = logging.getLogger(__name__)


####################
## SYSTEM IMPORTS ##
####################

from datetime import datetime, timedelta
import re
from hmac import compare_digest
import json
from functools import partial
from secrets import token_urlsafe


###########################
## SETUP JSON SERIALIZER ##
###########################

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


#####################
## TORNADO IMPORTS ##
#####################

import tornado.web
from tornado.escape import utf8, native_str
from tornado import httputil
from tornado.httpclient import AsyncHTTPClient, HTTPRequest

####################################
## AUTHNZERVER IMPORTS AND CONFIG ##
####################################

from cryptography.fernet import Fernet

from authnzerver.external.cookies import cookies
from authnzerver import cache
from authnzerver.permissions import pii_hash


######################
## MESSAGE HANDLING ##
######################

from authnzerver.messaging import encrypt_message, decrypt_message


########################
## BASE HANDLER CLASS ##
########################

class BaseHandler(tornado.web.RequestHandler):

    def initialize(
            self,
            conf,
            executor,
            cacheobj,
    ):
        '''
        This just sets up some stuff.

        Parameters
        ----------

        conf : object
            The server config loaded as an object. This should have attributes
            defining several things we need:

            - authnzerver_key: the pre-shared secret key for the authnzerver

            - authnzerver_url: the HTTP URL and port number for authnzerver

            - session_expiry_days: number of days after which sessions expire

            - session_cookie_name: the name of the session cookie to set

            - session_cookie_secure: True if the session cookie should be set as
              a secure cookie.

            - session_cookie_secret: the signing key for the secure cookies.

            - pii_salt: A random salt value to use when hashing PII like session
              tokens, user IDs, and API keys for logging.

            - api_key_expiry: The number of days after which a previously
              issued API key (presented in the Authorization: Bearer
              [token] header) expires.

        executor : Executor instance
            A concurrent.futures.ProcessPoolExecutor or
            concurrent.futures.ThreadPoolExecutor instance that will run
            background queries to the authnzerver.

        cacheobj : diskcache.Cache object instance
            This is a handle for the cache object to use for rate-limiting.

        '''

        # the passed config object
        self.conf = conf

        # the passed in cache object for rate-limiting
        self.cacheobj = cacheobj

        # the IOLoop instance
        self.loop = tornado.ioloop.IOLoop.current()

        # the AsyncHTTPClient for talking to the authnzerver
        self.httpclient = AsyncHTTPClient()

        # this is the request ID for this request
        self.reqid = token_urlsafe(16)

        # this is the executor to use for this request
        self.executor = executor

        # config from the conf object
        self.pii_salt = conf.pii_salt
        self.authnzerver_key = conf.authnzerver_key
        self.authnzerver_url = conf.authnzerver_url
        self.session_expiry = conf.session_expiry_days
        self.session_cookie_name = conf.session_cookie_name
        self.session_cookie_secure = conf.session_cookie_secure
        self.api_key_expiry = conf.api_key_expiry

        # we'll only accept issuers that correspond to the authnzerver we know
        self.api_key_issuer = self.authnzerver_url

        # If tls_enabled is False then we can't set secure cookies so disable
        # that if required
        if self.conf.tls_enabled is False:
            self.session_cookie_secure = False

        # initialize the current user to None
        # we'll set this later in self.prepare()
        self.current_user = None

        # api_key verification info
        self.api_key_verified = False
        self.api_key_dict = None

    def set_cookie(self,
                   name,
                   value,
                   domain=None,
                   expires=None,
                   path="/",
                   expires_days=None,
                   use_host_prefix=False,
                   **kwargs):
        """Sets an outgoing cookie name/value with the given options.

        Newly-set cookies are not immediately visible via `get_cookie`;
        they are not present until the next request.

        expires may be a numeric timestamp as returned by `time.time`,
        a time tuple as returned by `time.gmtime`, or a
        `datetime.datetime` object.

        If ``use_host_prefix = True``, then all cookies will be prefixed with
        the string "__Host-" to tie the cookie to a specific host, as
        recommended by:

        https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-05#section-4.1.3

        If the ``use_host_prefix`` kwarg is True, then domain must be None and
        path = '/' and the 'secure' cookie flag must be on.

        Additional keyword arguments are set on the cookies.Morsel
        directly.

        https://docs.python.org/3/library/http.cookies.html#http.cookies.Morsel

        ---

        Taken from Tornado's web module:

        https://github.com/tornadoweb/tornado/blob/
        627eafb3ce21a777981c37a5867b5f1956a4dc16/tornado/web.py#L528

        The main reason for bundling this in here is to allow use of the
        SameSite attribute for cookies via our vendored cookies library and
        allow adding in the --Host- prefix.

        """

        if (use_host_prefix and
            domain is None and
            path == '/' and
            kwargs.get('secure',False)):
            use_name = '__Host-%s' % name
        else:
            use_name = name

        # The cookie library only accepts type str, in both python 2 and 3
        use_name = native_str(use_name)
        value = native_str(value)
        if re.search(r"[\x00-\x20]", use_name + value):
            # Don't let us accidentally inject bad stuff
            raise ValueError("Invalid cookie %r: %r" % (use_name, value))
        if not hasattr(self, "_new_cookie"):
            self._new_cookie = cookies.SimpleCookie()
        if use_name in self._new_cookie:
            del self._new_cookie[use_name]
        self._new_cookie[use_name] = value
        morsel = self._new_cookie[use_name]
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

    async def authnzerver_request(self, request_type, request_body):
        '''
        This runs an authnzerver request on the IOLoop executor.

        '''

        message_dict = {
            'request':request_type,
            'body':request_body,
            'reqid': self.reqid
        }

        encrypted_request = await self.loop.run_in_executor(
            self.executor,
            encrypt_message,
            message_dict,
            self.authnzerver_key,
        )

        authnzerver_reqsetup = HTTPRequest(
            self.authnzerver_url,
            method='POST',
            body=encrypted_request,
            connect_timeout=5.0,
            request_timeout=5.0,
        )
        authnzerver_response = await self.httpclient.fetch(
            authnzerver_reqsetup,
            raise_error=False,
        )

        if authnzerver_response.code != 200:
            LOGGER.error(
                "[%s] Authnzerver did not respond to the "
                "frontend request: %s. Response code was: %s." %
                (self.reqid, request_type, authnzerver_response.code)
            )
            return (False,
                    None,
                    ["Authnzerver did not respond "
                     "to the frontend auth request."])

        decrypted_response = await self.loop.run_in_executor(
            self.executor,
            decrypt_message,
            authnzerver_response.body,
            self.authnzerver_key,
            self.reqid,
        )

        returned_reqid = decrypted_response['reqid']

        if returned_reqid != self.reqid:
            LOGGER.error(
                "[%s] Authnzerver responded with incorrect reqid. "
                "The frontend request reqid was: %s. Response reqid was: %s." %
                (self.reqid, self.reqid, returned_reqid)
            )
            return (False,
                    None,
                    ["Authnzerver did not respond "
                     "to the frontend auth request."])

        ok = decrypted_response['success']
        response = decrypted_response['response']
        messages = decrypted_response['response']['messages']

        return ok, response, messages

    async def new_session_token(self,
                                user_id=None,
                                expires_days=None,
                                extra_info=None):
        '''
        This is a shortcut function to request a new session token.

        Also sets the session cookie.

        '''

        if not expires_days:
            expires_days = self.session_expiry

        user_agent = self.request.headers.get('User-Agent')
        if not user_agent or len(user_agent.strip()) == 0:
            user_agent = 'no-user-agent'

        ok, resp, msgs = await self.authnzerver_request(
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
                '[%s] Setting new session cookie for session_token: %s, '
                'expires at %s, in %s days' %
                (self.reqid,
                 pii_hash(resp['session_token'], self.pii_salt),
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
                use_host_prefix=False,
            )

            return resp['session_token']

        else:

            self.current_user = None
            self.clear_all_cookies()
            LOGGER.error('[%s] Could not talk to the backend authnzerver. '
                         'Will fail this request.' % self.reqid)
            raise tornado.web.HTTPError(statuscode=401)

    async def check_auth_header_api_key(self):
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

                ferneter = Fernet()

                # do the Fernet decrypt using TTL = self.api_key_expiry
                decrypted_bytes = ferneter.decrypt(
                    key.encode(),
                    ttl=self.api_key_expiry*86400.0
                )

                # if decrypt OK, JSON load the api_key dict
                api_key_dict = json.loads(decrypted_bytes)

                # check if the current ip_address matches the the value stored
                # in the dict. if not, fail this request immediately. if it
                # does, send the dict on to the backend for additional
                # verification.

                # check the api_key IP address against the current one
                ipaddr_ok = (
                    self.request.remote_ip == api_key_dict['ipa']
                )

                # check the api_key version against the current one
                apiversion_ok = (
                    self.api_key_apiversion == api_key_dict['ver']
                )

                # check the api_key audience against the host of our server
                audience_ok = self.request.host == api_key_dict['aud']

                # check the api_key subject against the current URL or if
                # it's 'all', allow it in
                if isinstance(api_key_dict['sub'], (tuple, list)):
                    subject_ok = (
                        self.request.uri in api_key_dict['sub']
                    )
                elif (isinstance(api_key_dict['sub'], str) and
                      api_key_dict['sub'] == 'all'):
                    subject_ok = True
                else:
                    subject_ok = False

                # check the issuer (this is usually the authnzerver's name or
                # actual address)
                issuer_ok = self.api_key_issuer == api_key_dict['iss']

                # pass api_key dict to the backend to check for:
                # 1. not-before,
                # 2. expiry again,
                # 3. match to the user ID
                # 4. match to the user role,
                # 5. match to the actual api_key token
                if (ipaddr_ok and
                    apiversion_ok and
                    audience_ok and
                    subject_ok and
                    issuer_ok):

                    verify_ok, resp, msgs = (
                        await self.authnzerver_request(
                            'api_key-verify',
                            {'api_key_dict':api_key_dict}
                        )
                    )

                    # check if backend agrees it's OK
                    if verify_ok:

                        retdict = {
                            'status':'ok',
                            'message':msgs,
                            'result': api_key_dict
                        }

                        self.api_key_verified = True
                        self.api_key_dict = api_key_dict
                        return retdict

                    else:

                        self.set_status(401)
                        retdict = {
                            'status':'failed',
                            'message':msgs,
                            'result': None
                        }
                        self.api_key_verified = False
                        self.api_key_dict = None
                        return retdict

                # if the key doesn't pass initial verification, fail this
                # request immediately
                else:

                    message = (
                        '[%s] One of the provided API key IP address = %s, '
                        'API version = %s, subject = %s, audience = %s '
                        'do not match the '
                        'current request IP address = %s, '
                        'current API version = %s, '
                        'current request subject = %s, '
                        'current request audience = %s' %
                        (self.reqid,
                         pii_hash(api_key_dict['ipa'], self.pii_salt),
                         api_key_dict['ver'],
                         api_key_dict['sub'],
                         api_key_dict['aud'],
                         pii_hash(self.request.remote_ip, self.pii_salt),
                         self.api_key_apiversion,
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
                    self.api_key_verified = False
                    self.api_key_dict = None
                    return retdict

            else:

                LOGGER.error(
                    '[%s] No Authorization header key found for API key auth.' %
                    self.reqid
                )
                retdict = {
                    'status':'failed',
                    'message':('No credentials provided or '
                               'they could not be parsed safely'),
                    'result':None
                }

                self.api_key_verified = False
                self.api_key_dict = None
                self.set_status(401)
                return retdict

        except Exception:

            LOGGER.exception('[%s] Could not verify API key.' % self.reqid)
            retdict = {
                'status':'failed',
                'message':'Your API key appears to be invalid or has expired.',
                'result':None
            }

            self.api_key_verified = False
            self.api_key_dict = None
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
            return retdict

        _, token, _ = self._decode_xsrf_token(token)
        _, expected_token, _ = self._get_raw_xsrf_token()

        if not token:

            retdict = {
                'status':'failed',
                'message':("'_xsrf' argument missing from POST"),
                'result':None
            }
            return retdict

        if not compare_digest(utf8(token), utf8(expected_token)):

            retdict = {
                'status':'failed',
                'message':("XSRF cookie does not match POST argument"),
                'result':None
            }
            return retdict

        else:

            retdict = {
                'status':'ok',
                'message':("Successful XSRF cookie match to POST argument"),
                'result': None
            }
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

            if not self.post_check['status'] == 'ok':

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

            if ((not self.post_check['status'] == 'ok') or
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

            LOGGER.info('[%s] Using tornado XSRF auth for this POST...' %
                        self.reqid)
            self.xsrf_type = 'session'
            self.post_check = self.tornado_check_xsrf_cookie()

        elif self.request.headers.get("Authorization"):

            LOGGER.info(
                '[%s] Using API Authorization header auth for this POST. '
                'Passing through to the prepare function...' % self.reqid
            )
            self.xsrf_type = 'api_key'

        else:

            LOGGER.info('[%s] No Authorization key found in request header.' %
                        self.reqid)
            self.xsrf_type = 'unknown'
            self.post_check = {
                'status':'failed',
                'message':(
                    'Unknown authorization type, neither API key or session.'
                ),
                'result':None
            }

    def render_blocked_message(self,
                               code=403,
                               message=None):
        '''
        This renders the template indicating that the user is blocked.

        '''

        self.set_status(code)

        if not message:
            message = (
                "Sorry, it appears that you're not authorized to "
                "view the page you were trying to get to. "
                "If you believe this is in error, please contact "
                "the admins of this server instance."
            )

        self.render(
            'errorpage.html',
            baseurl=self.conf.baseurl,
            current_user=self.current_user,
            conf=self.conf,
            page_title=f"HTTP {code} - Oh no, something went wrong!",
            flash_message_list=self.flash_message_list,
            alert_type=self.alert_type,
            error_message=message,
        )

    def render_page_not_found(self, message=None):
        '''
        This renders the template indicating that the user is blocked.

        '''

        if not message:
            error_message = (
                "Sorry, we can't find a server page with that name."
            )
        else:
            error_message = message

        self.set_status(404)
        self.render(
            'errorpage.html',
            baseurl=self.conf.baseurl,
            current_user=self.current_user,
            conf=self.conf,
            page_title="HTTP 404 - Item not found",
            flash_message_list=self.flash_message_list,
            alert_type=self.alert_type,
            error_message=error_message,
        )

    def save_flash_messages(self, messages, alert_type):
        '''
        This saves the flash messages to a secure cookie.

        Alert types are::

            "primary", "secondary", "success", "danger",
            "warning", "info", "light", "dark"

        '''

        if isinstance(messages, list):
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
            'server-messages',
            outmsg,
            httponly=True,
            secure=self.session_cookie_secure,
            samesite='lax',
            use_host_prefix=False,
        )

    def get_flash_messages(self):
        '''
        This gets the previous saved flash messages from a secure cookie.

        It then deletes the cookie so they don't linger around.

        '''

        messages = self.get_secure_cookie(
            'server-messages',
            max_age_days=self.session_expiry
        )

        if messages is not None:
            messages = json.loads(messages)
            message_text = messages['text']
            alert_type = messages['type']
        else:
            message_text = ''
            alert_type = None

        # delete the server-messages cookie now that we're done with it
        self.clear_cookie('server-messages')

        return message_text, alert_type

    async def prepare(self):
        '''This async talks to the authnzerver to get info on the current user.

        1. check the session cookie and see if it's not expired.

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

        # get the flash messages
        self.flash_message_list, self.alert_type = self.get_flash_messages()

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

                # NOTE: get_secure_cookie returns bytes if successful
                ok, resp, msgs = await self.authnzerver_request(
                    'session-exists',
                    {'session_token': session_token.decode()}
                )

                # if we found the session successfully, set the current_user
                # attribute for this request
                if ok:

                    self.current_user = resp['session_info']
                    self.user_id = self.current_user['user_id']
                    self.user_role = self.current_user['user_role']

                    #
                    # check the rate now
                    #
                    incrementfn = partial(
                        cache.cache_increment,
                        session_token,
                        cacheobj=self.cacheobj
                    )

                    # increment the rate counter for this session token
                    reqcount = await self.loop.run_in_executor(
                        self.executor,
                        incrementfn
                    )

                    # rate limit only after 25 requests have been counted
                    if reqcount > 25:

                        getratefn = partial(
                            cache.cache_getrate,
                            session_token,
                            cacheobj=self.cacheobj
                        )

                        # check the rate for this session token
                        request_rate, keycount, time_zero = (
                            await self.loop.run_in_executor(self.executor,
                                                            getratefn)
                        )
                        rate_ok, _, _ = await self.authnzerver_request(
                            'user-check-limit',
                            {'user_id':self.user_id,
                             'user_role':self.user_role,
                             'limit_name':'max_requests_per_minute',
                             'value_to_check':request_rate}
                        )
                        self.request_rate_60sec = request_rate

                        if not rate_ok:

                            LOGGER.error(
                                '[%s] Session token: %s: '
                                'current rate = %s exceeds '
                                'their allowed rate for their role = %s'
                                % (self.reqid,
                                   pii_hash(session_token, self.pii_salt),
                                   request_rate,
                                   self.user_role)
                            )
                            self.set_status(429)
                            self.set_header('Retry-After','120')
                            message = (
                                "You have exceeded the request rate limit. "
                                "Please try again in a couple of minutes."
                            )
                            self.render_blocked_message(
                                code=429,
                                message=message
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

            # if the session token is not set, then create a new anonymous user
            # session
            else:

                session_token = await self.new_session_token(
                    user_id=None,
                    expires_days=self.session_expiry,
                    extra_info={}
                )

                # immediately get back the session object for the current user
                # so we don't have to redirect to get the session info from the
                # cookie
                ok, resp, msgs = await self.authnzerver_request(
                    'session-exists',
                    {'session_token': session_token}
                )

                # if we found the session successfully, set the current_user
                # attribute for this request
                if ok:

                    self.current_user = resp['session_info']
                    self.user_id = self.current_user['user_id']
                    self.user_role = self.current_user['user_role']

                    # increment the rate counter for this session token. we
                    # just increase the count to 1 since this is the first
                    # time we've seen this user.

                    incrementfn = partial(
                        cache.cache_increment,
                        session_token,
                        cacheobj=self.cacheobj
                    )

                    await self.loop.run_in_executor(self.executor,
                                                    incrementfn)

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
            api_key_check = await self.check_auth_header_api_key()

            if not api_key_check['status'] == 'ok':

                message = api_key_check['message']

                self.post_check = {
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

                message = api_key_check['message']
                self.post_check = {
                    'status':'ok',
                    'message': message,
                    'result':api_key_check['result']
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
                    'user_id':self.api_key_dict['uid'],
                    'email':None,
                    'is_active':True,
                    'user_role':self.api_key_dict['rol'],
                    'ip_address':self.request.remote_ip,
                    'user_agent':user_agent,
                    'session_token':self.api_key_dict['tkn'],
                    'created':self.api_key_dict['iat'],
                    'expires':self.api_key_dict['exp'],
                }
                self.user_id = self.current_user['user_id']
                self.user_role = self.current_user['user_role']

                #
                # check the rate now
                #

                incrementfn = partial(
                    cache.cache_increment,
                    self.api_key_dict['tkn'],
                    cacheobj=self.cacheobj
                )

                # increment the rate counter for this session token
                reqcount = await self.loop.run_in_executor(self.executor,
                                                           incrementfn)

                # rate limit only after 25 requests have been counted
                if reqcount > 25:

                    getratefn = partial(
                        cache.cache_getrate,
                        self.api_key_dict['tkn'],
                        cacheobj=self.cacheobj
                    )

                    # check the rate for this session token
                    request_rate, keycount, time_zero = (
                        await self.loop.run_in_executor(self.executor,
                                                        getratefn)
                    )
                    rate_ok, _, _ = await self.authnzerver_request(
                        'user-check-limit',
                        {'user_id':self.user_id,
                         'user_role':self.user_role,
                         'limit_name':'max_requests_per_minute',
                         'value_to_check':request_rate}
                    )
                    self.request_rate_60sec = request_rate

                    if not rate_ok:

                        LOGGER.error(
                            '[%] API key: %s: current rate = %s exceeds '
                            'their allowed rate for their role = %s. '
                            'total reqs = %s, time_zero = %s'
                            % (self.reqid,
                               pii_hash(self.api_key_dict['tkn'],
                                        self.pii_salt),
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


class PageNotFoundHandler(BaseHandler):
    '''This is suitable for use in Tornado Application.settings as a default
    handler.

    '''

    def get(self):
        self.render_page_not_found()
