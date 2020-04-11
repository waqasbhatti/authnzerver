# -*- coding: utf-8 -*-

'''This contains the handlers for the session endpoints.

'''

#############
## LOGGING ##
#############

import logging
LOGGER = logging.getLogger(__name__)

LOGDEBUG = LOGGER.debug
LOGINFO = LOGGER.info
LOGWARNING = LOGGER.warning
LOGERROR = LOGGER.error
LOGEXCEPTION = LOGGER.exception


#############
## IMPORTS ##
#############

import tornado.web

from ..permissions import pii_hash
from ..validators import validate_email_address
from . import basehandler


#########################
## BASIC PAGE HANDLERS ##
#########################

class LoginHandler(basehandler.BaseHandler):

    @tornado.web.removeslash
    def get(self):
        '''
        This handles the login page.

        '''

        # redirect if the user's already logged in
        if self.current_user['user_role'] not in ('anonymous','locked'):
            self.save_flash_messages(
                "You are already signed in.",
                "warning"
            )
            self.redirect(self.conf.baseurl)

        #
        # otherwise, show the page
        #
        else:

            self.render(
                'login.html',
                current_user=self.current_user,
                conf=self.conf,
                page_title='Sign in to your account.',
                flash_message_list=self.flash_message_list,
                alert_type=self.alert_type,
            )

    async def post(self):
        '''
        This handles the POST for the login.

        '''

        # disallow Authorization headers for this URL
        if self.xsrf_type == 'api_key':
            self.set_status(403)
            retdict = {
                'status':'failed',
                'data':None,
                'messages':"Sorry, API keys are not allowed for this endpoint."
            }
            self.write(retdict)
            raise tornado.web.Finish()

        # disallow if the XSRF check failed
        if self.post_check['status'] != 'ok':
            self.render_blocked_message(code=401)

        # redirect if the user's already logged in
        if self.current_user['user_role'] not in ('anonymous','locked'):
            self.save_flash_messages(
                "You are already signed in.",
                "warning"
            )
            self.redirect(self.conf.baseurl)

        #
        # actual processing here
        #

        try:

            email = self.get_argument('email')
            email_is_valid = validate_email_address(email)
            if not email_is_valid:
                raise ValueError("Email address provided did "
                                 "not pass validation.")

            password = self.get_argument('password')

            # avoid hashing DoS - the authnzerver also trims to this length
            password = password[:1024]

        except Exception as e:

            LOGGER.error(
                "[%s] Could not validate the input email or "
                "password for this request. Exception was: %r" % (self.reqid, e)
            )
            self.save_flash_messages(
                "A valid email address and password are both required.",
                "warning"
            )
            self.redirect("%s/login" % self.conf.baseurl)

        #
        # talk to the authnzerver to log in this user
        #
        request_type = 'user-login'
        request_body = {
            "session_token": self.current_user["session_token"],
            "email": email,
            "password": password,
        }

        success, response, messages = await self.authnzerver_request(
            request_type,
            request_body
        )

        if not success:

            LOGGER.error(
                "[%s] Login request failed for email: %s, session_token: %s. "
                "Authnzerver messages: '%s'" %
                (self.reqid,
                 pii_hash(email, self.conf.pii_salt),
                 pii_hash(self.current_user['session_token'],
                          self.conf.pii_salt),
                 ' '.join(messages))
            )

            self.save_flash_messages(
                messages,
                "danger"
            )

            await self.new_session_token(
                expires_days=self.session_expiry
            )

            self.redirect('%s/login' % self.conf.baseurl)

        else:

            new_session_token = await self.new_session_token(
                user_id=response['user_id'],
                expires_days=self.session_expiry,
            )

            LOGGER.info(
                "[%s] Login request succeeded for email: %s, "
                "old anonymous session_token: %s, "
                "new logged-in session_token: %s. "
                "Authnzerver messages: '%s'" %
                (self.reqid,
                 pii_hash(email, self.conf.pii_salt),
                 pii_hash(self.current_user['session_token'],
                          self.conf.pii_salt),
                 pii_hash(new_session_token,
                          self.conf.pii_salt),
                 ' '.join(messages))
            )

            self.redirect(self.conf.baseurl)


class LogoutHandler(basehandler.BaseHandler):

    async def post(self):
        '''
        This handles the POST for the logout action.

        '''

        if not self.current_user:
            self.redirect(self.conf.baseurl)

        if self.xsrf_type == 'api_key':
            self.set_status(403)
            retdict = {
                'status':'failed',
                'data':None,
                'messages':"Sorry, API keys are not allowed for this endpoint."
            }
            self.write(retdict)
            raise tornado.web.Finish()

        if self.post_check['status'] != 'ok':
            self.render_blocked_message(code=401)

        # if the user isn't signed in, they can't sign out
        if (not self.current_user or
            (self.current_user and
             self.current_user['user_role'] in ('anonymous', 'locked')) or
            (self.current_user and
             (not self.current_user['is_active']
              or not self.current_user['email_verified']))):

            LOGGER.error(
                "[%s] Logout request failed for session_token: %s. "
                "User wasn't signed in, so they can't sign out." %
                (self.reqid,
                 pii_hash(self.current_user['session_token'],
                          self.conf.pii_salt))
            )

            self.save_flash_messages(
                "You are not signed in, so you cannot sign out.",
                "warning"
            )

            self.redirect(self.conf.baseurl)

        #
        # otherwise, process the sign out request
        #

        request_type = 'user-logout'
        request_body = {
            "session_token": self.current_user["session_token"],
            "user_id":self.current_user["user_id"],
        }

        success, response, messages = await self.authnzerver_request(
            request_type,
            request_body
        )

        # we'll generate a new anonymous session token no matter what happens
        # with the logout action
        new_session_token = await self.new_session_token(
            expires_days=self.session_expiry,
        )

        if success:

            LOGGER.info(
                "[%s] Logout request succeeded for user_id: %s, "
                "old logged-in session_token: %s, "
                "new anonymous session_token: %s. "
                "Authnzerver messages: '%s'" %
                (self.reqid,
                 pii_hash(self.current_user['user_id'], self.conf.pii_salt),
                 pii_hash(self.current_user['session_token'],
                          self.conf.pii_salt),
                 pii_hash(new_session_token,
                          self.conf.pii_salt),
                 ' '.join(messages))
            )

        else:

            LOGGER.error(
                "[%s] Logout request failed for user_id: %s, "
                "old logged-in session_token: %s, "
                "new anonymous session_token: %s. "
                "Authnzerver messages: '%s'" %
                (self.reqid,
                 pii_hash(self.current_user['user_id'], self.conf.pii_salt),
                 pii_hash(self.current_user['session_token'],
                          self.conf.pii_salt),
                 pii_hash(new_session_token,
                          self.conf.pii_salt),
                 ' '.join(messages))
            )

        self.save_flash_messages(
            "You have signed out of your account. Have a great day!",
            "primary"
        )
        self.redirect(self.conf.baseurl)
