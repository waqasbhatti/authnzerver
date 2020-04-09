# -*- coding: utf-8 -*-

'''This contains the handlers for the user endpoints.

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
from tornado.escape import xhtml_escape

from . import basehandler
from ..validators import validate_email_address
from ..permissions import pii_hash
from ..tokens import generate_email_token, verify_email_token


#########################
## BASIC PAGE HANDLERS ##
#########################

class NewUserHandler(basehandler.BaseHandler):

    @tornado.web.removeslash
    def get(self):
        '''
        This handles the new user sign-up forn.

        '''

        # redirect if the user's already logged in
        if self.current_user['user_role'] not in ('anonymous','locked'):
            self.save_flash_messages(
                "You are already signed in.",
                "warning"
            )
            self.redirect(self.conf.baseurl)

        else:

            self.render(
                'signup.html',
                current_user=self.current_user,
                conf=self.conf,
                page_title='Sign up for an account.',
                flash_message_list=self.flash_message_list,
                alert_type=self.alert_type,
            )

    def post(self):
        '''
        This handles the POST for the new user sign up form.

        '''

        # disallow Authorization headers for this URL
        if self.xsrf_type == 'api_key':
            self.set_status(403)
            retdict = {
                'status':'failed',
                'data':None,
                'message':"Sorry, API keys are not allowed for this endpoint."
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

            full_name = xhtml_escape(self.get_argument('fullname'))

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
            self.redirect("%s/users/new" % self.conf.baseurl)

        #
        # talk to the authnzerver to sign this user up
        #

        # 1. first, we'll insert them into the DB
        request_type = 'user-new'
        request_body = {
            "full_name": full_name,
            "email": email,
            "password": password,
        }

        created_success, created_info, created_messages = (
            await self.authnzerver_request(
                request_type,
                request_body
            )
        )

        # if sign up fails, complain to the user
        if not created_success:

            LOGGER.error(
                "[%s] Sign up request failed for email: %s, session_token: %s. "
                "Authnzerver messages: '%s'" %
                (self.reqid,
                 pii_hash(email, self.conf.pii_salt),
                 pii_hash(self.current_user['session_token'],
                          self.conf.pii_salt),
                 ' '.join(created_messages))
            )

            self.save_flash_messages(
                created_messages,
                "danger"
            )

            self.redirect('%s/users/new' % self.conf.baseurl)

        # 2. otherwise, prepare to send the verification email to the new user
        else:

            # generate the token to send to the user
            email_token = generate_email_token(
                self.current_user['ip_address'],
                self.current_user['user_agent'],
                email,
                self.current_user['session_token'],
                self.conf.session_cookie_secret
            )

            # ask the authnzerver to send an email containing the token
            request_type = 'user-sendemail-signup'
            request_body = {
                'email_address':email,
                'session_token':self.current_user['session_token'],
                'created_info': created_info,
                'server_name':'Authnzerver frontend',
                'server_baseurl':self.conf.baseurl,
                'account_verify_url':'/users/verify',
                'verification_token':email_token,
                'verification_expiry':900
            }

            verifysent_success, verifysent_info, verifysent_messages = (
                await self.authnzerver_request(
                    request_type,
                    request_body,
                )
            )

        # if sending the email fails, complain to the user
        if not verifysent_success:

            LOGGER.error(
                "[%s] Sign up request failed for email: %s, session_token: %s. "
                "Authnzerver messages: '%s'" %
                (self.reqid,
                 pii_hash(email, self.conf.pii_salt),
                 pii_hash(self.current_user['session_token'],
                          self.conf.pii_salt),
                 ' '.join(created_messages))
            )

            self.save_flash_messages(
                ("Sorry, we were unable to send an email to "
                 "your email address to verify "
                 "your sign-up request. Please try again, or contact the "
                 "server admins if this error persists."),
                "danger"
            )

            self.redirect('%s/users/new' % self.conf.baseurl)

        # otherwise, if it succeeds, redirect them to the verify token page.
        else:

            self.save_flash_messages(
                ("Thanks for signing up! We've sent a verification "
                 "code to your email address. "
                 "Please complete user registration by "
                 "entering the code you received."),
                "primary"
            )

            self.redirect('%s/users/verify' % self.conf.baseurl)


class VerifyUserHandler(basehandler.BaseHandler):

    @tornado.web.removeslash
    def get(self):
        '''
        This handles the verify user page.

        '''

        # redirect if the user's already logged in
        if self.current_user['user_role'] not in ('anonymous','locked'):
            self.save_flash_messages(
                "You are already signed in.",
                "warning"
            )
            self.redirect(self.conf.baseurl)

        self.render(
            'verify.html',
            current_user=self.current_user,
            conf=self.conf,
            page_title='Verify your sign-up request.',
            flash_message_list=self.flash_message_list,
            alert_type=self.alert_type,
        )

    def post(self):
        '''
        This handles the POST for the verify user page.

        '''

        # disallow Authorization headers for this URL
        if self.xsrf_type == 'api_key':
            self.set_status(403)
            retdict = {
                'status':'failed',
                'data':None,
                'message':"Sorry, API keys are not allowed for this endpoint."
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


class DeleteUserHandler(basehandler.BaseHandler):

    @tornado.web.removeslash
    def get(self):
        '''
        This shows the delete user form.

        '''

        # disallow if the user isn't logged in
        if self.current_user['user_role'] in ('anonymous', 'locked'):
            self.render_blocked_message(code=403)

        self.render(
            'delete.html',
            current_user=self.current_user,
            conf=self.conf,
            page_title='Delete your account.',
            flash_message_list=self.flash_message_list,
            alert_type=self.alert_type,
        )

    def post(self):
        '''
        This handles the POST for the delete user action.

        '''

        # disallow Authorization headers for this URL
        if self.xsrf_type == 'api_key':
            self.set_status(403)
            retdict = {
                'status':'failed',
                'data':None,
                'message':"Sorry, API keys are not allowed for this endpoint."
            }
            self.write(retdict)
            raise tornado.web.Finish()

        # disallow if the XSRF check failed
        if self.post_check['status'] != 'ok':
            self.render_blocked_message(code=401)

        # disallow if the user isn't logged in
        if self.current_user['user_role'] in ('anonymous', 'locked'):
            self.render_blocked_message(code=403)

        #
        # actual processing here
        #
