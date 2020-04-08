# -*- coding: utf-8 -*-

'''This contains the handlers for the password endpoints

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
from . import basehandler


#########################
## BASIC PAGE HANDLERS ##
#########################

class ForgotPasswordStep1Handler(basehandler.BaseHandler):

    @tornado.web.removeslash
    def get(self):
        '''
        This handles the reset password step 1.

        '''

        self.render(
            'passreset-step1.html',
            current_user=self.current_user,
            conf=self.conf,
            page_title='Reset your account password.',
            flash_message_list=self.flash_message_list,
            alert_type=self.alert_type,
        )

    def post(self):
        '''
        This handles the POST for step 1.

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

        #
        # actual processing here
        #


class ForgotPasswordStep2Handler(basehandler.BaseHandler):

    @tornado.web.removeslash
    def get(self):
        '''
        This handles the reset password step 2.

        '''

        self.render(
            'passreset-step2.html',
            current_user=self.current_user,
            conf=self.conf,
            page_title='Verify your password reset request.',
            flash_message_list=self.flash_message_list,
            alert_type=self.alert_type,
        )

    def post(self):
        '''
        This handles the POST for the reset password step 2.

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

        #
        # actual processing here
        #


class ChangePasswordHandler(basehandler.BaseHandler):

    @tornado.web.removeslash
    def get(self):
        '''
        This shows the change password form.

        '''

        # disallow if the user isn't logged in
        if self.current_user['user_role'] in ('anonymous', 'locked'):
            self.render_blocked_message(code=403)

        self.render(
            'passchange.html',
            current_user=self.current_user,
            conf=self.conf,
            page_title='Change your account password.',
            flash_message_list=self.flash_message_list,
            alert_type=self.alert_type,
        )

    def post(self):
        '''
        This handles the POST for the change password form.

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
