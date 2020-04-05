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

        if (not self.post_check['status'] == 'ok' and
            self.xsrf_type == 'api_key'):

            self.set_status(401)
            retdict = {
                'status':'failed',
                'data':None,
                'message':"Sorry, you don't have access."
            }
            self.write(retdict)
            raise tornado.web.Finish()

        elif not self.post_check['status'] == 'ok':

            self.render_blocked_message(code=401)

        #
        # actual processing here
        #


class ForgotPasswordStep2Handler(basehandler.BaseHandler):

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

        if (not self.post_check['status'] == 'ok' and
            self.xsrf_type == 'api_key'):

            self.set_status(401)
            retdict = {
                'status':'failed',
                'data':None,
                'message':"Sorry, you don't have access."
            }
            self.write(retdict)
            raise tornado.web.Finish()

        elif not self.post_check['status'] == 'ok':

            self.render_blocked_message(code=401)

        #
        # actual processing here
        #


class ChangePasswordHandler(basehandler.BaseHandler):

    def get(self):
        '''
        This shows the change password form.

        '''

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

        if (not self.post_check['status'] == 'ok' and
            self.xsrf_type == 'api_key'):

            self.set_status(401)
            retdict = {
                'status':'failed',
                'data':None,
                'message':"Sorry, you don't have access."
            }
            self.write(retdict)
            raise tornado.web.Finish()

        elif not self.post_check['status'] == 'ok':

            self.render_blocked_message(code=401)

        #
        # actual processing here
        #
