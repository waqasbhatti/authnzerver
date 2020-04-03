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

from . import basehandler


#########################
## BASIC PAGE HANDLERS ##
#########################

class ForgotPasswordStep1Handler(basehandler.BaseHandler):

    def get(self):
        '''
        This handles the reset password step 1.

        '''

        flash_message_list, alert_type = self.get_flash_messages()

        self.render(
            'index.html',
            baseurl=self.conf.base_url,
            current_user=self.current_user,
            conf=self.conf,
            page_title='Reset your account password.',
            flash_message_list=flash_message_list,
            alert_type=alert_type,
        )

    def post(self):
        '''
        This handles the POST for step 1.

        '''


class ForgotPasswordStep2Handler(basehandler.BaseHandler):

    def get(self):
        '''
        This handles the reset password step 2.

        '''

        flash_message_list, alert_type = self.get_flash_messages()

        self.render(
            'index.html',
            baseurl=self.conf.base_url,
            current_user=self.current_user,
            conf=self.conf,
            page_title='Verify your password reset request.',
            flash_message_list=flash_message_list,
            alert_type=alert_type,
        )

    def post(self):
        '''
        This handles the POST for the reset password step 2.

        '''


class ChangePasswordHandler(basehandler.BaseHandler):

    def get(self):
        '''
        This shows the change password form.

        '''

        flash_message_list, alert_type = self.get_flash_messages()

        self.render(
            'index.html',
            baseurl=self.conf.base_url,
            current_user=self.current_user,
            conf=self.conf,
            page_title='Change your account password.',
            flash_message_list=flash_message_list,
            alert_type=alert_type,
        )

    def post(self):
        '''
        This handles the POST for the change password form.

        '''
