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

from . import basehandler


#########################
## BASIC PAGE HANDLERS ##
#########################

class NewUserHandler(basehandler.BaseHandler):

    def get(self):
        '''
        This handles the new user sign-up forn.

        '''

        flash_message_list, alert_type = self.get_flash_messages()

        self.render(
            'signup.html',
            current_user=self.current_user,
            conf=self.conf,
            page_title='Sign up for an account.',
            flash_message_list=flash_message_list,
            alert_type=alert_type,
        )

    def post(self):
        '''
        This handles the POST for the new user sign up form.

        '''


class VerifyUserHandler(basehandler.BaseHandler):

    def get(self):
        '''
        This handles the verify user page.

        '''

        flash_message_list, alert_type = self.get_flash_messages()

        self.render(
            'verify.html',
            current_user=self.current_user,
            conf=self.conf,
            page_title='Verify your sign-up request.',
            flash_message_list=flash_message_list,
            alert_type=alert_type,
        )

    def post(self):
        '''
        This handles the POST for the verify user page.

        '''


class DeleteUserHandler(basehandler.BaseHandler):

    def get(self):
        '''
        This shows the delete user form.

        '''

        flash_message_list, alert_type = self.get_flash_messages()

        self.render(
            'delete.html',
            current_user=self.current_user,
            conf=self.conf,
            page_title='Delete your account.',
            flash_message_list=flash_message_list,
            alert_type=alert_type,
        )

    def post(self):
        '''
        This handles the POST for the delete user action.

        '''
