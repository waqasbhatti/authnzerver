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

from . import basehandler


#########################
## BASIC PAGE HANDLERS ##
#########################

class LoginHandler(basehandler.BaseHandler):

    def get(self):
        '''
        This handles the basic index page.

        '''

        flash_message_list, alert_type = self.get_flash_messages()

        self.render(
            'login.html',
            current_user=self.current_user,
            conf=self.conf,
            page_title='Sign in to your account.',
            flash_message_list=flash_message_list,
            alert_type=alert_type,
        )

    def post(self):
        '''
        This handles the POST for the login.

        '''


class LogoutHandler(basehandler.BaseHandler):

    def post(self):
        '''
        This handles the POST for the logout action.

        '''
