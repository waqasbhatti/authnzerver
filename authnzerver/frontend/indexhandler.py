# -*- coding: utf-8 -*-

'''This contains the handlers for the index page.

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

class IndexHandler(basehandler.BaseHandler):

    def get(self):
        '''
        This handles the basic index page.

        '''

        self.render(
            'index.html',
            current_user=self.current_user,
            conf=self.conf,
            page_title='Authnzerver',
            flash_message_list=self.flash_message_list,
            alert_type=self.alert_type,
        )
