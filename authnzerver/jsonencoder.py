# -*- coding: utf-8 -*-
# jsonencoder.py - Waqas Bhatti (waqas.afzal.bhatti@gmail.com) - Jul 2020
# License: MIT - see the LICENSE file for the full text.

"""The JSON encoder class for all handlers.

"""

import json
from datetime import datetime


class FrontendEncoder(json.JSONEncoder):

    def default(self, obj):

        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, bytes):
            return obj.decode()
        elif isinstance(obj, complex):
            return obj.real, obj.imag
        else:
            return json.JSONEncoder.default(self, obj)
