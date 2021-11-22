# -*- coding: utf-8 -*-
# healthcheck.py - Waqas Bhatti (waqas.afzal.bhatti@gmail.com) - Jul 2020
# License: MIT - see the LICENSE file for the full text.

"""This contains functions to check database health.

"""

#############
## LOGGING ##
#############

import logging
from types import SimpleNamespace

# get a logger
LOGGER = logging.getLogger(__name__)


#############
## IMPORTS ##
#############

import multiprocessing as mp
from sqlalchemy import select

from authnzerver.actions.utils import get_procdb_permjson


def database_health_check(
    raiseonfail: bool = False,
    override_authdb_path: str = None,
    config: SimpleNamespace = None,
) -> dict:
    """
    This function checks if the current process' DB connection is good.

    """

    currproc = mp.current_process()
    currproc_name = currproc.name

    try:

        engine, meta, permjson, dbpath = get_procdb_permjson(
            override_authdb_path=override_authdb_path,
            override_permissions_json=None,
            raiseonfail=raiseonfail,
        )

        users = meta.tables["users"]
        with engine.begin() as conn:
            sel = (
                select(users.c.user_role)
                .select_from(users)
                .where(users.c.user_id == 1)
            )
            result = conn.execute(sel)
            item = result.scalar()

        if item is not None and item == "superuser":
            check = True
            failure_reason = None
            messages = ["Database in process: %s OK." % currproc_name]
        else:
            check = False
            failure_reason = "database broken"
            messages = ["Database has no superuser, probably broken."]

        retdict = {
            "success": check,
            "process": currproc_name,
            "messages": messages,
        }
        if failure_reason is not None:
            retdict["failure_reason"] = failure_reason

        return retdict

    except Exception:

        if raiseonfail:
            raise

        return {
            "success": False,
            "process": currproc_name,
            "failure_reason": "database broken",
            "messages": ["Database access exception, probably broken."],
        }
