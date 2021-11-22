"""
Contains utilities for actions.

"""

import logging

from multiprocessing import current_process
from typing import Tuple
import os.path

logger = logging.getLogger(__name__)

from sqlalchemy.engine import Engine
from sqlalchemy import MetaData

from authnzerver import authdb

MOD_DIR = os.path.dirname(__file__)
DEFAULT_PERMJSON = os.path.abspath(
    os.path.join(MOD_DIR, "..", "default-permissions-model.json")
)


def get_procdb_permjson(
    override_authdb_path: str = None,
    override_permissions_json: str = None,
    raiseonfail: bool = False,
) -> Tuple[Engine, MetaData, str, str]:
    """
    Gets the DB and permissions JSON path in the current process namespace.

    If these don't exist, will put the db in the current process's namespace
    and return it.

    """

    currproc = current_process()

    if override_authdb_path:
        currproc.auth_db_path = override_authdb_path
        logger.warning(
            f"overriding currproc.auth_db_path with "
            f"provided override_authdb_path = {override_authdb_path}"
        )
        currproc.authdb_engine, currproc.authdb_meta = authdb.get_auth_db(
            currproc.auth_db_path, echo=raiseonfail, returnconn=False
        )

    if override_permissions_json:
        logger.warning(
            f"overriding currproc.permissions_json with "
            f"provided override_permissions_json = {override_permissions_json}"
        )
        currproc.permissions_json = override_permissions_json
    else:
        currproc.permissions_json = DEFAULT_PERMJSON

    if not getattr(currproc, "authdb_engine", None):
        currproc.authdb_engine, currproc.authdb_meta = authdb.get_auth_db(
            currproc.auth_db_path, echo=raiseonfail, returnconn=False
        )

    return (
        currproc.authdb_engine,
        currproc.authdb_meta,
        currproc.permissions_json,
        currproc.auth_db_path,
    )
