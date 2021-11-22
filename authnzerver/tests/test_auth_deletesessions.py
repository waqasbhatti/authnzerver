"""test_auth_actions.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Sep 2018
License: MIT. See the LICENSE file for details.

This contains tests for the auth functions in authnzerver.actions.

"""

import os.path
import os
from datetime import datetime, timedelta
import multiprocessing as mp
from tempfile import mkdtemp

from .. import authdb, actions
from .test_support import get_public_suffix_list


def get_test_authdb():
    """This just makes a new test auth DB for each test function."""

    temp_dirname = mkdtemp()
    dbfile = os.path.join(temp_dirname, "test-sessiondelete.authdb.sqlite")
    dburl = f"sqlite:///{dbfile}"

    authdb.create_sqlite_authdb(dbfile)
    authdb.initial_authdb_inserts(dburl)

    return dbfile, dburl


def test_sessions_delete_userid():
    """
    This tests if we can delete sessions for a user.

    """

    db_file, db_url = get_test_authdb()
    get_public_suffix_list()

    # create the user
    user_payload = {
        "full_name": "Test User",
        "email": "testuser-sessiondelete@test.org",
        "password": "aROwQin9L8nNtPTEMLXd",
        "pii_salt": "super-secret-salt",
        "reqid": 1,
    }
    print(db_url)
    user_created = actions.create_new_user(
        user_payload,
        override_authdb_path=db_url,
    )
    assert user_created["success"] is True
    assert user_created["user_email"] == "testuser-sessiondelete@test.org"
    assert (
        "User account created. Please verify your email address to log in."
        in user_created["messages"]
    )

    # create a new session token
    session_payload = {
        "user_id": 2,
        "user_agent": "Mozzarella Killerwhale",
        "expires": datetime.utcnow() + timedelta(hours=1),
        "ip_address": "1.1.1.1",
        "extra_info_json": {"pref_datasets_always_private": True},
        "pii_salt": "super-secret-salt",
        "reqid": 1,
    }

    # check creation of session
    session_token1 = actions.auth_session_new(
        session_payload,
        override_authdb_path=db_url,
    )
    assert session_token1["success"] is True
    assert session_token1["session_token"] is not None

    # verify our email
    emailverify = actions.set_user_emailaddr_verified(
        {
            "email": user_payload["email"],
            "user_id": user_created["user_id"],
            "pii_salt": "super-secret-salt",
            "reqid": 1,
        },
        override_authdb_path=db_url,
    )

    assert emailverify["success"] is True
    assert emailverify["user_id"] == user_created["user_id"]
    assert emailverify["is_active"] is True
    assert emailverify["user_role"] == "authenticated"

    # login 1
    # make a new session token
    session_payload = {
        "user_id": emailverify["user_id"],
        "user_agent": "Mozzarella Killerwhale",
        "expires": datetime.utcnow() + timedelta(hours=1),
        "ip_address": "1.1.1.1",
        "extra_info_json": {"pref_datasets_always_private": True},
        "pii_salt": "super-secret-salt",
        "reqid": 1,
    }
    session_token1 = actions.auth_session_new(
        session_payload,
        override_authdb_path=db_url,
    )

    # login 2
    # make a new session token
    session_payload = {
        "user_id": emailverify["user_id"],
        "user_agent": "Searchzilla Oxide",
        "expires": datetime.utcnow() + timedelta(hours=1),
        "ip_address": "1.1.1.2",
        "extra_info_json": {"pref_datasets_always_private": True},
        "pii_salt": "super-secret-salt",
        "reqid": 1,
    }
    # check creation of session
    session_token2 = actions.auth_session_new(
        session_payload,
        override_authdb_path=db_url,
    )

    # login 3
    # make a new session token
    session_payload = {
        "user_id": emailverify["user_id"],
        "user_agent": "Pear Adventure",
        "expires": datetime.utcnow() + timedelta(hours=1),
        "ip_address": "1.1.1.3",
        "extra_info_json": {"pref_datasets_always_private": True},
        "pii_salt": "super-secret-salt",
        "reqid": 1,
    }
    session_token3 = actions.auth_session_new(
        session_payload,
        override_authdb_path=db_url,
    )

    #
    # Now we have three sessions. Kill all of them.
    #

    sessions_killed = actions.auth_delete_sessions_userid(
        {
            "user_id": emailverify["user_id"],
            "session_token": None,
            "keep_current_session": False,
            "pii_salt": "super-secret-salt",
            "reqid": 1,
        },
        raiseonfail=True,
        override_authdb_path=db_url,
    )

    assert sessions_killed["success"] is True

    # check if any of these sessions exist
    session_check_1 = actions.auth_session_exists(
        {
            "session_token": session_token1["session_token"],
            "pii_salt": "super-secret-salt",
            "reqid": 1,
        },
        raiseonfail=True,
        override_authdb_path=db_url,
    )
    assert session_check_1["success"] is False

    session_check_2 = actions.auth_session_exists(
        {
            "session_token": session_token2["session_token"],
            "pii_salt": "super-secret-salt",
            "reqid": 1,
        },
        raiseonfail=True,
        override_authdb_path=db_url,
    )
    assert session_check_2["success"] is False

    session_check_3 = actions.auth_session_exists(
        {
            "session_token": session_token3["session_token"],
            "pii_salt": "super-secret-salt",
            "reqid": 1,
        },
        raiseonfail=True,
        override_authdb_path=db_url,
    )
    assert session_check_3["success"] is False

    #
    # Now login 3 times again
    #

    # login 1
    # make a new session token
    session_payload = {
        "user_id": emailverify["user_id"],
        "user_agent": "Mozzarella Killerwhale",
        "expires": datetime.utcnow() + timedelta(hours=1),
        "ip_address": "1.1.1.1",
        "extra_info_json": {"pref_datasets_always_private": True},
        "pii_salt": "super-secret-salt",
        "reqid": 1,
    }
    session_token1 = actions.auth_session_new(
        session_payload,
        override_authdb_path=db_url,
    )

    # login 2
    # make a new session token
    session_payload = {
        "user_id": emailverify["user_id"],
        "user_agent": "Searchzilla Oxide",
        "expires": datetime.utcnow() + timedelta(hours=1),
        "ip_address": "1.1.1.2",
        "extra_info_json": {"pref_datasets_always_private": True},
        "pii_salt": "super-secret-salt",
        "reqid": 1,
    }
    # check creation of session
    session_token2 = actions.auth_session_new(
        session_payload,
        override_authdb_path=db_url,
    )

    # login 3
    # make a new session token
    session_payload = {
        "user_id": emailverify["user_id"],
        "user_agent": "Pear Adventure",
        "expires": datetime.utcnow() + timedelta(hours=1),
        "ip_address": "1.1.1.3",
        "extra_info_json": {"pref_datasets_always_private": True},
        "pii_salt": "super-secret-salt",
        "reqid": 1,
    }
    session_token3 = actions.auth_session_new(
        session_payload,
        override_authdb_path=db_url,
    )

    #
    # Now we have three sessions. Kill all of them except for the last one.
    #

    sessions_killed = actions.auth_delete_sessions_userid(
        {
            "user_id": emailverify["user_id"],
            "session_token": session_token3["session_token"],
            "keep_current_session": True,
            "pii_salt": "super-secret-salt",
            "reqid": 1,
        },
        raiseonfail=True,
        override_authdb_path=db_url,
    )

    assert sessions_killed["success"] is True

    # check if any of these sessions exist
    session_check_1 = actions.auth_session_exists(
        {
            "session_token": session_token1["session_token"],
            "pii_salt": "super-secret-salt",
            "reqid": 1,
        },
        raiseonfail=True,
        override_authdb_path=db_url,
    )
    assert session_check_1["success"] is False

    session_check_2 = actions.auth_session_exists(
        {
            "session_token": session_token2["session_token"],
            "pii_salt": "super-secret-salt",
            "reqid": 1,
        },
        raiseonfail=True,
        override_authdb_path=db_url,
    )
    assert session_check_2["success"] is False

    session_check_3 = actions.auth_session_exists(
        {
            "session_token": session_token3["session_token"],
            "pii_salt": "super-secret-salt",
            "reqid": 1,
        },
        raiseonfail=True,
        override_authdb_path=db_url,
    )
    assert session_check_3["success"] is True

    currproc = mp.current_process()
    if getattr(currproc, "authdb_meta", None):
        del currproc.authdb_meta

    if getattr(currproc, "connection", None):
        currproc.authdb_conn.close()
        del currproc.authdb_conn

    if getattr(currproc, "authdb_engine", None):
        currproc.authdb_engine.dispose()
        del currproc.authdb_engine

    try:
        os.remove(db_file)
    except Exception:
        pass
