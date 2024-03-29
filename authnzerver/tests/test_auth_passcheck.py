"""test_auth_actions.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Sep 2018
License: MIT. See the LICENSE file for details.

This contains tests for the auth functions in authnzerver.actions.

"""

from .. import authdb, actions
import os.path
import os
from datetime import datetime, timedelta
import multiprocessing as mp
from .test_support import get_public_suffix_list


def get_test_authdb():
    """This just makes a new test auth DB for each test function."""

    authdb.create_sqlite_authdb("test-passcheck.authdb.sqlite")
    authdb.initial_authdb_inserts("sqlite:///test-passcheck.authdb.sqlite")


def test_passcheck():
    """
    This tests if we can check the password for a logged-in user.

    """

    try:
        os.remove("test-passcheck.authdb.sqlite")
    except Exception:
        pass
    try:
        os.remove("test-passcheck.authdb.sqlite-shm")
    except Exception:
        pass
    try:
        os.remove("test-passcheck.authdb.sqlite-wal")
    except Exception:
        pass

    get_test_authdb()
    get_public_suffix_list()

    # create the user
    user_payload = {
        "full_name": "Test User",
        "email": "testuser-passcheck@test.org",
        "password": "aROwQin9L8nNtPTEMLXd",
        "pii_salt": "super-secret-salt",
        "reqid": 1,
    }
    user_created = actions.create_new_user(
        user_payload,
        override_authdb_path="sqlite:///test-passcheck.authdb.sqlite",
    )
    assert user_created["success"] is True
    assert user_created["user_email"] == "testuser-passcheck@test.org"
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
        override_authdb_path="sqlite:///test-passcheck.authdb.sqlite",
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
        override_authdb_path="sqlite:///test-passcheck.authdb.sqlite",
    )

    assert emailverify["success"] is True
    assert emailverify["user_id"] == user_created["user_id"]
    assert emailverify["is_active"] is True
    assert emailverify["user_role"] == "authenticated"

    # now make a new session token to simulate a logged-in user
    session_payload = {
        "user_id": emailverify["user_id"],
        "user_agent": "Mozzarella Killerwhale",
        "expires": datetime.utcnow() + timedelta(hours=1),
        "ip_address": "1.1.1.1",
        "extra_info_json": {"pref_datasets_always_private": True},
        "pii_salt": "super-secret-salt",
        "reqid": 1,
    }

    # check creation of session
    session_token2 = actions.auth_session_new(
        session_payload,
        override_authdb_path="sqlite:///test-passcheck.authdb.sqlite",
    )
    assert session_token2["success"] is True
    assert session_token2["session_token"] is not None

    #
    # now run a password check
    #

    # correct password
    pass_check = actions.auth_password_check(
        {
            "session_token": session_token2["session_token"],
            "password": user_payload["password"],
            "pii_salt": "super-secret-salt",
            "reqid": 1,
        },
        override_authdb_path="sqlite:///test-passcheck.authdb.sqlite",
        raiseonfail=True,
    )
    assert pass_check["success"] is True
    assert pass_check["user_id"] == emailverify["user_id"]

    # incorrect password
    pass_check = actions.auth_password_check(
        {
            "session_token": session_token2["session_token"],
            "password": "incorrectponylithiumfastener",
            "pii_salt": "super-secret-salt",
            "reqid": 1,
        },
        override_authdb_path="sqlite:///test-passcheck.authdb.sqlite",
        raiseonfail=True,
    )
    assert pass_check["success"] is False
    assert pass_check["user_id"] is None

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
        os.remove("test-passcheck.authdb.sqlite")
    except Exception:
        pass
    try:
        os.remove("test-passcheck.authdb.sqlite-shm")
    except Exception:
        pass
    try:
        os.remove("test-passcheck.authdb.sqlite-wal")
    except Exception:
        pass


def test_passcheck_nosession():
    """
    This tests if we can check the password for a user with their email and
    password only, with no need for an existing session.

    """

    try:
        os.remove("test-passcheck.authdb.sqlite")
    except Exception:
        pass
    try:
        os.remove("test-passcheck.authdb.sqlite-shm")
    except Exception:
        pass
    try:
        os.remove("test-passcheck.authdb.sqlite-wal")
    except Exception:
        pass

    get_test_authdb()

    # create the user
    user_payload = {
        "full_name": "Test User",
        "email": "testuser-passcheck@test.org",
        "password": "aROwQin9L8nNtPTEMLXd",
        "pii_salt": "super-secret-salt",
        "reqid": 1,
    }
    user_created = actions.create_new_user(
        user_payload,
        override_authdb_path="sqlite:///test-passcheck.authdb.sqlite",
    )
    assert user_created["success"] is True
    assert user_created["user_email"] == "testuser-passcheck@test.org"
    assert (
        "User account created. Please verify your email address to log in."
        in user_created["messages"]
    )

    # verify our email
    emailverify = actions.set_user_emailaddr_verified(
        {
            "email": user_payload["email"],
            "user_id": user_created["user_id"],
            "pii_salt": "super-secret-salt",
            "reqid": 1,
        },
        override_authdb_path="sqlite:///test-passcheck.authdb.sqlite",
    )

    assert emailverify["success"] is True
    assert emailverify["user_id"] == user_created["user_id"]
    assert emailverify["is_active"] is True
    assert emailverify["user_role"] == "authenticated"

    #
    # now run a password check
    #

    # correct password
    pass_check = actions.auth_password_check_nosession(
        {
            "email": user_payload["email"],
            "password": user_payload["password"],
            "pii_salt": "super-secret-salt",
            "reqid": 1,
        },
        override_authdb_path="sqlite:///test-passcheck.authdb.sqlite",
        raiseonfail=True,
    )
    assert pass_check["success"] is True
    assert pass_check["user_id"] == emailverify["user_id"]

    # incorrect password
    pass_check = actions.auth_password_check_nosession(
        {
            "email": user_payload["email"],
            "password": "incorrectponylithiumfastener",
            "pii_salt": "super-secret-salt",
            "reqid": 1,
        },
        override_authdb_path="sqlite:///test-passcheck.authdb.sqlite",
        raiseonfail=True,
    )
    assert pass_check["success"] is False
    assert pass_check["user_id"] is None

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
        os.remove("test-passcheck.authdb.sqlite")
    except Exception:
        pass
    try:
        os.remove("test-passcheck.authdb.sqlite-shm")
    except Exception:
        pass
    try:
        os.remove("test-passcheck.authdb.sqlite-wal")
    except Exception:
        pass
