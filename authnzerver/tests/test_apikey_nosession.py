"""
This contains tests for actions/apikey_nosession.py.

"""

import time
import os.path
import json
import multiprocessing as mp

import py.path

from authnzerver import authdb, actions
from .test_support import get_public_suffix_list


this_dir = os.path.abspath(os.path.dirname(__file__))
permissions_json = os.path.join(
    this_dir, "..", "default-permissions-model.json"
)


def get_test_authdb(tmpdir):
    """This just makes a new test auth DB for each test function."""

    if not isinstance(tmpdir, py.path.local):
        tmpdir = py.path.local(tmpdir)

    dbpath = str(tmpdir.join("test-apikey.authdb.sqlite"))

    authdb.create_sqlite_authdb(dbpath)
    authdb.initial_authdb_inserts("sqlite:///%s" % dbpath)

    return "sqlite:///%s" % dbpath


def delete_test_authdb(tmpdir):
    """
    This removes the authdb in the tmpdir.

    """
    try:
        os.remove(os.path.join(tmpdir, "test-apikey.authdb.sqlite"))
    except Exception:
        pass
    try:
        os.remove(os.path.join(tmpdir, "test-apikey.authdb.sqlite-wal"))
    except Exception:
        pass
    try:
        os.remove(os.path.join(tmpdir, "test-apikey.authdb.sqlite-shm"))
    except Exception:
        pass


def teardown():
    currproc = mp.current_process()
    if getattr(currproc, "authdb_meta", None):
        del currproc.authdb_meta

    if getattr(currproc, "connection", None):
        currproc.authdb_conn.close()
        del currproc.authdb_conn

    if getattr(currproc, "authdb_engine", None):
        currproc.authdb_engine.dispose()
        del currproc.authdb_engine


def test_issue_apikey(tmpdir):
    """
    Test if issuing an API key works.

    """

    delete_test_authdb(tmpdir)
    test_authdb_url = get_test_authdb(tmpdir)
    teardown()

    get_public_suffix_list()

    # 1. create a new user
    payload = {
        "full_name": "Test User",
        "email": "testuser@test.org",
        "password": "aROwQin9L8nNtPTEMLXd",
        "reqid": 1,
        "pii_salt": "super-secret-salt",
    }
    user_created = actions.create_new_user(
        payload, raiseonfail=True, override_authdb_path=test_authdb_url
    )
    assert user_created["success"] is True
    assert user_created["user_email"] == "testuser@test.org"
    assert user_created["user_id"] == 4

    # 2. verify their email
    email_verified_info = actions.set_user_emailaddr_verified(
        {
            "email": "testuser@test.org",
            "reqid": 2,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
    )

    assert email_verified_info["success"] is True
    assert email_verified_info["user_id"] == 4
    assert email_verified_info["is_active"] is True
    assert email_verified_info["user_role"] == "authenticated"

    # 3. generate an API key
    apikey_issue_payload = {
        "issuer": "authnzerver",
        "audience": "test-service",
        "subject": "/test-endpoint",
        "apiversion": 1,
        "expires_seconds": 7,
        "not_valid_before": 1,
        "user_id": 4,
        "user_role": "authenticated",
        "ip_address": "1.2.3.4",
        "refresh_expires": 10,
        "refresh_nbf": 2,
        "reqid": 3,
        "pii_salt": "super-secret-salt",
    }

    apikey_info = actions.issue_apikey_nosession(
        apikey_issue_payload,
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )

    assert apikey_info["success"] is True
    for key in ("apikey", "expires", "refresh_token", "refresh_token_expires"):
        assert key in apikey_info

    apikey = json.loads(apikey_info["apikey"])

    assert apikey["ipa"] == apikey_issue_payload["ip_address"]
    assert apikey["uid"] == apikey_issue_payload["user_id"]
    assert apikey["rol"] == apikey_issue_payload["user_role"]

    teardown()


def test_verify_apikey(tmpdir):
    """
    This tests if the issued API key can be verified:

    - within expiry time
    - within expiry but with other user
    - after expiry time

    """

    delete_test_authdb(tmpdir)
    test_authdb_url = get_test_authdb(tmpdir)
    teardown()

    get_public_suffix_list()

    # 1. create a couple of new users
    payload = {
        "full_name": "Test User",
        "email": "testuser@test.org",
        "password": "aROwQin9L8nNtPTEMLXd",
        "reqid": 1,
        "pii_salt": "super-secret-salt",
    }
    user_created = actions.create_new_user(
        payload, raiseonfail=True, override_authdb_path=test_authdb_url
    )
    assert user_created["success"] is True
    assert user_created["user_email"] == "testuser@test.org"
    assert user_created["user_id"] == 4

    payload = {
        "full_name": "Another Test User",
        "email": "testuse2r@test.org",
        "password": "aROwQin9L8nNtPTEMLXd",
        "reqid": 2,
        "pii_salt": "super-secret-salt",
    }
    user_created = actions.create_new_user(
        payload, raiseonfail=True, override_authdb_path=test_authdb_url
    )
    assert user_created["success"] is True
    assert user_created["user_email"] == "testuse2r@test.org"
    assert user_created["user_id"] == 5

    # 2. verify their emails
    email_verified_info = actions.set_user_emailaddr_verified(
        {
            "email": "testuser@test.org",
            "reqid": 3,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
    )

    assert email_verified_info["success"] is True
    assert email_verified_info["user_id"] == 4
    assert email_verified_info["is_active"] is True
    assert email_verified_info["user_role"] == "authenticated"

    email_verified_info = actions.set_user_emailaddr_verified(
        {
            "email": "testuse2r@test.org",
            "reqid": 4,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
    )

    assert email_verified_info["success"] is True
    assert email_verified_info["user_id"] == 5
    assert email_verified_info["is_active"] is True
    assert email_verified_info["user_role"] == "authenticated"

    # 3. generate an API key for the first user
    apikey_issue_payload = {
        "issuer": "authnzerver",
        "audience": "test-service",
        "subject": "/test-endpoint",
        "apiversion": 1,
        "expires_seconds": 6,
        "not_valid_before": 2,
        "user_id": 4,
        "user_role": "authenticated",
        "ip_address": "1.2.3.4",
        "refresh_expires": 10,
        "refresh_nbf": 2,
        "reqid": 4,
        "pii_salt": "super-secret-salt",
    }

    apikey_info = actions.issue_apikey_nosession(
        apikey_issue_payload,
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )
    assert apikey_info["success"] is True

    apikey_dict = json.loads(apikey_info["apikey"])

    # 4. try to verify the API key immediately - should fail because of
    # not-before
    apikey_verification = actions.verify_apikey_nosession(
        {
            "apikey_dict": apikey_dict,
            "user_id": 4,
            "user_role": "authenticated",
            "reqid": 5,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )
    assert apikey_verification["success"] is False

    # 5. wait 3 seconds, then verify again - this should pass
    time.sleep(3)
    apikey_verification = actions.verify_apikey_nosession(
        {
            "apikey_dict": apikey_dict,
            "user_id": 4,
            "user_role": "authenticated",
            "reqid": 6,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )
    assert apikey_verification["success"] is True

    # 6. try to verify the API key as a different user - this should fail
    apikey_verification = actions.verify_apikey_nosession(
        {
            "apikey_dict": apikey_dict,
            "user_id": 5,
            "user_role": "authenticated",
            "reqid": 6,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )
    assert apikey_verification["success"] is False

    # 7. wait 6 seconds, then try to reverify the API key as the original user
    # it should have expired by now so this should fail
    time.sleep(6)
    apikey_verification = actions.verify_apikey_nosession(
        {
            "apikey_dict": apikey_dict,
            "user_id": 4,
            "user_role": "authenticated",
            "reqid": 7,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
    )
    assert apikey_verification["success"] is False

    teardown()


def test_revoke_apikey(tmpdir):
    """
    This tests if an apikey can be revoked.

    - by the original user
    - by another user who somehow gets the API key

    """

    delete_test_authdb(tmpdir)
    test_authdb_url = get_test_authdb(tmpdir)
    teardown()

    get_public_suffix_list()

    # 1. create a couple of new users
    payload = {
        "full_name": "Test User",
        "email": "testuser@test.org",
        "password": "aROwQin9L8nNtPTEMLXd",
        "reqid": 1,
        "pii_salt": "super-secret-salt",
    }
    user_created = actions.create_new_user(
        payload, raiseonfail=True, override_authdb_path=test_authdb_url
    )
    assert user_created["success"] is True
    assert user_created["user_email"] == "testuser@test.org"
    assert user_created["user_id"] == 4

    payload = {
        "full_name": "Another Test User",
        "email": "testuse2r@test.org",
        "password": "aROwQin9L8nNtPTEMLXd",
        "reqid": 2,
        "pii_salt": "super-secret-salt",
    }
    user_created = actions.create_new_user(
        payload, raiseonfail=True, override_authdb_path=test_authdb_url
    )
    assert user_created["success"] is True
    assert user_created["user_email"] == "testuse2r@test.org"
    assert user_created["user_id"] == 5

    # 2. verify their emails
    email_verified_info = actions.set_user_emailaddr_verified(
        {
            "email": "testuser@test.org",
            "reqid": 3,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
    )

    assert email_verified_info["success"] is True
    assert email_verified_info["user_id"] == 4
    assert email_verified_info["is_active"] is True
    assert email_verified_info["user_role"] == "authenticated"

    email_verified_info = actions.set_user_emailaddr_verified(
        {
            "email": "testuse2r@test.org",
            "reqid": 4,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
    )

    assert email_verified_info["success"] is True
    assert email_verified_info["user_id"] == 5
    assert email_verified_info["is_active"] is True
    assert email_verified_info["user_role"] == "authenticated"

    # 3. generate an API key for the first user
    apikey_issue_payload = {
        "issuer": "authnzerver",
        "audience": "test-service",
        "subject": "/test-endpoint",
        "apiversion": 1,
        "expires_seconds": 6,
        "not_valid_before": 2,
        "user_id": 4,
        "user_role": "authenticated",
        "ip_address": "1.2.3.4",
        "refresh_expires": 10,
        "refresh_nbf": 2,
        "reqid": 5,
        "pii_salt": "super-secret-salt",
    }

    apikey_info = actions.issue_apikey_nosession(
        apikey_issue_payload,
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )
    assert apikey_info["success"] is True

    apikey_dict = json.loads(apikey_info["apikey"])
    time.sleep(2)

    # 4. try to revoke the API key as a different user
    # this should fail
    apikey_revocation = actions.revoke_apikey_nosession(
        {
            "apikey_dict": apikey_dict,
            "user_id": 5,
            "user_role": "authenticated",
            "reqid": 6,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )
    assert apikey_revocation["success"] is False

    # 5. try to revoke the API key as the correct user
    # this should pass
    apikey_revocation = actions.revoke_apikey_nosession(
        {
            "apikey_dict": apikey_dict,
            "user_id": 4,
            "user_role": "authenticated",
            "reqid": 7,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )
    assert apikey_revocation["success"] is True

    # 6. try to verify the API key after it has been revoked
    # this should fail
    apikey_verification = actions.verify_apikey_nosession(
        {
            "apikey_dict": apikey_dict,
            "user_id": 4,
            "user_role": "authenticated",
            "reqid": 8,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )
    assert apikey_verification["success"] is False

    # 7. try to verify the API key as a different user - this should fail anyway
    apikey_verification = actions.verify_apikey_nosession(
        {
            "apikey_dict": apikey_dict,
            "user_id": 5,
            "user_role": "authenticated",
            "reqid": 9,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )
    assert apikey_verification["success"] is False

    teardown()


def test_revoke_all_apikeys(tmpdir):
    """
    This tests if all API keys for a user can be revoked.

    """

    delete_test_authdb(tmpdir)
    test_authdb_url = get_test_authdb(tmpdir)
    teardown()

    get_public_suffix_list()

    # 1. create a new user
    payload = {
        "full_name": "Test User",
        "email": "testuser@test.org",
        "password": "aROwQin9L8nNtPTEMLXd",
        "reqid": 1,
        "pii_salt": "super-secret-salt",
    }
    user_created = actions.create_new_user(
        payload, raiseonfail=True, override_authdb_path=test_authdb_url
    )
    assert user_created["success"] is True
    assert user_created["user_email"] == "testuser@test.org"
    assert user_created["user_id"] == 4

    # 2. verify their email
    email_verified_info = actions.set_user_emailaddr_verified(
        {
            "email": "testuser@test.org",
            "reqid": 2,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
    )

    assert email_verified_info["success"] is True
    assert email_verified_info["user_id"] == 4
    assert email_verified_info["is_active"] is True
    assert email_verified_info["user_role"] == "authenticated"

    # 3. generate a couple of API keys
    apikey_payload_one = {
        "issuer": "authnzerver",
        "audience": "test-service",
        "subject": "/test-endpoint-one",
        "apiversion": 1,
        "expires_seconds": 7,
        "not_valid_before": 1,
        "user_id": 4,
        "user_role": "authenticated",
        "ip_address": "1.2.3.4",
        "refresh_expires": 10,
        "refresh_nbf": 2,
        "reqid": 3,
        "pii_salt": "super-secret-salt",
    }

    apikey_info_one = actions.issue_apikey_nosession(
        apikey_payload_one,
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )

    apikey_one = json.loads(apikey_info_one["apikey"])

    apikey_payload_two = {
        "issuer": "authnzerver",
        "audience": "test-service",
        "subject": "/test-endpoint-two",
        "apiversion": 1,
        "expires_seconds": 7,
        "not_valid_before": 1,
        "user_id": 4,
        "user_role": "authenticated",
        "ip_address": "1.2.3.4",
        "refresh_expires": 10,
        "refresh_nbf": 2,
        "reqid": 3,
        "pii_salt": "super-secret-salt",
    }

    apikey_info_two = actions.issue_apikey_nosession(
        apikey_payload_two,
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )

    apikey_two = json.loads(apikey_info_two["apikey"])

    time.sleep(2)

    # 1. try to revoke all API keys with an incorrect API key
    good_tkn = apikey_one["tkn"]
    apikey_one["tkn"] = "haha-bad-token"
    revoke_one = actions.revoke_all_apikeys_nosession(
        {
            "apikey_dict": apikey_one,
            "user_id": 4,
            "user_role": "authenticated",
            "reqid": 2,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )
    assert revoke_one["success"] is False

    # 2. try to revoke all API keys with a correct API key
    revoke_two = actions.revoke_all_apikeys_nosession(
        {
            "apikey_dict": apikey_two,
            "user_id": 4,
            "user_role": "authenticated",
            "reqid": 2,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )
    assert revoke_two["success"] is True

    # 3. make sure we can't use any API key afterwards
    apikey_one["tkn"] = good_tkn

    verify_one = actions.verify_apikey_nosession(
        {
            "apikey_dict": apikey_one,
            "user_id": 4,
            "user_role": "authenticated",
            "reqid": 3,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )
    assert verify_one["success"] is False

    verify_two = actions.verify_apikey_nosession(
        {
            "apikey_dict": apikey_two,
            "user_id": 4,
            "user_role": "authenticated",
            "reqid": 4,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )
    assert verify_two["success"] is False

    teardown()


def test_refresh_apikey(tmpdir):
    """
    This tests refreshing an API key.

    - before it expires
    - after it expires
    - with an unexpired correct refresh token
    - with the incorrect refresh token
    - with an expired refresh token

    """

    delete_test_authdb(tmpdir)
    test_authdb_url = get_test_authdb(tmpdir)
    teardown()

    get_public_suffix_list()

    # 1. create a new user
    payload = {
        "full_name": "Test User",
        "email": "testuser@test.org",
        "password": "aROwQin9L8nNtPTEMLXd",
        "reqid": 1,
        "pii_salt": "super-secret-salt",
    }
    user_created = actions.create_new_user(
        payload, raiseonfail=True, override_authdb_path=test_authdb_url
    )
    assert user_created["success"] is True
    assert user_created["user_email"] == "testuser@test.org"
    assert user_created["user_id"] == 4

    # 2. verify their email
    email_verified_info = actions.set_user_emailaddr_verified(
        {
            "email": "testuser@test.org",
            "reqid": 2,
            "pii_salt": "super-secret-salt",
        },
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
    )

    assert email_verified_info["success"] is True
    assert email_verified_info["user_id"] == 4
    assert email_verified_info["is_active"] is True
    assert email_verified_info["user_role"] == "authenticated"

    # 3. generate an API key
    apikey_issue_payload = {
        "issuer": "authnzerver",
        "audience": "test-service",
        "subject": "/test-endpoint",
        "apiversion": 1,
        "expires_seconds": 6,
        "not_valid_before": 1,
        "user_id": 4,
        "user_role": "authenticated",
        "ip_address": "1.2.3.4",
        "refresh_expires": 10,
        "refresh_nbf": 1,
        "reqid": 3,
        "pii_salt": "super-secret-salt",
    }

    apikey_info = actions.issue_apikey_nosession(
        apikey_issue_payload,
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )

    assert apikey_info["success"] is True
    for key in ("apikey", "expires", "refresh_token", "refresh_token_expires"):
        assert key in apikey_info

    apikey = json.loads(apikey_info["apikey"])

    assert apikey["ipa"] == apikey_issue_payload["ip_address"]
    assert apikey["uid"] == apikey_issue_payload["user_id"]
    assert apikey["rol"] == apikey_issue_payload["user_role"]

    # 4. refresh the key immediately - this should fail because of refresh_nbf
    apikey_refresh_payload = {
        "apikey_dict": apikey,
        "user_id": 4,
        "user_role": "authenticated",
        "refresh_token": apikey_info["refresh_token"],
        "ip_address": "1.2.3.4",
        "expires_seconds": 4,
        "not_valid_before": 1,
        "refresh_expires": 10,
        "refresh_nbf": 1,
        "reqid": 3,
        "pii_salt": "super-secret-salt",
    }

    refreshed_apikey = actions.refresh_apikey_nosession(
        apikey_refresh_payload,
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )

    assert refreshed_apikey["success"] is False

    # 5. now try to refresh within the lifetime of the key but with incorrect
    # refresh token - should fail
    time.sleep(2)

    apikey_refresh_payload["refresh_token"] = "haha wrong token"

    refreshed_apikey = actions.refresh_apikey_nosession(
        apikey_refresh_payload,
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )

    assert refreshed_apikey["success"] is False

    # 6. now try to refresh with correct refresh token - should pass
    apikey_refresh_payload["refresh_token"] = apikey_info["refresh_token"]

    refreshed_apikey = actions.refresh_apikey_nosession(
        apikey_refresh_payload,
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )

    assert refreshed_apikey["success"] is True

    # 7. now try to refresh after the key expires - should pass
    time.sleep(6)

    refreshed_apikey_dict = json.loads(refreshed_apikey["apikey"])

    apikey_refresh_payload = {
        "apikey_dict": refreshed_apikey_dict,
        "user_id": 4,
        "user_role": "authenticated",
        "refresh_token": refreshed_apikey["refresh_token"],
        "ip_address": "1.2.3.4",
        "expires_seconds": 4,
        "not_valid_before": 1,
        "refresh_expires": 5,
        "refresh_nbf": 1,
        "reqid": 3,
        "pii_salt": "super-secret-salt",
    }

    refreshed_apikey = actions.refresh_apikey_nosession(
        apikey_refresh_payload,
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )

    assert refreshed_apikey["success"] is True

    # 8. now try to refresh after the refresh token expires - should fail
    time.sleep(6)

    refreshed_apikey = actions.refresh_apikey_nosession(
        apikey_refresh_payload,
        raiseonfail=True,
        override_authdb_path=test_authdb_url,
        override_permissions_json=permissions_json,
    )

    assert refreshed_apikey["success"] is False

    teardown()
