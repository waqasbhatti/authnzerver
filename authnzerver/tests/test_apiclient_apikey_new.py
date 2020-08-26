"""
This contains tests for the authnzerver apiclient module.

"""

import os
from datetime import datetime, timedelta
import json

import pytest

from authnzerver.apiclient import APIClient


@pytest.mark.skipif(
    os.environ.get("GITHUB_WORKFLOW", None) is not None,
    reason="github doesn't allow server tests probably"
)
def test_apikey_new(new_authnzerver):
    '''
    This tests apiclient.apikey_new().

    '''

    authnzerver_url, authnzerver_secret = new_authnzerver

    srv = APIClient(
        authnzerver_url=authnzerver_url,
        authnzerver_secret=authnzerver_secret
    )

    password = "OLvXU7zeeoZEYo2ZH875"

    # 1. create the user
    new_user = srv.user_new(
        "Test User",
        "testuser@example.com",
        password
    )

    assert new_user.success is True
    assert new_user.response["user_id"] == 4
    assert new_user.response["send_verification"] is True
    assert new_user.messages == [
        "User account created. Please verify your email address to log in."
    ]

    # 2. activate them
    activate = srv.user_set_emailverified("testuser@example.com")
    assert activate.success is True

    # 3. create a new session tied to this user
    session = srv.session_new(
        "127.0.0.1",
        "Mozzarella T-Rex",
        4,
        (datetime.utcnow() + timedelta(days=1)).isoformat(),
        None,
    )
    assert session.success is True
    session_token = session.response["session_token"]

    # 4. create an API key for them
    new_apikey = srv.apikey_new(
        "Authnzerver",
        "test-apikey-server.internal",
        "/test/apikey/endpoint",
        1,
        30,
        1,
        new_user.response["user_id"],
        "authenticated",
        "127.0.0.1",
        "Mozzarella T-Rex",
        session_token
    )
    assert new_apikey.success is True
    apikey_json = new_apikey.response["apikey"]
    apikey_dict = json.loads(apikey_json)

    assert apikey_dict["iss"] == "Authnzerver"
    assert apikey_dict["ver"] == 1
    assert apikey_dict["uid"] == 4
    assert apikey_dict["rol"] == "authenticated"
    assert apikey_dict["usa"] == "Mozzarella T-Rex"
    assert apikey_dict["aud"] == "test-apikey-server.internal"
    assert apikey_dict["sub"] == "/test/apikey/endpoint"
    assert apikey_dict["ipa"] == "127.0.0.1"
