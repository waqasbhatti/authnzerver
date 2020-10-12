"""
This contains tests for the authnzerver apiclient module.

"""

import os
import json

import pytest

from authnzerver.apiclient import APIClient


@pytest.mark.skipif(
    os.environ.get("GITHUB_WORKFLOW", None) is not None,
    reason="github doesn't allow server tests probably"
)
def test_apikey_refresh_nosession(new_authnzerver):
    '''
    This tests apiclient.user_delete().

    '''

    authnzerver_url, authnzerver_secret = new_authnzerver

    srv = APIClient(
        authnzerver_url=authnzerver_url,
        authnzerver_secret=authnzerver_secret,
        use_kwargs=True
    )

    password = "OLvXU7zeeoZEYo2ZH875"

    # 1. create the user
    new_user = srv.user_new(
        full_name="Test User",
        email="testuser@example.com",
        password=password
    )

    assert new_user.success is True
    assert new_user.response["user_id"] == 4
    assert new_user.response["send_verification"] is True
    assert new_user.messages == [
        "User account created. Please verify your email address to log in."
    ]

    # 2. activate them
    activation = srv.user_set_emailverified(email="testuser@example.com")
    assert activation.success is True

    # 3. make a new no-session API key
    new_apikey = srv.apikey_new_nosession(
        issuer="Authnzerver",
        audience="test-apikey-server.internal",
        subject="/test/apikey/endpoint",
        apiversion=1,
        expires_seconds=30,
        not_valid_before=1,
        refresh_expires=60,
        refresh_nbf=1,
        user_id=new_user.response["user_id"],
        user_role="authenticated",
        ip_address="1.2.3.4"
    )

    assert new_apikey.success is True
    apikey_json = new_apikey.response["apikey"]
    apikey_refreshtoken = new_apikey.response["refresh_token"]
    apikey_dict = json.loads(apikey_json)

    # 4. wait a couple of seconds and then try to refresh the key
