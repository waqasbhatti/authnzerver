"""
This contains tests for the authnzerver apiclient module.

"""

import os

import pytest

from authnzerver.apiclient import APIClient


@pytest.mark.skipif(
    os.environ.get("GITHUB_WORKFLOW", None) is not None,
    reason="github doesn't allow server tests probably"
)
def test_user_delete(new_authnzerver):
    '''
    This tests apiclient.user_delete().

    '''

    authnzerver_url, authnzerver_secret = new_authnzerver

    srv = APIClient(
        authnzerver_url=authnzerver_url,
        authnzerver_secret=authnzerver_secret
    )

    password = "OLvXU7zeeoZEYo2ZH875"

    # 1. create the user
    resp = srv.user_new(
        "Test User",
        "testuser@example.com",
        password
    )

    assert resp.success is True
    assert resp.response["user_id"] == 4
    assert resp.response["send_verification"] is True
    assert resp.messages == [
        "User account created. Please verify your email address to log in."
    ]

    # 2. activate them
    resp = srv.user_set_emailverified("testuser@example.com")
    assert resp.success is True

    # 3. delete them
    resp = srv.user_delete("testuser@example.com", 4, password)
    assert resp.success is True

    # 4. try to do a pass-check as the deleted user
    resp = srv.user_passcheck_nosession("testuser@example.com", password)
    assert resp.success is False
