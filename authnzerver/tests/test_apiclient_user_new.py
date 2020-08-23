"""
This contains tests for the authnzerver apiclient module.

"""

import os
import secrets

import pytest

from authnzerver.apiclient import APIClient


@pytest.mark.skipif(
    os.environ.get("GITHUB_WORKFLOW", None) is not None,
    reason="github doesn't allow server tests probably"
)
def test_user_new(new_authnzerver):
    '''
    This tests if the server does rate-limiting correctly.

    '''

    authnzerver_url, authnzerver_secret = new_authnzerver

    srv = APIClient(
        authnzerver_url=authnzerver_url,
        authnzerver_secret=authnzerver_secret
    )

    password = secrets.token_urlsafe(20)

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
