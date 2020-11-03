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
def test_user_new(new_authnzerver):
    '''
    This tests apiclient.user_new().

    '''

    authnzerver_url, authnzerver_secret = new_authnzerver

    srv = APIClient(
        authnzerver_url=authnzerver_url,
        authnzerver_secret=authnzerver_secret
    )

    password = "OLvXU7zeeoZEYo2ZH875"

    resp = srv.user_new(
        "Test User",
        "testuser@example.com",
        password,
        system_id="some-random-system-id",
    )

    assert resp.success is True
    assert resp.response["user_id"] == 4
    assert resp.response["system_id"] == "some-random-system-id"
    assert resp.response["send_verification"] is True
    assert resp.messages == [
        "User account created. Please verify your email address to log in."
    ]


@pytest.mark.skipif(
    os.environ.get("GITHUB_WORKFLOW", None) is not None,
    reason="github doesn't allow server tests probably"
)
def test_user_new_with_extra_info(new_authnzerver):
    '''
    This tests apiclient.user_new().

    '''

    authnzerver_url, authnzerver_secret = new_authnzerver

    srv = APIClient(
        authnzerver_url=authnzerver_url,
        authnzerver_secret=authnzerver_secret
    )

    password = "OLvXU7zeeoZEYo2ZH875"

    resp = srv.user_new(
        "Test User",
        "testuser@example.com",
        password,
        extra_info={
            "arbitrary key": "arbitrary info",
            "hello": "world!",
            "test dict": {
                "hello": "there!"
            }
        },
        verify_retry_wait=2,
    )

    assert resp.success is True
    assert resp.response["user_id"] == 4
    assert resp.response["send_verification"] is True
    assert resp.messages == [
        "User account created. Please verify your email address to log in."
    ]

    # look up the user's information and check if extra_info and
    # verify_retry_wait were populated correctly
    resp = srv.user_lookup_email("testuser@example.com")
    assert resp.success is True
    user_extra_info = resp.response["user_info"]["extra_info"]
    assert user_extra_info["arbitrary key"] == "arbitrary info"
    assert user_extra_info["hello"] == "world!"
    assert user_extra_info["test dict"] == {"hello": "there!"}
    assert user_extra_info["verify_retry_wait"] == 2
