# -*- coding: utf-8 -*-
# test_permissions_locked.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug
# 2018
# License: MIT - see the LICENSE file for the full text.

"""
This tests permissions for locked users

"""

import os.path
import pytest
from authnzerver import permissions


######################
## LOCKED ACCESS ##
######################


@pytest.mark.parametrize(
    "access,target,expected",
    [
        # locked -> self-owned private collection
        ((2, "locked", "list"), ("collection", 2, "private", ""), False),
        ((2, "locked", "view"), ("collection", 2, "private", ""), False),
        ((2, "locked", "create"), ("collection", 2, "private", ""), False),
        ((2, "locked", "edit"), ("collection", 2, "private", ""), False),
        ((2, "locked", "delete"), ("collection", 2, "private", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("collection", 2, "private", ""),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("collection", 2, "private", ""),
            False,
        ),
        # locked -> self-owned shared collection
        ((2, "locked", "list"), ("collection", 2, "shared", ""), False),
        ((2, "locked", "view"), ("collection", 2, "shared", ""), False),
        ((2, "locked", "create"), ("collection", 2, "shared", ""), False),
        ((2, "locked", "edit"), ("collection", 2, "shared", ""), False),
        ((2, "locked", "delete"), ("collection", 2, "shared", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("collection", 2, "shared", ""),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("collection", 2, "shared", ""),
            False,
        ),
        # locked -> self-owned public collection
        ((2, "locked", "list"), ("collection", 2, "public", ""), False),
        ((2, "locked", "view"), ("collection", 2, "public", ""), False),
        ((2, "locked", "create"), ("collection", 2, "public", ""), False),
        ((2, "locked", "edit"), ("collection", 2, "public", ""), False),
        ((2, "locked", "delete"), ("collection", 2, "public", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("collection", 2, "public", ""),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("collection", 2, "public", ""),
            False,
        ),
        # locked -> public collection from others
        ((2, "locked", "list"), ("collection", 1, "public", ""), False),
        ((2, "locked", "view"), ("collection", 1, "public", ""), False),
        ((2, "locked", "create"), ("collection", 1, "public", ""), False),
        ((2, "locked", "edit"), ("collection", 1, "public", ""), False),
        ((2, "locked", "delete"), ("collection", 1, "public", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("collection", 1, "public", ""),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("collection", 1, "public", ""),
            False,
        ),
        # locked -> shared collection from others
        ((2, "locked", "list"), ("collection", 1, "shared", "2,5,6"), False),
        ((2, "locked", "view"), ("collection", 1, "shared", "2,5,6"), False),
        ((2, "locked", "create"), ("collection", 1, "shared", "2,5,6"), False),
        ((2, "locked", "edit"), ("collection", 1, "shared", "2,5,6"), False),
        ((2, "locked", "delete"), ("collection", 1, "shared", "2,5,6"), False),
        (
            (2, "locked", "change_visibility"),
            ("collection", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("collection", 1, "shared", "2,5,6"),
            False,
        ),
        # locked -> shared from others but not shared to this
        # user (should all fail)
        ((2, "locked", "list"), ("collection", 1, "shared", "5,6"), False),
        ((2, "locked", "view"), ("collection", 1, "shared", "5,6"), False),
        ((2, "locked", "create"), ("collection", 1, "shared", "5,6"), False),
        ((2, "locked", "edit"), ("collection", 1, "shared", "5,6"), False),
        ((2, "locked", "delete"), ("collection", 1, "shared", "5,6"), False),
        (
            (2, "locked", "change_visibility"),
            ("collection", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("collection", 1, "shared", "5,6"),
            False,
        ),
        # locked -> private collection from others
        ((2, "locked", "list"), ("collection", 1, "private", ""), False),
        ((2, "locked", "view"), ("collection", 1, "private", ""), False),
        ((2, "locked", "create"), ("collection", 1, "private", ""), False),
        ((2, "locked", "edit"), ("collection", 1, "private", ""), False),
        ((2, "locked", "delete"), ("collection", 1, "private", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("collection", 1, "private", ""),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("collection", 1, "private", ""),
            False,
        ),
    ],
)
def test_check_locked_access_to_collection(access, target, expected):
    """
    This checks user access.

    """
    userid, role, action = access
    target_name, target_owner, target_visibility, target_sharedwith = target

    # load the default permissions model
    modpath = os.path.abspath(os.path.dirname(__file__))
    permpath = os.path.abspath(
        os.path.join(modpath, "..", "default-permissions-model.json")
    )

    assert (
        permissions.load_policy_and_check_access(
            permpath,
            userid=userid,
            role=role,
            action=action,
            target_name=target_name,
            target_owner=target_owner,
            target_visibility=target_visibility,
            target_sharedwith=target_sharedwith,
        )
        is expected
    )


@pytest.mark.parametrize(
    "access,target,expected",
    [
        # locked -> self-owned private dataset
        ((2, "locked", "list"), ("dataset", 2, "private", ""), False),
        ((2, "locked", "view"), ("dataset", 2, "private", ""), False),
        ((2, "locked", "create"), ("dataset", 2, "private", ""), False),
        ((2, "locked", "edit"), ("dataset", 2, "private", ""), False),
        ((2, "locked", "delete"), ("dataset", 2, "private", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("dataset", 2, "private", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("dataset", 2, "private", ""), False),
        # locked -> self-owned shared dataset
        ((2, "locked", "list"), ("dataset", 2, "shared", ""), False),
        ((2, "locked", "view"), ("dataset", 2, "shared", ""), False),
        ((2, "locked", "create"), ("dataset", 2, "shared", ""), False),
        ((2, "locked", "edit"), ("dataset", 2, "shared", ""), False),
        ((2, "locked", "delete"), ("dataset", 2, "shared", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("dataset", 2, "shared", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("dataset", 2, "shared", ""), False),
        # locked -> self-owned public dataset
        ((2, "locked", "list"), ("dataset", 2, "public", ""), False),
        ((2, "locked", "view"), ("dataset", 2, "public", ""), False),
        ((2, "locked", "create"), ("dataset", 2, "public", ""), False),
        ((2, "locked", "edit"), ("dataset", 2, "public", ""), False),
        ((2, "locked", "delete"), ("dataset", 2, "public", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("dataset", 2, "public", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("dataset", 2, "public", ""), False),
        # locked -> public dataset from others
        ((2, "locked", "list"), ("dataset", 1, "public", ""), False),
        ((2, "locked", "view"), ("dataset", 1, "public", ""), False),
        ((2, "locked", "create"), ("dataset", 1, "public", ""), False),
        ((2, "locked", "edit"), ("dataset", 1, "public", ""), False),
        ((2, "locked", "delete"), ("dataset", 1, "public", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("dataset", 1, "public", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("dataset", 1, "public", ""), False),
        # locked -> shared dataset from others
        ((2, "locked", "list"), ("dataset", 1, "shared", "2,5,6"), False),
        ((2, "locked", "view"), ("dataset", 1, "shared", "2,5,6"), False),
        ((2, "locked", "create"), ("dataset", 1, "shared", "2,5,6"), False),
        ((2, "locked", "edit"), ("dataset", 1, "shared", "2,5,6"), False),
        ((2, "locked", "delete"), ("dataset", 1, "shared", "2,5,6"), False),
        (
            (2, "locked", "change_visibility"),
            ("dataset", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("dataset", 1, "shared", "2,5,6"),
            False,
        ),
        # locked -> shared from others but not shared to this
        # user (should all fail)
        ((2, "locked", "list"), ("dataset", 1, "shared", "5,6"), False),
        ((2, "locked", "view"), ("dataset", 1, "shared", "5,6"), False),
        ((2, "locked", "create"), ("dataset", 1, "shared", "5,6"), False),
        ((2, "locked", "edit"), ("dataset", 1, "shared", "5,6"), False),
        ((2, "locked", "delete"), ("dataset", 1, "shared", "5,6"), False),
        (
            (2, "locked", "change_visibility"),
            ("dataset", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("dataset", 1, "shared", "5,6"),
            False,
        ),
        # locked -> private dataset from others
        ((2, "locked", "list"), ("dataset", 1, "private", ""), False),
        ((2, "locked", "view"), ("dataset", 1, "private", ""), False),
        ((2, "locked", "create"), ("dataset", 1, "private", ""), False),
        ((2, "locked", "edit"), ("dataset", 1, "private", ""), False),
        ((2, "locked", "delete"), ("dataset", 1, "private", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("dataset", 1, "private", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("dataset", 1, "private", ""), False),
    ],
)
def test_check_locked_access_to_dataset(access, target, expected):
    """
    This checks user access.

    """
    userid, role, action = access
    target_name, target_owner, target_visibility, target_sharedwith = target

    # load the default permissions model
    modpath = os.path.abspath(os.path.dirname(__file__))
    permpath = os.path.abspath(
        os.path.join(modpath, "..", "default-permissions-model.json")
    )

    assert (
        permissions.load_policy_and_check_access(
            permpath,
            userid=userid,
            role=role,
            action=action,
            target_name=target_name,
            target_owner=target_owner,
            target_visibility=target_visibility,
            target_sharedwith=target_sharedwith,
        )
        is expected
    )


@pytest.mark.parametrize(
    "access,target,expected",
    [
        # locked -> self-owned private object
        ((2, "locked", "list"), ("object", 2, "private", ""), False),
        ((2, "locked", "view"), ("object", 2, "private", ""), False),
        ((2, "locked", "create"), ("object", 2, "private", ""), False),
        ((2, "locked", "edit"), ("object", 2, "private", ""), False),
        ((2, "locked", "delete"), ("object", 2, "private", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("object", 2, "private", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("object", 2, "private", ""), False),
        # locked -> self-owned shared object
        ((2, "locked", "list"), ("object", 2, "shared", ""), False),
        ((2, "locked", "view"), ("object", 2, "shared", ""), False),
        ((2, "locked", "create"), ("object", 2, "shared", ""), False),
        ((2, "locked", "edit"), ("object", 2, "shared", ""), False),
        ((2, "locked", "delete"), ("object", 2, "shared", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("object", 2, "shared", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("object", 2, "shared", ""), False),
        # locked -> self-owned public object (should all fail)
        ((2, "locked", "list"), ("object", 2, "public", ""), False),
        ((2, "locked", "view"), ("object", 2, "public", ""), False),
        ((2, "locked", "create"), ("object", 2, "public", ""), False),
        ((2, "locked", "edit"), ("object", 2, "public", ""), False),
        ((2, "locked", "delete"), ("object", 2, "public", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("object", 2, "public", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("object", 2, "public", ""), False),
        # locked -> public object from others (list, view OK)
        ((2, "locked", "list"), ("object", 1, "public", ""), False),
        ((2, "locked", "view"), ("object", 1, "public", ""), False),
        ((2, "locked", "create"), ("object", 1, "public", ""), False),
        ((2, "locked", "edit"), ("object", 1, "public", ""), False),
        ((2, "locked", "delete"), ("object", 1, "public", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("object", 1, "public", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("object", 1, "public", ""), False),
        # locked -> shared object from others (should all fail)
        ((2, "locked", "list"), ("object", 1, "shared", "2,5,6"), False),
        ((2, "locked", "view"), ("object", 1, "shared", "2,5,6"), False),
        ((2, "locked", "create"), ("object", 1, "shared", "2,5,6"), False),
        ((2, "locked", "edit"), ("object", 1, "shared", "2,5,6"), False),
        ((2, "locked", "delete"), ("object", 1, "shared", "2,5,6"), False),
        (
            (2, "locked", "change_visibility"),
            ("object", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("object", 1, "shared", "2,5,6"),
            False,
        ),
        # locked -> shared from others but not shared to this
        # user (should all fail)
        ((2, "locked", "list"), ("object", 1, "shared", "5,6"), False),
        ((2, "locked", "view"), ("object", 1, "shared", "5,6"), False),
        ((2, "locked", "create"), ("object", 1, "shared", "5,6"), False),
        ((2, "locked", "edit"), ("object", 1, "shared", "5,6"), False),
        ((2, "locked", "delete"), ("object", 1, "shared", "5,6"), False),
        (
            (2, "locked", "change_visibility"),
            ("object", 1, "shared", "5,6"),
            False,
        ),
        ((2, "locked", "change_owner"), ("object", 1, "shared", "5,6"), False),
        # locked -> private object from others (should all fail)
        ((2, "locked", "list"), ("object", 1, "private", ""), False),
        ((2, "locked", "view"), ("object", 1, "private", ""), False),
        ((2, "locked", "create"), ("object", 1, "private", ""), False),
        ((2, "locked", "edit"), ("object", 1, "private", ""), False),
        ((2, "locked", "delete"), ("object", 1, "private", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("object", 1, "private", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("object", 1, "private", ""), False),
    ],
)
def test_check_locked_access_to_object(access, target, expected):
    """
    This checks user access.

    """
    userid, role, action = access
    target_name, target_owner, target_visibility, target_sharedwith = target

    # load the default permissions model
    modpath = os.path.abspath(os.path.dirname(__file__))
    permpath = os.path.abspath(
        os.path.join(modpath, "..", "default-permissions-model.json")
    )

    assert (
        permissions.load_policy_and_check_access(
            permpath,
            userid=userid,
            role=role,
            action=action,
            target_name=target_name,
            target_owner=target_owner,
            target_visibility=target_visibility,
            target_sharedwith=target_sharedwith,
        )
        is expected
    )


@pytest.mark.parametrize(
    "access,target,expected",
    [
        # locked -> self-owned private users
        ((2, "locked", "list"), ("user", 2, "private", ""), False),
        ((2, "locked", "view"), ("user", 2, "private", ""), False),
        ((2, "locked", "create"), ("user", 2, "private", ""), False),
        ((2, "locked", "edit"), ("user", 2, "private", ""), False),
        ((2, "locked", "delete"), ("user", 2, "private", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("user", 2, "private", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("user", 2, "private", ""), False),
        # locked -> self-owned shared users
        ((2, "locked", "list"), ("user", 2, "shared", ""), False),
        ((2, "locked", "view"), ("user", 2, "shared", ""), False),
        ((2, "locked", "create"), ("user", 2, "shared", ""), False),
        ((2, "locked", "edit"), ("user", 2, "shared", ""), False),
        ((2, "locked", "delete"), ("user", 2, "shared", ""), False),
        ((2, "locked", "change_visibility"), ("user", 2, "shared", ""), False),
        ((2, "locked", "change_owner"), ("user", 2, "shared", ""), False),
        # locked -> self-owned public users (should all fail)
        ((2, "locked", "list"), ("user", 2, "public", ""), False),
        ((2, "locked", "view"), ("user", 2, "public", ""), False),
        ((2, "locked", "create"), ("user", 2, "public", ""), False),
        ((2, "locked", "edit"), ("user", 2, "public", ""), False),
        ((2, "locked", "delete"), ("user", 2, "public", ""), False),
        ((2, "locked", "change_visibility"), ("user", 2, "public", ""), False),
        ((2, "locked", "change_owner"), ("user", 2, "public", ""), False),
        # locked -> public users from others (should all fail)
        ((2, "locked", "list"), ("user", 1, "public", ""), False),
        ((2, "locked", "view"), ("user", 1, "public", ""), False),
        ((2, "locked", "create"), ("user", 1, "public", ""), False),
        ((2, "locked", "edit"), ("user", 1, "public", ""), False),
        ((2, "locked", "delete"), ("user", 1, "public", ""), False),
        ((2, "locked", "change_visibility"), ("user", 1, "public", ""), False),
        ((2, "locked", "change_owner"), ("user", 1, "public", ""), False),
        # locked -> shared users from others (should all fail)
        ((2, "locked", "list"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "locked", "view"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "locked", "create"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "locked", "edit"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "locked", "delete"), ("user", 1, "shared", "2,5,6"), False),
        (
            (2, "locked", "change_visibility"),
            ("user", 1, "shared", "2,5,6"),
            False,
        ),
        ((2, "locked", "change_owner"), ("user", 1, "shared", "2,5,6"), False),
        # locked -> shared from others but not shared to this
        # user (should all fail)
        ((2, "locked", "list"), ("user", 1, "shared", "5,6"), False),
        ((2, "locked", "view"), ("user", 1, "shared", "5,6"), False),
        ((2, "locked", "create"), ("user", 1, "shared", "5,6"), False),
        ((2, "locked", "edit"), ("user", 1, "shared", "5,6"), False),
        ((2, "locked", "delete"), ("user", 1, "shared", "5,6"), False),
        (
            (2, "locked", "change_visibility"),
            ("user", 1, "shared", "5,6"),
            False,
        ),
        ((2, "locked", "change_owner"), ("user", 1, "shared", "5,6"), False),
        # locked -> private users from others (should all fail)
        ((2, "locked", "list"), ("user", 1, "private", ""), False),
        ((2, "locked", "view"), ("user", 1, "private", ""), False),
        ((2, "locked", "create"), ("user", 1, "private", ""), False),
        ((2, "locked", "edit"), ("user", 1, "private", ""), False),
        ((2, "locked", "delete"), ("user", 1, "private", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("user", 1, "private", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("user", 1, "private", ""), False),
    ],
)
def test_check_locked_access_to_users(access, target, expected):
    """
    This checks user access.

    """
    userid, role, action = access
    target_name, target_owner, target_visibility, target_sharedwith = target

    # load the default permissions model
    modpath = os.path.abspath(os.path.dirname(__file__))
    permpath = os.path.abspath(
        os.path.join(modpath, "..", "default-permissions-model.json")
    )

    assert (
        permissions.load_policy_and_check_access(
            permpath,
            userid=userid,
            role=role,
            action=action,
            target_name=target_name,
            target_owner=target_owner,
            target_visibility=target_visibility,
            target_sharedwith=target_sharedwith,
        )
        is expected
    )


@pytest.mark.parametrize(
    "access,target,expected",
    [
        # locked -> self-owned private sessions
        ((2, "locked", "list"), ("session", 2, "private", ""), False),
        ((2, "locked", "view"), ("session", 2, "private", ""), False),
        ((2, "locked", "create"), ("session", 2, "private", ""), False),
        ((2, "locked", "edit"), ("session", 2, "private", ""), False),
        ((2, "locked", "delete"), ("session", 2, "private", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("session", 2, "private", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("session", 2, "private", ""), False),
        # locked -> self-owned shared sessions
        ((2, "locked", "list"), ("session", 2, "shared", ""), False),
        ((2, "locked", "view"), ("session", 2, "shared", ""), False),
        ((2, "locked", "create"), ("session", 2, "shared", ""), False),
        ((2, "locked", "edit"), ("session", 2, "shared", ""), False),
        ((2, "locked", "delete"), ("session", 2, "shared", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("session", 2, "shared", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("session", 2, "shared", ""), False),
        # locked -> self-owned public sessions (should all fail)
        ((2, "locked", "list"), ("session", 2, "public", ""), False),
        ((2, "locked", "view"), ("session", 2, "public", ""), False),
        ((2, "locked", "create"), ("session", 2, "public", ""), False),
        ((2, "locked", "edit"), ("session", 2, "public", ""), False),
        ((2, "locked", "delete"), ("session", 2, "public", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("session", 2, "public", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("session", 2, "public", ""), False),
        # locked -> public sessions from others (should all fail)
        ((2, "locked", "list"), ("session", 1, "public", ""), False),
        ((2, "locked", "view"), ("session", 1, "public", ""), False),
        ((2, "locked", "create"), ("session", 1, "public", ""), False),
        ((2, "locked", "edit"), ("session", 1, "public", ""), False),
        ((2, "locked", "delete"), ("session", 1, "public", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("session", 1, "public", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("session", 1, "public", ""), False),
        # locked -> shared sessions from others (should all fail)
        ((2, "locked", "list"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "locked", "view"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "locked", "create"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "locked", "edit"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "locked", "delete"), ("session", 1, "shared", "2,5,6"), False),
        (
            (2, "locked", "change_visibility"),
            ("session", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("session", 1, "shared", "2,5,6"),
            False,
        ),
        # locked -> shared from others but not shared to this
        # user (should all fail)
        ((2, "locked", "list"), ("session", 1, "shared", "5,6"), False),
        ((2, "locked", "view"), ("session", 1, "shared", "5,6"), False),
        ((2, "locked", "create"), ("session", 1, "shared", "5,6"), False),
        ((2, "locked", "edit"), ("session", 1, "shared", "5,6"), False),
        ((2, "locked", "delete"), ("session", 1, "shared", "5,6"), False),
        (
            (2, "locked", "change_visibility"),
            ("session", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("session", 1, "shared", "5,6"),
            False,
        ),
        # locked -> private sessions from others (should all fail)
        ((2, "locked", "list"), ("session", 1, "private", ""), False),
        ((2, "locked", "view"), ("session", 1, "private", ""), False),
        ((2, "locked", "create"), ("session", 1, "private", ""), False),
        ((2, "locked", "edit"), ("session", 1, "private", ""), False),
        ((2, "locked", "delete"), ("session", 1, "private", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("session", 1, "private", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("session", 1, "private", ""), False),
    ],
)
def test_check_locked_access_to_sessions(access, target, expected):
    """
    This checks user access.

    """
    userid, role, action = access
    target_name, target_owner, target_visibility, target_sharedwith = target

    # load the default permissions model
    modpath = os.path.abspath(os.path.dirname(__file__))
    permpath = os.path.abspath(
        os.path.join(modpath, "..", "default-permissions-model.json")
    )

    assert (
        permissions.load_policy_and_check_access(
            permpath,
            userid=userid,
            role=role,
            action=action,
            target_name=target_name,
            target_owner=target_owner,
            target_visibility=target_visibility,
            target_sharedwith=target_sharedwith,
        )
        is expected
    )


@pytest.mark.parametrize(
    "access,target,expected",
    [
        # locked -> self-owned private apikeys
        ((2, "locked", "list"), ("apikey", 2, "private", ""), False),
        ((2, "locked", "view"), ("apikey", 2, "private", ""), False),
        ((2, "locked", "create"), ("apikey", 2, "private", ""), False),
        ((2, "locked", "edit"), ("apikey", 2, "private", ""), False),
        ((2, "locked", "delete"), ("apikey", 2, "private", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("apikey", 2, "private", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("apikey", 2, "private", ""), False),
        # locked -> self-owned shared apikeys
        ((2, "locked", "list"), ("apikey", 2, "shared", ""), False),
        ((2, "locked", "view"), ("apikey", 2, "shared", ""), False),
        ((2, "locked", "create"), ("apikey", 2, "shared", ""), False),
        ((2, "locked", "edit"), ("apikey", 2, "shared", ""), False),
        ((2, "locked", "delete"), ("apikey", 2, "shared", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("apikey", 2, "shared", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("apikey", 2, "shared", ""), False),
        # locked -> self-owned public apikeys (should all fail)
        ((2, "locked", "list"), ("apikey", 2, "public", ""), False),
        ((2, "locked", "view"), ("apikey", 2, "public", ""), False),
        ((2, "locked", "create"), ("apikey", 2, "public", ""), False),
        ((2, "locked", "edit"), ("apikey", 2, "public", ""), False),
        ((2, "locked", "delete"), ("apikey", 2, "public", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("apikey", 2, "public", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("apikey", 2, "public", ""), False),
        # locked -> public apikeys from others (should all fail)
        ((2, "locked", "list"), ("apikey", 1, "public", ""), False),
        ((2, "locked", "view"), ("apikey", 1, "public", ""), False),
        ((2, "locked", "create"), ("apikey", 1, "public", ""), False),
        ((2, "locked", "edit"), ("apikey", 1, "public", ""), False),
        ((2, "locked", "delete"), ("apikey", 1, "public", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("apikey", 1, "public", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("apikey", 1, "public", ""), False),
        # locked -> shared apikeys from others (should all fail)
        ((2, "locked", "list"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "locked", "view"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "locked", "create"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "locked", "edit"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "locked", "delete"), ("apikey", 1, "shared", "2,5,6"), False),
        (
            (2, "locked", "change_visibility"),
            ("apikey", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("apikey", 1, "shared", "2,5,6"),
            False,
        ),
        # locked -> shared from others but not shared to this
        # user (should all fail)
        ((2, "locked", "list"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "locked", "view"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "locked", "create"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "locked", "edit"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "locked", "delete"), ("apikey", 1, "shared", "5,6"), False),
        (
            (2, "locked", "change_visibility"),
            ("apikey", 1, "shared", "5,6"),
            False,
        ),
        ((2, "locked", "change_owner"), ("apikey", 1, "shared", "5,6"), False),
        # locked -> private apikeys from others (should all fail)
        ((2, "locked", "list"), ("apikey", 1, "private", ""), False),
        ((2, "locked", "view"), ("apikey", 1, "private", ""), False),
        ((2, "locked", "create"), ("apikey", 1, "private", ""), False),
        ((2, "locked", "edit"), ("apikey", 1, "private", ""), False),
        ((2, "locked", "delete"), ("apikey", 1, "private", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("apikey", 1, "private", ""),
            False,
        ),
        ((2, "locked", "change_owner"), ("apikey", 1, "private", ""), False),
    ],
)
def test_check_locked_access_to_apikeys(access, target, expected):
    """
    This checks user access.

    """
    userid, role, action = access
    target_name, target_owner, target_visibility, target_sharedwith = target

    # load the default permissions model
    modpath = os.path.abspath(os.path.dirname(__file__))
    permpath = os.path.abspath(
        os.path.join(modpath, "..", "default-permissions-model.json")
    )

    assert (
        permissions.load_policy_and_check_access(
            permpath,
            userid=userid,
            role=role,
            action=action,
            target_name=target_name,
            target_owner=target_owner,
            target_visibility=target_visibility,
            target_sharedwith=target_sharedwith,
        )
        is expected
    )


@pytest.mark.parametrize(
    "access,target,expected",
    [
        # locked -> self-owned private preferences
        ((2, "locked", "list"), ("preference", 2, "private", ""), False),
        ((2, "locked", "view"), ("preference", 2, "private", ""), False),
        ((2, "locked", "create"), ("preference", 2, "private", ""), False),
        ((2, "locked", "edit"), ("preference", 2, "private", ""), False),
        ((2, "locked", "delete"), ("preference", 2, "private", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("preference", 2, "private", ""),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("preference", 2, "private", ""),
            False,
        ),
        # locked -> self-owned shared preferences
        ((2, "locked", "list"), ("preference", 2, "shared", ""), False),
        ((2, "locked", "view"), ("preference", 2, "shared", ""), False),
        ((2, "locked", "create"), ("preference", 2, "shared", ""), False),
        ((2, "locked", "edit"), ("preference", 2, "shared", ""), False),
        ((2, "locked", "delete"), ("preference", 2, "shared", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("preference", 2, "shared", ""),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("preference", 2, "shared", ""),
            False,
        ),
        # locked -> self-owned public preferences (should all fail)
        ((2, "locked", "list"), ("preference", 2, "public", ""), False),
        ((2, "locked", "view"), ("preference", 2, "public", ""), False),
        ((2, "locked", "create"), ("preference", 2, "public", ""), False),
        ((2, "locked", "edit"), ("preference", 2, "public", ""), False),
        ((2, "locked", "delete"), ("preference", 2, "public", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("preference", 2, "public", ""),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("preference", 2, "public", ""),
            False,
        ),
        # locked -> public preferences from others (should all fail)
        ((2, "locked", "list"), ("preference", 1, "public", ""), False),
        ((2, "locked", "view"), ("preference", 1, "public", ""), False),
        ((2, "locked", "create"), ("preference", 1, "public", ""), False),
        ((2, "locked", "edit"), ("preference", 1, "public", ""), False),
        ((2, "locked", "delete"), ("preference", 1, "public", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("preference", 1, "public", ""),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("preference", 1, "public", ""),
            False,
        ),
        # locked -> shared preferences from others (should all fail)
        ((2, "locked", "list"), ("preference", 1, "shared", "2,5,6"), False),
        ((2, "locked", "view"), ("preference", 1, "shared", "2,5,6"), False),
        ((2, "locked", "create"), ("preference", 1, "shared", "2,5,6"), False),
        ((2, "locked", "edit"), ("preference", 1, "shared", "2,5,6"), False),
        ((2, "locked", "delete"), ("preference", 1, "shared", "2,5,6"), False),
        (
            (2, "locked", "change_visibility"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        # locked -> shared from others but not shared to this
        # user (should all fail)
        ((2, "locked", "list"), ("preference", 1, "shared", "5,6"), False),
        ((2, "locked", "view"), ("preference", 1, "shared", "5,6"), False),
        ((2, "locked", "create"), ("preference", 1, "shared", "5,6"), False),
        ((2, "locked", "edit"), ("preference", 1, "shared", "5,6"), False),
        ((2, "locked", "delete"), ("preference", 1, "shared", "5,6"), False),
        (
            (2, "locked", "change_visibility"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        # locked -> private preferences from others (should all fail)
        ((2, "locked", "list"), ("preference", 1, "private", ""), False),
        ((2, "locked", "view"), ("preference", 1, "private", ""), False),
        ((2, "locked", "create"), ("preference", 1, "private", ""), False),
        ((2, "locked", "edit"), ("preference", 1, "private", ""), False),
        ((2, "locked", "delete"), ("preference", 1, "private", ""), False),
        (
            (2, "locked", "change_visibility"),
            ("preference", 1, "private", ""),
            False,
        ),
        (
            (2, "locked", "change_owner"),
            ("preference", 1, "private", ""),
            False,
        ),
    ],
)
def test_check_locked_access_to_preferences(access, target, expected):
    """
    This checks user access.

    """
    userid, role, action = access
    target_name, target_owner, target_visibility, target_sharedwith = target

    # load the default permissions model
    modpath = os.path.abspath(os.path.dirname(__file__))
    permpath = os.path.abspath(
        os.path.join(modpath, "..", "default-permissions-model.json")
    )

    assert (
        permissions.load_policy_and_check_access(
            permpath,
            userid=userid,
            role=role,
            action=action,
            target_name=target_name,
            target_owner=target_owner,
            target_visibility=target_visibility,
            target_sharedwith=target_sharedwith,
        )
        is expected
    )
