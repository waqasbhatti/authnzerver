# -*- coding: utf-8 -*-
# test_permissions_staff.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug
# 2018
# License: MIT - see the LICENSE file for the full text.

"""
This tests permissions for staff users.

"""

import os.path
import pytest
from authnzerver import permissions


######################
## STAFF ACCESS ##
######################


@pytest.mark.parametrize(
    "access,target,expected",
    [
        # staff -> self-owned private collection
        ((2, "staff", "list"), ("collection", 2, "private", ""), True),
        ((2, "staff", "view"), ("collection", 2, "private", ""), True),
        ((2, "staff", "create"), ("collection", 2, "private", ""), True),
        ((2, "staff", "edit"), ("collection", 2, "private", ""), True),
        ((2, "staff", "delete"), ("collection", 2, "private", ""), True),
        (
            (2, "staff", "change_visibility"),
            ("collection", 2, "private", ""),
            True,
        ),
        ((2, "staff", "change_owner"), ("collection", 2, "private", ""), True),
        # staff -> self-owned shared collection
        ((2, "staff", "list"), ("collection", 2, "shared", ""), True),
        ((2, "staff", "view"), ("collection", 2, "shared", ""), True),
        ((2, "staff", "create"), ("collection", 2, "shared", ""), True),
        ((2, "staff", "edit"), ("collection", 2, "shared", ""), True),
        ((2, "staff", "delete"), ("collection", 2, "shared", ""), True),
        (
            (2, "staff", "change_visibility"),
            ("collection", 2, "shared", ""),
            True,
        ),
        ((2, "staff", "change_owner"), ("collection", 2, "shared", ""), True),
        # staff -> self-owned public collection
        ((2, "staff", "list"), ("collection", 2, "public", ""), True),
        ((2, "staff", "view"), ("collection", 2, "public", ""), True),
        ((2, "staff", "create"), ("collection", 2, "public", ""), True),
        ((2, "staff", "edit"), ("collection", 2, "public", ""), True),
        ((2, "staff", "delete"), ("collection", 2, "public", ""), True),
        (
            (2, "staff", "change_visibility"),
            ("collection", 2, "public", ""),
            True,
        ),
        ((2, "staff", "change_owner"), ("collection", 2, "public", ""), True),
        # staff -> public collection from others
        ((2, "staff", "list"), ("collection", 1, "public", ""), True),
        ((2, "staff", "view"), ("collection", 1, "public", ""), True),
        ((2, "staff", "create"), ("collection", 1, "public", ""), False),
        ((2, "staff", "edit"), ("collection", 1, "public", ""), True),
        ((2, "staff", "delete"), ("collection", 1, "public", ""), True),
        (
            (2, "staff", "change_visibility"),
            ("collection", 1, "public", ""),
            True,
        ),
        ((2, "staff", "change_owner"), ("collection", 1, "public", ""), True),
        # staff -> shared collection from others
        ((2, "staff", "list"), ("collection", 1, "shared", "2,5,6"), True),
        ((2, "staff", "view"), ("collection", 1, "shared", "2,5,6"), True),
        ((2, "staff", "create"), ("collection", 1, "shared", "2,5,6"), False),
        ((2, "staff", "edit"), ("collection", 1, "shared", "2,5,6"), True),
        ((2, "staff", "delete"), ("collection", 1, "shared", "2,5,6"), False),
        (
            (2, "staff", "change_visibility"),
            ("collection", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "staff", "change_owner"),
            ("collection", 1, "shared", "2,5,6"),
            False,
        ),
        # staff -> shared from others but not shared to this
        # user
        ((2, "staff", "list"), ("collection", 1, "shared", "5,6"), True),
        ((2, "staff", "view"), ("collection", 1, "shared", "5,6"), True),
        ((2, "staff", "create"), ("collection", 1, "shared", "5,6"), False),
        ((2, "staff", "edit"), ("collection", 1, "shared", "5,6"), True),
        ((2, "staff", "delete"), ("collection", 1, "shared", "5,6"), False),
        (
            (2, "staff", "change_visibility"),
            ("collection", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "staff", "change_owner"),
            ("collection", 1, "shared", "5,6"),
            False,
        ),
        # staff -> private collection from others
        ((2, "staff", "list"), ("collection", 1, "private", ""), True),
        ((2, "staff", "view"), ("collection", 1, "private", ""), False),
        ((2, "staff", "create"), ("collection", 1, "private", ""), False),
        ((2, "staff", "edit"), ("collection", 1, "private", ""), False),
        ((2, "staff", "delete"), ("collection", 1, "private", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("collection", 1, "private", ""),
            False,
        ),
        (
            (2, "staff", "change_owner"),
            ("collection", 1, "private", ""),
            False,
        ),
    ],
)
def test_staff_access_to_collection(access, target, expected):
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
        # staff -> self-owned private dataset
        ((2, "staff", "list"), ("dataset", 2, "private", ""), True),
        ((2, "staff", "view"), ("dataset", 2, "private", ""), True),
        ((2, "staff", "create"), ("dataset", 2, "private", ""), True),
        ((2, "staff", "edit"), ("dataset", 2, "private", ""), True),
        ((2, "staff", "delete"), ("dataset", 2, "private", ""), True),
        (
            (2, "staff", "change_visibility"),
            ("dataset", 2, "private", ""),
            True,
        ),
        ((2, "staff", "change_owner"), ("dataset", 2, "private", ""), True),
        # staff -> self-owned shared dataset
        ((2, "staff", "list"), ("dataset", 2, "shared", ""), True),
        ((2, "staff", "view"), ("dataset", 2, "shared", ""), True),
        ((2, "staff", "create"), ("dataset", 2, "shared", ""), True),
        ((2, "staff", "edit"), ("dataset", 2, "shared", ""), True),
        ((2, "staff", "delete"), ("dataset", 2, "shared", ""), True),
        (
            (2, "staff", "change_visibility"),
            ("dataset", 2, "shared", ""),
            True,
        ),
        ((2, "staff", "change_owner"), ("dataset", 2, "shared", ""), True),
        # staff -> self-owned public dataset
        ((2, "staff", "list"), ("dataset", 2, "public", ""), True),
        ((2, "staff", "view"), ("dataset", 2, "public", ""), True),
        ((2, "staff", "create"), ("dataset", 2, "public", ""), True),
        ((2, "staff", "edit"), ("dataset", 2, "public", ""), True),
        ((2, "staff", "delete"), ("dataset", 2, "public", ""), True),
        (
            (2, "staff", "change_visibility"),
            ("dataset", 2, "public", ""),
            True,
        ),
        ((2, "staff", "change_owner"), ("dataset", 2, "public", ""), True),
        # staff -> public dataset from others
        ((2, "staff", "list"), ("dataset", 1, "public", ""), True),
        ((2, "staff", "view"), ("dataset", 1, "public", ""), True),
        ((2, "staff", "create"), ("dataset", 1, "public", ""), False),
        ((2, "staff", "edit"), ("dataset", 1, "public", ""), True),
        ((2, "staff", "delete"), ("dataset", 1, "public", ""), True),
        (
            (2, "staff", "change_visibility"),
            ("dataset", 1, "public", ""),
            True,
        ),
        ((2, "staff", "change_owner"), ("dataset", 1, "public", ""), True),
        # staff -> shared dataset from others
        ((2, "staff", "list"), ("dataset", 1, "shared", "2,5,6"), True),
        ((2, "staff", "view"), ("dataset", 1, "shared", "2,5,6"), True),
        ((2, "staff", "create"), ("dataset", 1, "shared", "2,5,6"), False),
        ((2, "staff", "edit"), ("dataset", 1, "shared", "2,5,6"), True),
        ((2, "staff", "delete"), ("dataset", 1, "shared", "2,5,6"), False),
        (
            (2, "staff", "change_visibility"),
            ("dataset", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "staff", "change_owner"),
            ("dataset", 1, "shared", "2,5,6"),
            False,
        ),
        # staff -> shared from others but not shared to this
        # user
        ((2, "staff", "list"), ("dataset", 1, "shared", "5,6"), True),
        ((2, "staff", "view"), ("dataset", 1, "shared", "5,6"), True),
        ((2, "staff", "create"), ("dataset", 1, "shared", "5,6"), False),
        ((2, "staff", "edit"), ("dataset", 1, "shared", "5,6"), True),
        ((2, "staff", "delete"), ("dataset", 1, "shared", "5,6"), False),
        (
            (2, "staff", "change_visibility"),
            ("dataset", 1, "shared", "5,6"),
            False,
        ),
        ((2, "staff", "change_owner"), ("dataset", 1, "shared", "5,6"), False),
        # staff -> private dataset from others
        ((2, "staff", "list"), ("dataset", 1, "private", ""), True),
        ((2, "staff", "view"), ("dataset", 1, "private", ""), False),
        ((2, "staff", "create"), ("dataset", 1, "private", ""), False),
        ((2, "staff", "edit"), ("dataset", 1, "private", ""), False),
        ((2, "staff", "delete"), ("dataset", 1, "private", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("dataset", 1, "private", ""),
            False,
        ),
        ((2, "staff", "change_owner"), ("dataset", 1, "private", ""), False),
    ],
)
def test_staff_access_to_dataset(access, target, expected):
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
        # staff -> self-owned private object
        ((2, "staff", "list"), ("object", 2, "private", ""), True),
        ((2, "staff", "view"), ("object", 2, "private", ""), True),
        ((2, "staff", "create"), ("object", 2, "private", ""), True),
        ((2, "staff", "edit"), ("object", 2, "private", ""), True),
        ((2, "staff", "delete"), ("object", 2, "private", ""), True),
        (
            (2, "staff", "change_visibility"),
            ("object", 2, "private", ""),
            True,
        ),
        ((2, "staff", "change_owner"), ("object", 2, "private", ""), True),
        # staff -> self-owned shared object
        ((2, "staff", "list"), ("object", 2, "shared", ""), True),
        ((2, "staff", "view"), ("object", 2, "shared", ""), True),
        ((2, "staff", "create"), ("object", 2, "shared", ""), True),
        ((2, "staff", "edit"), ("object", 2, "shared", ""), True),
        ((2, "staff", "delete"), ("object", 2, "shared", ""), True),
        ((2, "staff", "change_visibility"), ("object", 2, "shared", ""), True),
        ((2, "staff", "change_owner"), ("object", 2, "shared", ""), True),
        # staff -> self-owned public object
        ((2, "staff", "list"), ("object", 2, "public", ""), True),
        ((2, "staff", "view"), ("object", 2, "public", ""), True),
        ((2, "staff", "create"), ("object", 2, "public", ""), True),
        ((2, "staff", "edit"), ("object", 2, "public", ""), True),
        ((2, "staff", "delete"), ("object", 2, "public", ""), True),
        ((2, "staff", "change_visibility"), ("object", 2, "public", ""), True),
        ((2, "staff", "change_owner"), ("object", 2, "public", ""), True),
        # staff -> public object from others (list, view OK)
        ((2, "staff", "list"), ("object", 1, "public", ""), True),
        ((2, "staff", "view"), ("object", 1, "public", ""), True),
        ((2, "staff", "create"), ("object", 1, "public", ""), False),
        ((2, "staff", "edit"), ("object", 1, "public", ""), True),
        ((2, "staff", "delete"), ("object", 1, "public", ""), True),
        ((2, "staff", "change_visibility"), ("object", 1, "public", ""), True),
        ((2, "staff", "change_owner"), ("object", 1, "public", ""), True),
        # staff -> shared object from others
        ((2, "staff", "list"), ("object", 1, "shared", "2,5,6"), True),
        ((2, "staff", "view"), ("object", 1, "shared", "2,5,6"), True),
        ((2, "staff", "create"), ("object", 1, "shared", "2,5,6"), False),
        ((2, "staff", "edit"), ("object", 1, "shared", "2,5,6"), True),
        ((2, "staff", "delete"), ("object", 1, "shared", "2,5,6"), False),
        (
            (2, "staff", "change_visibility"),
            ("object", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "staff", "change_owner"),
            ("object", 1, "shared", "2,5,6"),
            False,
        ),
        # staff -> shared from others but not shared to this
        # user
        ((2, "staff", "list"), ("object", 1, "shared", "5,6"), True),
        ((2, "staff", "view"), ("object", 1, "shared", "5,6"), True),
        ((2, "staff", "create"), ("object", 1, "shared", "5,6"), False),
        ((2, "staff", "edit"), ("object", 1, "shared", "5,6"), True),
        ((2, "staff", "delete"), ("object", 1, "shared", "5,6"), False),
        (
            (2, "staff", "change_visibility"),
            ("object", 1, "shared", "5,6"),
            False,
        ),
        ((2, "staff", "change_owner"), ("object", 1, "shared", "5,6"), False),
        # staff -> private object from others
        ((2, "staff", "list"), ("object", 1, "private", ""), True),
        ((2, "staff", "view"), ("object", 1, "private", ""), False),
        ((2, "staff", "create"), ("object", 1, "private", ""), False),
        ((2, "staff", "edit"), ("object", 1, "private", ""), False),
        ((2, "staff", "delete"), ("object", 1, "private", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("object", 1, "private", ""),
            False,
        ),
        ((2, "staff", "change_owner"), ("object", 1, "private", ""), False),
    ],
)
def test_staff_access_to_object(access, target, expected):
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
        # staff -> self-owned private users
        ((2, "staff", "list"), ("user", 2, "private", ""), False),
        ((2, "staff", "view"), ("user", 2, "private", ""), False),
        ((2, "staff", "create"), ("user", 2, "private", ""), False),
        ((2, "staff", "edit"), ("user", 2, "private", ""), False),
        ((2, "staff", "delete"), ("user", 2, "private", ""), False),
        ((2, "staff", "change_visibility"), ("user", 2, "private", ""), False),
        ((2, "staff", "change_owner"), ("user", 2, "private", ""), False),
        # staff -> self-owned shared users
        ((2, "staff", "list"), ("user", 2, "shared", ""), False),
        ((2, "staff", "view"), ("user", 2, "shared", ""), False),
        ((2, "staff", "create"), ("user", 2, "shared", ""), False),
        ((2, "staff", "edit"), ("user", 2, "shared", ""), False),
        ((2, "staff", "delete"), ("user", 2, "shared", ""), False),
        ((2, "staff", "change_visibility"), ("user", 2, "shared", ""), False),
        ((2, "staff", "change_owner"), ("user", 2, "shared", ""), False),
        # staff -> self-owned public users
        ((2, "staff", "list"), ("user", 2, "public", ""), False),
        ((2, "staff", "view"), ("user", 2, "public", ""), False),
        ((2, "staff", "create"), ("user", 2, "public", ""), False),
        ((2, "staff", "edit"), ("user", 2, "public", ""), False),
        ((2, "staff", "delete"), ("user", 2, "public", ""), False),
        ((2, "staff", "change_visibility"), ("user", 2, "public", ""), False),
        ((2, "staff", "change_owner"), ("user", 2, "public", ""), False),
        # staff -> public users from others
        ((2, "staff", "list"), ("user", 1, "public", ""), False),
        ((2, "staff", "view"), ("user", 1, "public", ""), False),
        ((2, "staff", "create"), ("user", 1, "public", ""), False),
        ((2, "staff", "edit"), ("user", 1, "public", ""), False),
        ((2, "staff", "delete"), ("user", 1, "public", ""), False),
        ((2, "staff", "change_visibility"), ("user", 1, "public", ""), False),
        ((2, "staff", "change_owner"), ("user", 1, "public", ""), False),
        # staff -> shared users from others
        ((2, "staff", "list"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "staff", "view"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "staff", "create"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "staff", "edit"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "staff", "delete"), ("user", 1, "shared", "2,5,6"), False),
        (
            (2, "staff", "change_visibility"),
            ("user", 1, "shared", "2,5,6"),
            False,
        ),
        ((2, "staff", "change_owner"), ("user", 1, "shared", "2,5,6"), False),
        # staff -> shared from others but not shared to this
        # user
        ((2, "staff", "list"), ("user", 1, "shared", "5,6"), False),
        ((2, "staff", "view"), ("user", 1, "shared", "5,6"), False),
        ((2, "staff", "create"), ("user", 1, "shared", "5,6"), False),
        ((2, "staff", "edit"), ("user", 1, "shared", "5,6"), False),
        ((2, "staff", "delete"), ("user", 1, "shared", "5,6"), False),
        (
            (2, "staff", "change_visibility"),
            ("user", 1, "shared", "5,6"),
            False,
        ),
        ((2, "staff", "change_owner"), ("user", 1, "shared", "5,6"), False),
        # staff -> private users from others
        ((2, "staff", "list"), ("user", 1, "private", ""), True),
        ((2, "staff", "view"), ("user", 1, "private", ""), False),
        ((2, "staff", "create"), ("user", 1, "private", ""), False),
        ((2, "staff", "edit"), ("user", 1, "private", ""), False),
        ((2, "staff", "delete"), ("user", 1, "private", ""), False),
        ((2, "staff", "change_visibility"), ("user", 1, "private", ""), False),
        ((2, "staff", "change_owner"), ("user", 1, "private", ""), False),
    ],
)
def test_staff_access_to_users(access, target, expected):
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
        # staff -> self-owned private sessions
        ((2, "staff", "list"), ("session", 2, "private", ""), False),
        ((2, "staff", "view"), ("session", 2, "private", ""), False),
        ((2, "staff", "create"), ("session", 2, "private", ""), False),
        ((2, "staff", "edit"), ("session", 2, "private", ""), False),
        ((2, "staff", "delete"), ("session", 2, "private", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("session", 2, "private", ""),
            False,
        ),
        ((2, "staff", "change_owner"), ("session", 2, "private", ""), False),
        # staff -> self-owned shared sessions
        ((2, "staff", "list"), ("session", 2, "shared", ""), False),
        ((2, "staff", "view"), ("session", 2, "shared", ""), False),
        ((2, "staff", "create"), ("session", 2, "shared", ""), False),
        ((2, "staff", "edit"), ("session", 2, "shared", ""), False),
        ((2, "staff", "delete"), ("session", 2, "shared", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("session", 2, "shared", ""),
            False,
        ),
        ((2, "staff", "change_owner"), ("session", 2, "shared", ""), False),
        # staff -> self-owned public sessions
        ((2, "staff", "list"), ("session", 2, "public", ""), False),
        ((2, "staff", "view"), ("session", 2, "public", ""), False),
        ((2, "staff", "create"), ("session", 2, "public", ""), False),
        ((2, "staff", "edit"), ("session", 2, "public", ""), False),
        ((2, "staff", "delete"), ("session", 2, "public", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("session", 2, "public", ""),
            False,
        ),
        ((2, "staff", "change_owner"), ("session", 2, "public", ""), False),
        # staff -> public sessions from others
        ((2, "staff", "list"), ("session", 1, "public", ""), False),
        ((2, "staff", "view"), ("session", 1, "public", ""), False),
        ((2, "staff", "create"), ("session", 1, "public", ""), False),
        ((2, "staff", "edit"), ("session", 1, "public", ""), False),
        ((2, "staff", "delete"), ("session", 1, "public", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("session", 1, "public", ""),
            False,
        ),
        ((2, "staff", "change_owner"), ("session", 1, "public", ""), False),
        # staff -> shared sessions from others
        ((2, "staff", "list"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "staff", "view"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "staff", "create"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "staff", "edit"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "staff", "delete"), ("session", 1, "shared", "2,5,6"), False),
        (
            (2, "staff", "change_visibility"),
            ("session", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "staff", "change_owner"),
            ("session", 1, "shared", "2,5,6"),
            False,
        ),
        # staff -> shared from others but not shared to this
        # user
        ((2, "staff", "list"), ("session", 1, "shared", "5,6"), False),
        ((2, "staff", "view"), ("session", 1, "shared", "5,6"), False),
        ((2, "staff", "create"), ("session", 1, "shared", "5,6"), False),
        ((2, "staff", "edit"), ("session", 1, "shared", "5,6"), False),
        ((2, "staff", "delete"), ("session", 1, "shared", "5,6"), False),
        (
            (2, "staff", "change_visibility"),
            ("session", 1, "shared", "5,6"),
            False,
        ),
        ((2, "staff", "change_owner"), ("session", 1, "shared", "5,6"), False),
        # staff -> private sessions from others
        ((2, "staff", "list"), ("session", 1, "private", ""), True),
        ((2, "staff", "view"), ("session", 1, "private", ""), False),
        ((2, "staff", "create"), ("session", 1, "private", ""), False),
        ((2, "staff", "edit"), ("session", 1, "private", ""), False),
        ((2, "staff", "delete"), ("session", 1, "private", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("session", 1, "private", ""),
            False,
        ),
        ((2, "staff", "change_owner"), ("session", 1, "private", ""), False),
    ],
)
def test_staff_access_to_sessions(access, target, expected):
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
        # staff -> self-owned private apikeys
        ((2, "staff", "list"), ("apikey", 2, "private", ""), True),
        ((2, "staff", "view"), ("apikey", 2, "private", ""), True),
        ((2, "staff", "create"), ("apikey", 2, "private", ""), True),
        ((2, "staff", "edit"), ("apikey", 2, "private", ""), False),
        ((2, "staff", "delete"), ("apikey", 2, "private", ""), True),
        (
            (2, "staff", "change_visibility"),
            ("apikey", 2, "private", ""),
            False,
        ),
        ((2, "staff", "change_owner"), ("apikey", 2, "private", ""), False),
        # staff -> self-owned shared apikeys
        ((2, "staff", "list"), ("apikey", 2, "shared", ""), False),
        ((2, "staff", "view"), ("apikey", 2, "shared", ""), False),
        ((2, "staff", "create"), ("apikey", 2, "shared", ""), False),
        ((2, "staff", "edit"), ("apikey", 2, "shared", ""), False),
        ((2, "staff", "delete"), ("apikey", 2, "shared", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("apikey", 2, "shared", ""),
            False,
        ),
        ((2, "staff", "change_owner"), ("apikey", 2, "shared", ""), False),
        # staff -> self-owned public apikeys
        ((2, "staff", "list"), ("apikey", 2, "public", ""), False),
        ((2, "staff", "view"), ("apikey", 2, "public", ""), False),
        ((2, "staff", "create"), ("apikey", 2, "public", ""), False),
        ((2, "staff", "edit"), ("apikey", 2, "public", ""), False),
        ((2, "staff", "delete"), ("apikey", 2, "public", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("apikey", 2, "public", ""),
            False,
        ),
        ((2, "staff", "change_owner"), ("apikey", 2, "public", ""), False),
        # staff -> public apikeys from others
        ((2, "staff", "list"), ("apikey", 1, "public", ""), False),
        ((2, "staff", "view"), ("apikey", 1, "public", ""), False),
        ((2, "staff", "create"), ("apikey", 1, "public", ""), False),
        ((2, "staff", "edit"), ("apikey", 1, "public", ""), False),
        ((2, "staff", "delete"), ("apikey", 1, "public", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("apikey", 1, "public", ""),
            False,
        ),
        ((2, "staff", "change_owner"), ("apikey", 1, "public", ""), False),
        # staff -> shared apikeys from others
        ((2, "staff", "list"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "staff", "view"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "staff", "create"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "staff", "edit"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "staff", "delete"), ("apikey", 1, "shared", "2,5,6"), False),
        (
            (2, "staff", "change_visibility"),
            ("apikey", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "staff", "change_owner"),
            ("apikey", 1, "shared", "2,5,6"),
            False,
        ),
        # staff -> shared from others but not shared to this
        # user
        ((2, "staff", "list"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "staff", "view"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "staff", "create"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "staff", "edit"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "staff", "delete"), ("apikey", 1, "shared", "5,6"), False),
        (
            (2, "staff", "change_visibility"),
            ("apikey", 1, "shared", "5,6"),
            False,
        ),
        ((2, "staff", "change_owner"), ("apikey", 1, "shared", "5,6"), False),
        # staff -> private apikeys from others
        ((2, "staff", "list"), ("apikey", 1, "private", ""), True),
        ((2, "staff", "view"), ("apikey", 1, "private", ""), False),
        ((2, "staff", "create"), ("apikey", 1, "private", ""), False),
        ((2, "staff", "edit"), ("apikey", 1, "private", ""), False),
        ((2, "staff", "delete"), ("apikey", 1, "private", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("apikey", 1, "private", ""),
            False,
        ),
        ((2, "staff", "change_owner"), ("apikey", 1, "private", ""), False),
    ],
)
def test_staff_access_to_apikeys(access, target, expected):
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
        # staff -> self-owned private preferences
        ((2, "staff", "list"), ("preference", 2, "private", ""), True),
        ((2, "staff", "view"), ("preference", 2, "private", ""), True),
        ((2, "staff", "create"), ("preference", 2, "private", ""), False),
        ((2, "staff", "edit"), ("preference", 2, "private", ""), True),
        ((2, "staff", "delete"), ("preference", 2, "private", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("preference", 2, "private", ""),
            False,
        ),
        (
            (2, "staff", "change_owner"),
            ("preference", 2, "private", ""),
            False,
        ),
        # staff -> self-owned shared preferences
        ((2, "staff", "list"), ("preference", 2, "shared", ""), False),
        ((2, "staff", "view"), ("preference", 2, "shared", ""), False),
        ((2, "staff", "create"), ("preference", 2, "shared", ""), False),
        ((2, "staff", "edit"), ("preference", 2, "shared", ""), False),
        ((2, "staff", "delete"), ("preference", 2, "shared", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("preference", 2, "shared", ""),
            False,
        ),
        ((2, "staff", "change_owner"), ("preference", 2, "shared", ""), False),
        # staff -> self-owned public preferences
        ((2, "staff", "list"), ("preference", 2, "public", ""), False),
        ((2, "staff", "view"), ("preference", 2, "public", ""), False),
        ((2, "staff", "create"), ("preference", 2, "public", ""), False),
        ((2, "staff", "edit"), ("preference", 2, "public", ""), False),
        ((2, "staff", "delete"), ("preference", 2, "public", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("preference", 2, "public", ""),
            False,
        ),
        ((2, "staff", "change_owner"), ("preference", 2, "public", ""), False),
        # staff -> public preferences from others
        ((2, "staff", "list"), ("preference", 1, "public", ""), False),
        ((2, "staff", "view"), ("preference", 1, "public", ""), False),
        ((2, "staff", "create"), ("preference", 1, "public", ""), False),
        ((2, "staff", "edit"), ("preference", 1, "public", ""), False),
        ((2, "staff", "delete"), ("preference", 1, "public", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("preference", 1, "public", ""),
            False,
        ),
        ((2, "staff", "change_owner"), ("preference", 1, "public", ""), False),
        # staff -> shared preferences from others
        ((2, "staff", "list"), ("preference", 1, "shared", "2,5,6"), False),
        ((2, "staff", "view"), ("preference", 1, "shared", "2,5,6"), False),
        ((2, "staff", "create"), ("preference", 1, "shared", "2,5,6"), False),
        ((2, "staff", "edit"), ("preference", 1, "shared", "2,5,6"), False),
        ((2, "staff", "delete"), ("preference", 1, "shared", "2,5,6"), False),
        (
            (2, "staff", "change_visibility"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "staff", "change_owner"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        # staff -> shared from others but not shared to this
        # user
        ((2, "staff", "list"), ("preference", 1, "shared", "5,6"), False),
        ((2, "staff", "view"), ("preference", 1, "shared", "5,6"), False),
        ((2, "staff", "create"), ("preference", 1, "shared", "5,6"), False),
        ((2, "staff", "edit"), ("preference", 1, "shared", "5,6"), False),
        ((2, "staff", "delete"), ("preference", 1, "shared", "5,6"), False),
        (
            (2, "staff", "change_visibility"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "staff", "change_owner"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        # staff -> private preferences from others
        ((2, "staff", "list"), ("preference", 1, "private", ""), True),
        ((2, "staff", "view"), ("preference", 1, "private", ""), False),
        ((2, "staff", "create"), ("preference", 1, "private", ""), False),
        ((2, "staff", "edit"), ("preference", 1, "private", ""), False),
        ((2, "staff", "delete"), ("preference", 1, "private", ""), False),
        (
            (2, "staff", "change_visibility"),
            ("preference", 1, "private", ""),
            False,
        ),
        (
            (2, "staff", "change_owner"),
            ("preference", 1, "private", ""),
            False,
        ),
    ],
)
def test_staff_access_to_preferences(access, target, expected):
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
