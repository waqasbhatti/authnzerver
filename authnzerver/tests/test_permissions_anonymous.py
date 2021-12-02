# -*- coding: utf-8 -*-
# test_permissions_anonymous.py - Waqas Bhatti (wbhatti@astro.princeton.edu) -
# Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""
This tests permissions for anonymous users.

"""

import os.path
import pytest
from authnzerver import permissions


######################
## ANONYMOUS ACCESS ##
######################


@pytest.mark.parametrize(
    "access,target,expected",
    [
        # anonymous -> self-owned private collection
        ((2, "anonymous", "list"), ("collection", 2, "private", ""), False),
        ((2, "anonymous", "view"), ("collection", 2, "private", ""), False),
        ((2, "anonymous", "create"), ("collection", 2, "private", ""), False),
        ((2, "anonymous", "edit"), ("collection", 2, "private", ""), False),
        ((2, "anonymous", "delete"), ("collection", 2, "private", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("collection", 2, "private", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("collection", 2, "private", ""),
            False,
        ),
        # anonymous -> self-owned shared collection
        ((2, "anonymous", "list"), ("collection", 2, "shared", ""), False),
        ((2, "anonymous", "view"), ("collection", 2, "shared", ""), False),
        ((2, "anonymous", "create"), ("collection", 2, "shared", ""), False),
        ((2, "anonymous", "edit"), ("collection", 2, "shared", ""), False),
        ((2, "anonymous", "delete"), ("collection", 2, "shared", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("collection", 2, "shared", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("collection", 2, "shared", ""),
            False,
        ),
        # anonymous -> self-owned public collection
        ((2, "anonymous", "list"), ("collection", 2, "public", ""), False),
        ((2, "anonymous", "view"), ("collection", 2, "public", ""), False),
        ((2, "anonymous", "create"), ("collection", 2, "public", ""), False),
        ((2, "anonymous", "edit"), ("collection", 2, "public", ""), False),
        ((2, "anonymous", "delete"), ("collection", 2, "public", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("collection", 2, "public", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("collection", 2, "public", ""),
            False,
        ),
        # anonymous -> public collection from others
        ((2, "anonymous", "list"), ("collection", 1, "public", ""), True),
        ((2, "anonymous", "view"), ("collection", 1, "public", ""), True),
        ((2, "anonymous", "create"), ("collection", 1, "public", ""), False),
        ((2, "anonymous", "edit"), ("collection", 1, "public", ""), False),
        ((2, "anonymous", "delete"), ("collection", 1, "public", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("collection", 1, "public", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("collection", 1, "public", ""),
            False,
        ),
        # anonymous -> shared collection from others
        (
            (2, "anonymous", "list"),
            ("collection", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "view"),
            ("collection", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "create"),
            ("collection", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "edit"),
            ("collection", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "delete"),
            ("collection", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_visibility"),
            ("collection", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("collection", 1, "shared", "2,5,6"),
            False,
        ),
        # anonymous -> shared from others but not shared to this
        # user (should all fail)
        ((2, "anonymous", "list"), ("collection", 1, "shared", "5,6"), False),
        ((2, "anonymous", "view"), ("collection", 1, "shared", "5,6"), False),
        (
            (2, "anonymous", "create"),
            ("collection", 1, "shared", "5,6"),
            False,
        ),
        ((2, "anonymous", "edit"), ("collection", 1, "shared", "5,6"), False),
        (
            (2, "anonymous", "delete"),
            ("collection", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_visibility"),
            ("collection", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("collection", 1, "shared", "5,6"),
            False,
        ),
        # anonymous -> private collection from others
        ((2, "anonymous", "list"), ("collection", 1, "private", ""), False),
        ((2, "anonymous", "view"), ("collection", 1, "private", ""), False),
        ((2, "anonymous", "create"), ("collection", 1, "private", ""), False),
        ((2, "anonymous", "edit"), ("collection", 1, "private", ""), False),
        ((2, "anonymous", "delete"), ("collection", 1, "private", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("collection", 1, "private", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("collection", 1, "private", ""),
            False,
        ),
    ],
)
def test_check_anonymous_access_to_collection(access, target, expected):
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
        # anonymous -> self-owned private dataset
        ((2, "anonymous", "list"), ("dataset", 2, "private", ""), True),
        ((2, "anonymous", "view"), ("dataset", 2, "private", ""), True),
        ((2, "anonymous", "create"), ("dataset", 2, "private", ""), True),
        ((2, "anonymous", "edit"), ("dataset", 2, "private", ""), False),
        ((2, "anonymous", "delete"), ("dataset", 2, "private", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("dataset", 2, "private", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("dataset", 2, "private", ""),
            False,
        ),
        # anonymous -> self-owned shared dataset
        ((2, "anonymous", "list"), ("dataset", 2, "shared", ""), True),
        ((2, "anonymous", "view"), ("dataset", 2, "shared", ""), True),
        ((2, "anonymous", "create"), ("dataset", 2, "shared", ""), True),
        ((2, "anonymous", "edit"), ("dataset", 2, "shared", ""), False),
        ((2, "anonymous", "delete"), ("dataset", 2, "shared", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("dataset", 2, "shared", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("dataset", 2, "shared", ""),
            False,
        ),
        # anonymous -> self-owned public dataset
        ((2, "anonymous", "list"), ("dataset", 2, "public", ""), True),
        ((2, "anonymous", "view"), ("dataset", 2, "public", ""), True),
        ((2, "anonymous", "create"), ("dataset", 2, "public", ""), True),
        ((2, "anonymous", "edit"), ("dataset", 2, "public", ""), False),
        ((2, "anonymous", "delete"), ("dataset", 2, "public", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("dataset", 2, "public", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("dataset", 2, "public", ""),
            False,
        ),
        # anonymous -> public dataset from others
        ((2, "anonymous", "list"), ("dataset", 1, "public", ""), True),
        ((2, "anonymous", "view"), ("dataset", 1, "public", ""), True),
        ((2, "anonymous", "create"), ("dataset", 1, "public", ""), False),
        ((2, "anonymous", "edit"), ("dataset", 1, "public", ""), False),
        ((2, "anonymous", "delete"), ("dataset", 1, "public", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("dataset", 1, "public", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("dataset", 1, "public", ""),
            False,
        ),
        # anonymous -> shared dataset from others
        ((2, "anonymous", "list"), ("dataset", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "view"), ("dataset", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "create"), ("dataset", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "edit"), ("dataset", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "delete"), ("dataset", 1, "shared", "2,5,6"), False),
        (
            (2, "anonymous", "change_visibility"),
            ("dataset", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("dataset", 1, "shared", "2,5,6"),
            False,
        ),
        # anonymous -> shared from others but not shared to this
        # user (should all fail)
        ((2, "anonymous", "list"), ("dataset", 1, "shared", "5,6"), False),
        ((2, "anonymous", "view"), ("dataset", 1, "shared", "5,6"), False),
        ((2, "anonymous", "create"), ("dataset", 1, "shared", "5,6"), False),
        ((2, "anonymous", "edit"), ("dataset", 1, "shared", "5,6"), False),
        ((2, "anonymous", "delete"), ("dataset", 1, "shared", "5,6"), False),
        (
            (2, "anonymous", "change_visibility"),
            ("dataset", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("dataset", 1, "shared", "5,6"),
            False,
        ),
        # anonymous -> private dataset from others
        ((2, "anonymous", "list"), ("dataset", 1, "private", ""), False),
        ((2, "anonymous", "view"), ("dataset", 1, "private", ""), False),
        ((2, "anonymous", "create"), ("dataset", 1, "private", ""), False),
        ((2, "anonymous", "edit"), ("dataset", 1, "private", ""), False),
        ((2, "anonymous", "delete"), ("dataset", 1, "private", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("dataset", 1, "private", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("dataset", 1, "private", ""),
            False,
        ),
    ],
)
def test_check_anonymous_access_to_dataset(access, target, expected):
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
        # anonymous -> self-owned private object
        ((2, "anonymous", "list"), ("object", 2, "private", ""), False),
        ((2, "anonymous", "view"), ("object", 2, "private", ""), False),
        ((2, "anonymous", "create"), ("object", 2, "private", ""), False),
        ((2, "anonymous", "edit"), ("object", 2, "private", ""), False),
        ((2, "anonymous", "delete"), ("object", 2, "private", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("object", 2, "private", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("object", 2, "private", ""),
            False,
        ),
        # anonymous -> self-owned shared object
        ((2, "anonymous", "list"), ("object", 2, "shared", ""), False),
        ((2, "anonymous", "view"), ("object", 2, "shared", ""), False),
        ((2, "anonymous", "create"), ("object", 2, "shared", ""), False),
        ((2, "anonymous", "edit"), ("object", 2, "shared", ""), False),
        ((2, "anonymous", "delete"), ("object", 2, "shared", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("object", 2, "shared", ""),
            False,
        ),
        ((2, "anonymous", "change_owner"), ("object", 2, "shared", ""), False),
        # anonymous -> self-owned public object (should all fail)
        ((2, "anonymous", "list"), ("object", 2, "public", ""), False),
        ((2, "anonymous", "view"), ("object", 2, "public", ""), False),
        ((2, "anonymous", "create"), ("object", 2, "public", ""), False),
        ((2, "anonymous", "edit"), ("object", 2, "public", ""), False),
        ((2, "anonymous", "delete"), ("object", 2, "public", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("object", 2, "public", ""),
            False,
        ),
        ((2, "anonymous", "change_owner"), ("object", 2, "public", ""), False),
        # anonymous -> public object from others (list, view OK)
        ((2, "anonymous", "list"), ("object", 1, "public", ""), True),
        ((2, "anonymous", "view"), ("object", 1, "public", ""), True),
        ((2, "anonymous", "create"), ("object", 1, "public", ""), False),
        ((2, "anonymous", "edit"), ("object", 1, "public", ""), False),
        ((2, "anonymous", "delete"), ("object", 1, "public", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("object", 1, "public", ""),
            False,
        ),
        ((2, "anonymous", "change_owner"), ("object", 1, "public", ""), False),
        # anonymous -> shared object from others (should all fail)
        ((2, "anonymous", "list"), ("object", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "view"), ("object", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "create"), ("object", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "edit"), ("object", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "delete"), ("object", 1, "shared", "2,5,6"), False),
        (
            (2, "anonymous", "change_visibility"),
            ("object", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("object", 1, "shared", "2,5,6"),
            False,
        ),
        # anonymous -> shared from others but not shared to this
        # user (should all fail)
        ((2, "anonymous", "list"), ("object", 1, "shared", "5,6"), False),
        ((2, "anonymous", "view"), ("object", 1, "shared", "5,6"), False),
        ((2, "anonymous", "create"), ("object", 1, "shared", "5,6"), False),
        ((2, "anonymous", "edit"), ("object", 1, "shared", "5,6"), False),
        ((2, "anonymous", "delete"), ("object", 1, "shared", "5,6"), False),
        (
            (2, "anonymous", "change_visibility"),
            ("object", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("object", 1, "shared", "5,6"),
            False,
        ),
        # anonymous -> private object from others (should all fail)
        ((2, "anonymous", "list"), ("object", 1, "private", ""), False),
        ((2, "anonymous", "view"), ("object", 1, "private", ""), False),
        ((2, "anonymous", "create"), ("object", 1, "private", ""), False),
        ((2, "anonymous", "edit"), ("object", 1, "private", ""), False),
        ((2, "anonymous", "delete"), ("object", 1, "private", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("object", 1, "private", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("object", 1, "private", ""),
            False,
        ),
    ],
)
def test_check_anonymous_access_to_object(access, target, expected):
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
        # anonymous -> self-owned private users
        ((2, "anonymous", "list"), ("user", 2, "private", ""), False),
        ((2, "anonymous", "view"), ("user", 2, "private", ""), False),
        ((2, "anonymous", "create"), ("user", 2, "private", ""), False),
        ((2, "anonymous", "edit"), ("user", 2, "private", ""), False),
        ((2, "anonymous", "delete"), ("user", 2, "private", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("user", 2, "private", ""),
            False,
        ),
        ((2, "anonymous", "change_owner"), ("user", 2, "private", ""), False),
        # anonymous -> self-owned shared users
        ((2, "anonymous", "list"), ("user", 2, "shared", ""), False),
        ((2, "anonymous", "view"), ("user", 2, "shared", ""), False),
        ((2, "anonymous", "create"), ("user", 2, "shared", ""), False),
        ((2, "anonymous", "edit"), ("user", 2, "shared", ""), False),
        ((2, "anonymous", "delete"), ("user", 2, "shared", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("user", 2, "shared", ""),
            False,
        ),
        ((2, "anonymous", "change_owner"), ("user", 2, "shared", ""), False),
        # anonymous -> self-owned public users (should all fail)
        ((2, "anonymous", "list"), ("user", 2, "public", ""), False),
        ((2, "anonymous", "view"), ("user", 2, "public", ""), False),
        ((2, "anonymous", "create"), ("user", 2, "public", ""), False),
        ((2, "anonymous", "edit"), ("user", 2, "public", ""), False),
        ((2, "anonymous", "delete"), ("user", 2, "public", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("user", 2, "public", ""),
            False,
        ),
        ((2, "anonymous", "change_owner"), ("user", 2, "public", ""), False),
        # anonymous -> public users from others (should all fail)
        ((2, "anonymous", "list"), ("user", 1, "public", ""), False),
        ((2, "anonymous", "view"), ("user", 1, "public", ""), False),
        ((2, "anonymous", "create"), ("user", 1, "public", ""), False),
        ((2, "anonymous", "edit"), ("user", 1, "public", ""), False),
        ((2, "anonymous", "delete"), ("user", 1, "public", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("user", 1, "public", ""),
            False,
        ),
        ((2, "anonymous", "change_owner"), ("user", 1, "public", ""), False),
        # anonymous -> shared users from others (should all fail)
        ((2, "anonymous", "list"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "view"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "create"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "edit"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "delete"), ("user", 1, "shared", "2,5,6"), False),
        (
            (2, "anonymous", "change_visibility"),
            ("user", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "make_shared"),
            ("user", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("user", 1, "shared", "2,5,6"),
            False,
        ),
        # anonymous -> shared from others but not shared to this
        # user (should all fail)
        ((2, "anonymous", "list"), ("user", 1, "shared", "5,6"), False),
        ((2, "anonymous", "view"), ("user", 1, "shared", "5,6"), False),
        ((2, "anonymous", "create"), ("user", 1, "shared", "5,6"), False),
        ((2, "anonymous", "edit"), ("user", 1, "shared", "5,6"), False),
        ((2, "anonymous", "delete"), ("user", 1, "shared", "5,6"), False),
        (
            (2, "anonymous", "change_visibility"),
            ("user", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("user", 1, "shared", "5,6"),
            False,
        ),
        # anonymous -> private users from others (should all fail)
        ((2, "anonymous", "list"), ("user", 1, "private", ""), False),
        ((2, "anonymous", "view"), ("user", 1, "private", ""), False),
        ((2, "anonymous", "create"), ("user", 1, "private", ""), False),
        ((2, "anonymous", "edit"), ("user", 1, "private", ""), False),
        ((2, "anonymous", "delete"), ("user", 1, "private", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("user", 1, "private", ""),
            False,
        ),
        ((2, "anonymous", "change_owner"), ("user", 1, "private", ""), False),
    ],
)
def test_check_anonymous_access_to_users(access, target, expected):
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
        # anonymous -> self-owned private sessions
        ((2, "anonymous", "list"), ("session", 2, "private", ""), False),
        ((2, "anonymous", "view"), ("session", 2, "private", ""), False),
        ((2, "anonymous", "create"), ("session", 2, "private", ""), False),
        ((2, "anonymous", "edit"), ("session", 2, "private", ""), False),
        ((2, "anonymous", "delete"), ("session", 2, "private", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("session", 2, "private", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("session", 2, "private", ""),
            False,
        ),
        # anonymous -> self-owned shared sessions
        ((2, "anonymous", "list"), ("session", 2, "shared", ""), False),
        ((2, "anonymous", "view"), ("session", 2, "shared", ""), False),
        ((2, "anonymous", "create"), ("session", 2, "shared", ""), False),
        ((2, "anonymous", "edit"), ("session", 2, "shared", ""), False),
        ((2, "anonymous", "delete"), ("session", 2, "shared", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("session", 2, "shared", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("session", 2, "shared", ""),
            False,
        ),
        # anonymous -> self-owned public sessions (should all fail)
        ((2, "anonymous", "list"), ("session", 2, "public", ""), False),
        ((2, "anonymous", "view"), ("session", 2, "public", ""), False),
        ((2, "anonymous", "create"), ("session", 2, "public", ""), False),
        ((2, "anonymous", "edit"), ("session", 2, "public", ""), False),
        ((2, "anonymous", "delete"), ("session", 2, "public", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("session", 2, "public", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("session", 2, "public", ""),
            False,
        ),
        # anonymous -> public sessions from others (should all fail)
        ((2, "anonymous", "list"), ("session", 1, "public", ""), False),
        ((2, "anonymous", "view"), ("session", 1, "public", ""), False),
        ((2, "anonymous", "create"), ("session", 1, "public", ""), False),
        ((2, "anonymous", "edit"), ("session", 1, "public", ""), False),
        ((2, "anonymous", "delete"), ("session", 1, "public", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("session", 1, "public", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("session", 1, "public", ""),
            False,
        ),
        # anonymous -> shared sessions from others (should all fail)
        ((2, "anonymous", "list"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "view"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "create"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "edit"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "delete"), ("session", 1, "shared", "2,5,6"), False),
        (
            (2, "anonymous", "change_visibility"),
            ("session", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("session", 1, "shared", "2,5,6"),
            False,
        ),
        # anonymous -> shared from others but not shared to this
        # user (should all fail)
        ((2, "anonymous", "list"), ("session", 1, "shared", "5,6"), False),
        ((2, "anonymous", "view"), ("session", 1, "shared", "5,6"), False),
        ((2, "anonymous", "create"), ("session", 1, "shared", "5,6"), False),
        ((2, "anonymous", "edit"), ("session", 1, "shared", "5,6"), False),
        ((2, "anonymous", "delete"), ("session", 1, "shared", "5,6"), False),
        (
            (2, "anonymous", "change_visibility"),
            ("session", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("session", 1, "shared", "5,6"),
            False,
        ),
        # anonymous -> private sessions from others (should all fail)
        ((2, "anonymous", "list"), ("session", 1, "private", ""), False),
        ((2, "anonymous", "view"), ("session", 1, "private", ""), False),
        ((2, "anonymous", "create"), ("session", 1, "private", ""), False),
        ((2, "anonymous", "edit"), ("session", 1, "private", ""), False),
        ((2, "anonymous", "delete"), ("session", 1, "private", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("session", 1, "private", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("session", 1, "private", ""),
            False,
        ),
    ],
)
def test_check_anonymous_access_to_sessions(access, target, expected):
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
        # anonymous -> self-owned private apikeys
        ((2, "anonymous", "list"), ("apikey", 2, "private", ""), False),
        ((2, "anonymous", "view"), ("apikey", 2, "private", ""), False),
        ((2, "anonymous", "create"), ("apikey", 2, "private", ""), False),
        ((2, "anonymous", "edit"), ("apikey", 2, "private", ""), False),
        ((2, "anonymous", "delete"), ("apikey", 2, "private", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("apikey", 2, "private", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("apikey", 2, "private", ""),
            False,
        ),
        # anonymous -> self-owned shared apikeys
        ((2, "anonymous", "list"), ("apikey", 2, "shared", ""), False),
        ((2, "anonymous", "view"), ("apikey", 2, "shared", ""), False),
        ((2, "anonymous", "create"), ("apikey", 2, "shared", ""), False),
        ((2, "anonymous", "edit"), ("apikey", 2, "shared", ""), False),
        ((2, "anonymous", "delete"), ("apikey", 2, "shared", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("apikey", 2, "shared", ""),
            False,
        ),
        ((2, "anonymous", "change_owner"), ("apikey", 2, "shared", ""), False),
        # anonymous -> self-owned public apikeys (should all fail)
        ((2, "anonymous", "list"), ("apikey", 2, "public", ""), False),
        ((2, "anonymous", "view"), ("apikey", 2, "public", ""), False),
        ((2, "anonymous", "create"), ("apikey", 2, "public", ""), False),
        ((2, "anonymous", "edit"), ("apikey", 2, "public", ""), False),
        ((2, "anonymous", "delete"), ("apikey", 2, "public", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("apikey", 2, "public", ""),
            False,
        ),
        ((2, "anonymous", "change_owner"), ("apikey", 2, "public", ""), False),
        # anonymous -> public apikeys from others (should all fail)
        ((2, "anonymous", "list"), ("apikey", 1, "public", ""), False),
        ((2, "anonymous", "view"), ("apikey", 1, "public", ""), False),
        ((2, "anonymous", "create"), ("apikey", 1, "public", ""), False),
        ((2, "anonymous", "edit"), ("apikey", 1, "public", ""), False),
        ((2, "anonymous", "delete"), ("apikey", 1, "public", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("apikey", 1, "public", ""),
            False,
        ),
        ((2, "anonymous", "change_owner"), ("apikey", 1, "public", ""), False),
        # anonymous -> shared apikeys from others (should all fail)
        ((2, "anonymous", "list"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "view"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "create"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "edit"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "anonymous", "delete"), ("apikey", 1, "shared", "2,5,6"), False),
        (
            (2, "anonymous", "change_visibility"),
            ("apikey", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("apikey", 1, "shared", "2,5,6"),
            False,
        ),
        # anonymous -> shared from others but not shared to this
        # user (should all fail)
        ((2, "anonymous", "list"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "anonymous", "view"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "anonymous", "create"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "anonymous", "edit"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "anonymous", "delete"), ("apikey", 1, "shared", "5,6"), False),
        (
            (2, "anonymous", "change_visibility"),
            ("apikey", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("apikey", 1, "shared", "5,6"),
            False,
        ),
        # anonymous -> private apikeys from others (should all fail)
        ((2, "anonymous", "list"), ("apikey", 1, "private", ""), False),
        ((2, "anonymous", "view"), ("apikey", 1, "private", ""), False),
        ((2, "anonymous", "create"), ("apikey", 1, "private", ""), False),
        ((2, "anonymous", "edit"), ("apikey", 1, "private", ""), False),
        ((2, "anonymous", "delete"), ("apikey", 1, "private", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("apikey", 1, "private", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("apikey", 1, "private", ""),
            False,
        ),
    ],
)
def test_check_anonymous_access_to_apikeys(access, target, expected):
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
        # anonymous -> self-owned private preferences
        ((2, "anonymous", "list"), ("preference", 2, "private", ""), False),
        ((2, "anonymous", "view"), ("preference", 2, "private", ""), False),
        ((2, "anonymous", "create"), ("preference", 2, "private", ""), False),
        ((2, "anonymous", "edit"), ("preference", 2, "private", ""), False),
        ((2, "anonymous", "delete"), ("preference", 2, "private", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("preference", 2, "private", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("preference", 2, "private", ""),
            False,
        ),
        # anonymous -> self-owned shared preferences
        ((2, "anonymous", "list"), ("preference", 2, "shared", ""), False),
        ((2, "anonymous", "view"), ("preference", 2, "shared", ""), False),
        ((2, "anonymous", "create"), ("preference", 2, "shared", ""), False),
        ((2, "anonymous", "edit"), ("preference", 2, "shared", ""), False),
        ((2, "anonymous", "delete"), ("preference", 2, "shared", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("preference", 2, "shared", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("preference", 2, "shared", ""),
            False,
        ),
        # anonymous -> self-owned public preferences (should all fail)
        ((2, "anonymous", "list"), ("preference", 2, "public", ""), False),
        ((2, "anonymous", "view"), ("preference", 2, "public", ""), False),
        ((2, "anonymous", "create"), ("preference", 2, "public", ""), False),
        ((2, "anonymous", "edit"), ("preference", 2, "public", ""), False),
        ((2, "anonymous", "delete"), ("preference", 2, "public", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("preference", 2, "public", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("preference", 2, "public", ""),
            False,
        ),
        # anonymous -> public preferences from others (should all fail)
        ((2, "anonymous", "list"), ("preference", 1, "public", ""), False),
        ((2, "anonymous", "view"), ("preference", 1, "public", ""), False),
        ((2, "anonymous", "create"), ("preference", 1, "public", ""), False),
        ((2, "anonymous", "edit"), ("preference", 1, "public", ""), False),
        ((2, "anonymous", "delete"), ("preference", 1, "public", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("preference", 1, "public", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("preference", 1, "public", ""),
            False,
        ),
        # anonymous -> shared preferences from others (should all fail)
        (
            (2, "anonymous", "list"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "view"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "create"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "edit"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "delete"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_visibility"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        # anonymous -> shared from others but not shared to this
        # user (should all fail)
        ((2, "anonymous", "list"), ("preference", 1, "shared", "5,6"), False),
        ((2, "anonymous", "view"), ("preference", 1, "shared", "5,6"), False),
        (
            (2, "anonymous", "create"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        ((2, "anonymous", "edit"), ("preference", 1, "shared", "5,6"), False),
        (
            (2, "anonymous", "delete"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_visibility"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        # anonymous -> private preferences from others (should all fail)
        ((2, "anonymous", "list"), ("preference", 1, "private", ""), False),
        ((2, "anonymous", "view"), ("preference", 1, "private", ""), False),
        ((2, "anonymous", "create"), ("preference", 1, "private", ""), False),
        ((2, "anonymous", "edit"), ("preference", 1, "private", ""), False),
        ((2, "anonymous", "delete"), ("preference", 1, "private", ""), False),
        (
            (2, "anonymous", "change_visibility"),
            ("preference", 1, "private", ""),
            False,
        ),
        (
            (2, "anonymous", "change_owner"),
            ("preference", 1, "private", ""),
            False,
        ),
    ],
)
def test_check_anonymous_access_to_preferences(access, target, expected):
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
