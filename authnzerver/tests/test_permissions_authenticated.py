# -*- coding: utf-8 -*-
# test_permissions_authenticated.py - Waqas Bhatti (wbhatti@astro.princeton.edu)
# - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""
This tests permissions for authenticated users.

"""

import os.path
import pytest
from authnzerver import permissions


##########################
## AUTHENTICATED ACCESS ##
##########################


@pytest.mark.parametrize(
    "access,target,expected",
    [
        # authenticated -> self-owned private collection
        (
            (2, "authenticated", "list"),
            ("collection", 2, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "view"),
            ("collection", 2, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "create"),
            ("collection", 2, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "edit"),
            ("collection", 2, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "delete"),
            ("collection", 2, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("collection", 2, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("collection", 2, "private", ""),
            False,
        ),
        # authenticated -> self-owned shared collection
        ((2, "authenticated", "list"), ("collection", 2, "shared", ""), False),
        ((2, "authenticated", "view"), ("collection", 2, "shared", ""), False),
        (
            (2, "authenticated", "create"),
            ("collection", 2, "shared", ""),
            False,
        ),
        ((2, "authenticated", "edit"), ("collection", 2, "shared", ""), False),
        (
            (2, "authenticated", "delete"),
            ("collection", 2, "shared", ""),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("collection", 2, "shared", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("collection", 2, "shared", ""),
            False,
        ),
        # authenticated -> self-owned public collection
        ((2, "authenticated", "list"), ("collection", 2, "public", ""), False),
        ((2, "authenticated", "view"), ("collection", 2, "public", ""), False),
        (
            (2, "authenticated", "create"),
            ("collection", 2, "public", ""),
            False,
        ),
        ((2, "authenticated", "edit"), ("collection", 2, "public", ""), False),
        (
            (2, "authenticated", "delete"),
            ("collection", 2, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("collection", 2, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("collection", 2, "public", ""),
            False,
        ),
        # authenticated -> public collection from others
        ((2, "authenticated", "list"), ("collection", 1, "public", ""), True),
        ((2, "authenticated", "view"), ("collection", 1, "public", ""), True),
        (
            (2, "authenticated", "create"),
            ("collection", 1, "public", ""),
            False,
        ),
        ((2, "authenticated", "edit"), ("collection", 1, "public", ""), False),
        (
            (2, "authenticated", "delete"),
            ("collection", 1, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("collection", 1, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("collection", 1, "public", ""),
            False,
        ),
        # authenticated -> shared collection from others
        (
            (2, "authenticated", "list"),
            ("collection", 1, "shared", "2,5,6"),
            True,
        ),
        (
            (2, "authenticated", "view"),
            ("collection", 1, "shared", "2,5,6"),
            True,
        ),
        (
            (2, "authenticated", "create"),
            ("collection", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "edit"),
            ("collection", 1, "shared", "2,5,6"),
            True,
        ),
        (
            (2, "authenticated", "delete"),
            ("collection", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("collection", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("collection", 1, "shared", "2,5,6"),
            False,
        ),
        # authenticated -> shared from others but not shared to this
        # user (should all fail)
        (
            (2, "authenticated", "list"),
            ("collection", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "view"),
            ("collection", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "create"),
            ("collection", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "edit"),
            ("collection", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "delete"),
            ("collection", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("collection", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("collection", 1, "shared", "5,6"),
            False,
        ),
        # authenticated -> private collection from others
        (
            (2, "authenticated", "list"),
            ("collection", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "view"),
            ("collection", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "create"),
            ("collection", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "edit"),
            ("collection", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "delete"),
            ("collection", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("collection", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("collection", 1, "private", ""),
            False,
        ),
    ],
)
def test_check_authenticated_access_to_collection(access, target, expected):
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
        # authenticated -> self-owned private dataset
        ((2, "authenticated", "list"), ("dataset", 2, "private", ""), True),
        ((2, "authenticated", "view"), ("dataset", 2, "private", ""), True),
        ((2, "authenticated", "create"), ("dataset", 2, "private", ""), True),
        ((2, "authenticated", "edit"), ("dataset", 2, "private", ""), True),
        ((2, "authenticated", "delete"), ("dataset", 2, "private", ""), True),
        (
            (2, "authenticated", "change_visibility"),
            ("dataset", 2, "private", ""),
            True,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("dataset", 2, "private", ""),
            False,
        ),
        # authenticated -> self-owned shared dataset
        ((2, "authenticated", "list"), ("dataset", 2, "shared", ""), True),
        ((2, "authenticated", "view"), ("dataset", 2, "shared", ""), True),
        ((2, "authenticated", "create"), ("dataset", 2, "shared", ""), True),
        ((2, "authenticated", "edit"), ("dataset", 2, "shared", ""), True),
        ((2, "authenticated", "delete"), ("dataset", 2, "shared", ""), True),
        (
            (2, "authenticated", "change_visibility"),
            ("dataset", 2, "shared", ""),
            True,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("dataset", 2, "shared", ""),
            False,
        ),
        # authenticated -> self-owned public dataset
        ((2, "authenticated", "list"), ("dataset", 2, "public", ""), True),
        ((2, "authenticated", "view"), ("dataset", 2, "public", ""), True),
        ((2, "authenticated", "create"), ("dataset", 2, "public", ""), True),
        ((2, "authenticated", "edit"), ("dataset", 2, "public", ""), True),
        ((2, "authenticated", "delete"), ("dataset", 2, "public", ""), True),
        (
            (2, "authenticated", "change_visibility"),
            ("dataset", 2, "public", ""),
            True,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("dataset", 2, "public", ""),
            False,
        ),
        # authenticated -> public dataset from others
        ((2, "authenticated", "list"), ("dataset", 1, "public", ""), True),
        ((2, "authenticated", "view"), ("dataset", 1, "public", ""), True),
        ((2, "authenticated", "create"), ("dataset", 1, "public", ""), False),
        ((2, "authenticated", "edit"), ("dataset", 1, "public", ""), False),
        ((2, "authenticated", "delete"), ("dataset", 1, "public", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("dataset", 1, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("dataset", 1, "public", ""),
            False,
        ),
        # authenticated -> shared dataset from others
        (
            (2, "authenticated", "list"),
            ("dataset", 1, "shared", "2,5,6"),
            True,
        ),
        (
            (2, "authenticated", "view"),
            ("dataset", 1, "shared", "2,5,6"),
            True,
        ),
        (
            (2, "authenticated", "create"),
            ("dataset", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "edit"),
            ("dataset", 1, "shared", "2,5,6"),
            True,
        ),
        (
            (2, "authenticated", "delete"),
            ("dataset", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("dataset", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("dataset", 1, "shared", "2,5,6"),
            False,
        ),
        # authenticated -> shared from others but not shared to this
        # user (should all fail)
        ((2, "authenticated", "list"), ("dataset", 1, "shared", "5,6"), False),
        ((2, "authenticated", "view"), ("dataset", 1, "shared", "5,6"), False),
        (
            (2, "authenticated", "create"),
            ("dataset", 1, "shared", "5,6"),
            False,
        ),
        ((2, "authenticated", "edit"), ("dataset", 1, "shared", "5,6"), False),
        (
            (2, "authenticated", "delete"),
            ("dataset", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("dataset", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("dataset", 1, "shared", "5,6"),
            False,
        ),
        # authenticated -> private dataset from others
        ((2, "authenticated", "list"), ("dataset", 1, "private", ""), False),
        ((2, "authenticated", "view"), ("dataset", 1, "private", ""), False),
        ((2, "authenticated", "create"), ("dataset", 1, "private", ""), False),
        ((2, "authenticated", "edit"), ("dataset", 1, "private", ""), False),
        ((2, "authenticated", "delete"), ("dataset", 1, "private", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("dataset", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("dataset", 1, "private", ""),
            False,
        ),
    ],
)
def test_check_authenticated_access_to_dataset(access, target, expected):
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
        # authenticated -> self-owned private object
        ((2, "authenticated", "list"), ("object", 2, "private", ""), False),
        ((2, "authenticated", "view"), ("object", 2, "private", ""), False),
        ((2, "authenticated", "create"), ("object", 2, "private", ""), False),
        ((2, "authenticated", "edit"), ("object", 2, "private", ""), False),
        ((2, "authenticated", "delete"), ("object", 2, "private", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("object", 2, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("object", 2, "private", ""),
            False,
        ),
        # authenticated -> self-owned shared object
        ((2, "authenticated", "list"), ("object", 2, "shared", ""), False),
        ((2, "authenticated", "view"), ("object", 2, "shared", ""), False),
        ((2, "authenticated", "create"), ("object", 2, "shared", ""), False),
        ((2, "authenticated", "edit"), ("object", 2, "shared", ""), False),
        ((2, "authenticated", "delete"), ("object", 2, "shared", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("object", 2, "shared", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("object", 2, "shared", ""),
            False,
        ),
        # authenticated -> self-owned public object (should all fail)
        ((2, "authenticated", "list"), ("object", 2, "public", ""), False),
        ((2, "authenticated", "view"), ("object", 2, "public", ""), False),
        ((2, "authenticated", "create"), ("object", 2, "public", ""), False),
        ((2, "authenticated", "edit"), ("object", 2, "public", ""), False),
        ((2, "authenticated", "delete"), ("object", 2, "public", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("object", 2, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("object", 2, "public", ""),
            False,
        ),
        # authenticated -> public object from others (list, view OK)
        ((2, "authenticated", "list"), ("object", 1, "public", ""), True),
        ((2, "authenticated", "view"), ("object", 1, "public", ""), True),
        ((2, "authenticated", "create"), ("object", 1, "public", ""), False),
        ((2, "authenticated", "edit"), ("object", 1, "public", ""), False),
        ((2, "authenticated", "delete"), ("object", 1, "public", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("object", 1, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("object", 1, "public", ""),
            False,
        ),
        # authenticated -> shared object from others (should all fail)
        ((2, "authenticated", "list"), ("object", 1, "shared", "2,5,6"), True),
        ((2, "authenticated", "view"), ("object", 1, "shared", "2,5,6"), True),
        (
            (2, "authenticated", "create"),
            ("object", 1, "shared", "2,5,6"),
            False,
        ),
        ((2, "authenticated", "edit"), ("object", 1, "shared", "2,5,6"), True),
        (
            (2, "authenticated", "delete"),
            ("object", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("object", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("object", 1, "shared", "2,5,6"),
            False,
        ),
        # authenticated -> shared from others but not shared to this
        # user (should all fail)
        ((2, "authenticated", "list"), ("object", 1, "shared", "5,6"), False),
        ((2, "authenticated", "view"), ("object", 1, "shared", "5,6"), False),
        (
            (2, "authenticated", "create"),
            ("object", 1, "shared", "5,6"),
            False,
        ),
        ((2, "authenticated", "edit"), ("object", 1, "shared", "5,6"), False),
        (
            (2, "authenticated", "delete"),
            ("object", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("object", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("object", 1, "shared", "5,6"),
            False,
        ),
        # authenticated -> private object from others (should all fail)
        ((2, "authenticated", "list"), ("object", 1, "private", ""), False),
        ((2, "authenticated", "view"), ("object", 1, "private", ""), False),
        ((2, "authenticated", "create"), ("object", 1, "private", ""), False),
        ((2, "authenticated", "edit"), ("object", 1, "private", ""), False),
        ((2, "authenticated", "delete"), ("object", 1, "private", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("object", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("object", 1, "private", ""),
            False,
        ),
    ],
)
def test_check_authenticated_access_to_object(access, target, expected):
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
        # authenticated -> self-owned private users
        ((2, "authenticated", "list"), ("user", 2, "private", ""), False),
        ((2, "authenticated", "view"), ("user", 2, "private", ""), False),
        ((2, "authenticated", "create"), ("user", 2, "private", ""), False),
        ((2, "authenticated", "edit"), ("user", 2, "private", ""), False),
        ((2, "authenticated", "delete"), ("user", 2, "private", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("user", 2, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("user", 2, "private", ""),
            False,
        ),
        # authenticated -> self-owned shared users
        ((2, "authenticated", "list"), ("user", 2, "shared", ""), False),
        ((2, "authenticated", "view"), ("user", 2, "shared", ""), False),
        ((2, "authenticated", "create"), ("user", 2, "shared", ""), False),
        ((2, "authenticated", "edit"), ("user", 2, "shared", ""), False),
        ((2, "authenticated", "delete"), ("user", 2, "shared", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("user", 2, "shared", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("user", 2, "shared", ""),
            False,
        ),
        # authenticated -> self-owned public users (should all fail)
        ((2, "authenticated", "list"), ("user", 2, "public", ""), False),
        ((2, "authenticated", "view"), ("user", 2, "public", ""), False),
        ((2, "authenticated", "create"), ("user", 2, "public", ""), False),
        ((2, "authenticated", "edit"), ("user", 2, "public", ""), False),
        ((2, "authenticated", "delete"), ("user", 2, "public", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("user", 2, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("user", 2, "public", ""),
            False,
        ),
        # authenticated -> public users from others (should all fail)
        ((2, "authenticated", "list"), ("user", 1, "public", ""), False),
        ((2, "authenticated", "view"), ("user", 1, "public", ""), False),
        ((2, "authenticated", "create"), ("user", 1, "public", ""), False),
        ((2, "authenticated", "edit"), ("user", 1, "public", ""), False),
        ((2, "authenticated", "delete"), ("user", 1, "public", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("user", 1, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("user", 1, "public", ""),
            False,
        ),
        # authenticated -> shared users from others (should all fail)
        ((2, "authenticated", "list"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "authenticated", "view"), ("user", 1, "shared", "2,5,6"), False),
        (
            (2, "authenticated", "create"),
            ("user", 1, "shared", "2,5,6"),
            False,
        ),
        ((2, "authenticated", "edit"), ("user", 1, "shared", "2,5,6"), False),
        (
            (2, "authenticated", "delete"),
            ("user", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("user", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("user", 1, "shared", "2,5,6"),
            False,
        ),
        # authenticated -> shared from others but not shared to this
        # user (should all fail)
        ((2, "authenticated", "list"), ("user", 1, "shared", "5,6"), False),
        ((2, "authenticated", "view"), ("user", 1, "shared", "5,6"), False),
        ((2, "authenticated", "create"), ("user", 1, "shared", "5,6"), False),
        ((2, "authenticated", "edit"), ("user", 1, "shared", "5,6"), False),
        ((2, "authenticated", "delete"), ("user", 1, "shared", "5,6"), False),
        (
            (2, "authenticated", "change_visibility"),
            ("user", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("user", 1, "shared", "5,6"),
            False,
        ),
        # authenticated -> private users from others (should all fail)
        ((2, "authenticated", "list"), ("user", 1, "private", ""), False),
        ((2, "authenticated", "view"), ("user", 1, "private", ""), False),
        ((2, "authenticated", "create"), ("user", 1, "private", ""), False),
        ((2, "authenticated", "edit"), ("user", 1, "private", ""), False),
        ((2, "authenticated", "delete"), ("user", 1, "private", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("user", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("user", 1, "private", ""),
            False,
        ),
    ],
)
def test_check_authenticated_access_to_users(access, target, expected):
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
        # authenticated -> self-owned private sessions
        ((2, "authenticated", "list"), ("session", 2, "private", ""), False),
        ((2, "authenticated", "view"), ("session", 2, "private", ""), False),
        ((2, "authenticated", "create"), ("session", 2, "private", ""), False),
        ((2, "authenticated", "edit"), ("session", 2, "private", ""), False),
        ((2, "authenticated", "delete"), ("session", 2, "private", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("session", 2, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("session", 2, "private", ""),
            False,
        ),
        # authenticated -> self-owned shared sessions
        ((2, "authenticated", "list"), ("session", 2, "shared", ""), False),
        ((2, "authenticated", "view"), ("session", 2, "shared", ""), False),
        ((2, "authenticated", "create"), ("session", 2, "shared", ""), False),
        ((2, "authenticated", "edit"), ("session", 2, "shared", ""), False),
        ((2, "authenticated", "delete"), ("session", 2, "shared", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("session", 2, "shared", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("session", 2, "shared", ""),
            False,
        ),
        # authenticated -> self-owned public sessions (should all fail)
        ((2, "authenticated", "list"), ("session", 2, "public", ""), False),
        ((2, "authenticated", "view"), ("session", 2, "public", ""), False),
        ((2, "authenticated", "create"), ("session", 2, "public", ""), False),
        ((2, "authenticated", "edit"), ("session", 2, "public", ""), False),
        ((2, "authenticated", "delete"), ("session", 2, "public", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("session", 2, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("session", 2, "public", ""),
            False,
        ),
        # authenticated -> public sessions from others (should all fail)
        ((2, "authenticated", "list"), ("session", 1, "public", ""), False),
        ((2, "authenticated", "view"), ("session", 1, "public", ""), False),
        ((2, "authenticated", "create"), ("session", 1, "public", ""), False),
        ((2, "authenticated", "edit"), ("session", 1, "public", ""), False),
        ((2, "authenticated", "delete"), ("session", 1, "public", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("session", 1, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("session", 1, "public", ""),
            False,
        ),
        # authenticated -> shared sessions from others (should all fail)
        (
            (2, "authenticated", "list"),
            ("session", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "view"),
            ("session", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "create"),
            ("session", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "edit"),
            ("session", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "delete"),
            ("session", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("session", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("session", 1, "shared", "2,5,6"),
            False,
        ),
        # authenticated -> shared from others but not shared to this
        # user (should all fail)
        ((2, "authenticated", "list"), ("session", 1, "shared", "5,6"), False),
        ((2, "authenticated", "view"), ("session", 1, "shared", "5,6"), False),
        (
            (2, "authenticated", "create"),
            ("session", 1, "shared", "5,6"),
            False,
        ),
        ((2, "authenticated", "edit"), ("session", 1, "shared", "5,6"), False),
        (
            (2, "authenticated", "delete"),
            ("session", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("session", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("session", 1, "shared", "5,6"),
            False,
        ),
        # authenticated -> private sessions from others (should all fail)
        ((2, "authenticated", "list"), ("session", 1, "private", ""), False),
        ((2, "authenticated", "view"), ("session", 1, "private", ""), False),
        ((2, "authenticated", "create"), ("session", 1, "private", ""), False),
        ((2, "authenticated", "edit"), ("session", 1, "private", ""), False),
        ((2, "authenticated", "delete"), ("session", 1, "private", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("session", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("session", 1, "private", ""),
            False,
        ),
    ],
)
def test_check_authenticated_access_to_sessions(access, target, expected):
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
        # authenticated -> self-owned private apikey
        ((2, "authenticated", "list"), ("apikey", 2, "private", ""), True),
        ((2, "authenticated", "view"), ("apikey", 2, "private", ""), True),
        ((2, "authenticated", "create"), ("apikey", 2, "private", ""), True),
        ((2, "authenticated", "edit"), ("apikey", 2, "private", ""), False),
        ((2, "authenticated", "delete"), ("apikey", 2, "private", ""), True),
        (
            (2, "authenticated", "change_visibility"),
            ("apikey", 2, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("apikey", 2, "private", ""),
            False,
        ),
        # authenticated -> self-owned shared apikey
        ((2, "authenticated", "list"), ("apikey", 2, "shared", ""), False),
        ((2, "authenticated", "view"), ("apikey", 2, "shared", ""), False),
        ((2, "authenticated", "create"), ("apikey", 2, "shared", ""), False),
        ((2, "authenticated", "edit"), ("apikey", 2, "shared", ""), False),
        ((2, "authenticated", "delete"), ("apikey", 2, "shared", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("apikey", 2, "shared", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("apikey", 2, "shared", ""),
            False,
        ),
        # authenticated -> self-owned public apikey (should all fail)
        ((2, "authenticated", "list"), ("apikey", 2, "public", ""), False),
        ((2, "authenticated", "view"), ("apikey", 2, "public", ""), False),
        ((2, "authenticated", "create"), ("apikey", 2, "public", ""), False),
        ((2, "authenticated", "edit"), ("apikey", 2, "public", ""), False),
        ((2, "authenticated", "delete"), ("apikey", 2, "public", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("apikey", 2, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("apikey", 2, "public", ""),
            False,
        ),
        # authenticated -> public apikey from others (should all fail)
        ((2, "authenticated", "list"), ("apikey", 1, "public", ""), False),
        ((2, "authenticated", "view"), ("apikey", 1, "public", ""), False),
        ((2, "authenticated", "create"), ("apikey", 1, "public", ""), False),
        ((2, "authenticated", "edit"), ("apikey", 1, "public", ""), False),
        ((2, "authenticated", "delete"), ("apikey", 1, "public", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("apikey", 1, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("apikey", 1, "public", ""),
            False,
        ),
        # authenticated -> shared apikey from others (should all fail)
        (
            (2, "authenticated", "list"),
            ("apikey", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "view"),
            ("apikey", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "create"),
            ("apikey", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "edit"),
            ("apikey", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "delete"),
            ("apikey", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("apikey", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("apikey", 1, "shared", "2,5,6"),
            False,
        ),
        # authenticated -> shared from others but not shared to this
        # user (should all fail)
        ((2, "authenticated", "list"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "authenticated", "view"), ("apikey", 1, "shared", "5,6"), False),
        (
            (2, "authenticated", "create"),
            ("apikey", 1, "shared", "5,6"),
            False,
        ),
        ((2, "authenticated", "edit"), ("apikey", 1, "shared", "5,6"), False),
        (
            (2, "authenticated", "delete"),
            ("apikey", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("apikey", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("apikey", 1, "shared", "5,6"),
            False,
        ),
        # authenticated -> private apikey from others (should all fail)
        ((2, "authenticated", "list"), ("apikey", 1, "private", ""), False),
        ((2, "authenticated", "view"), ("apikey", 1, "private", ""), False),
        ((2, "authenticated", "create"), ("apikey", 1, "private", ""), False),
        ((2, "authenticated", "edit"), ("apikey", 1, "private", ""), False),
        ((2, "authenticated", "delete"), ("apikey", 1, "private", ""), False),
        (
            (2, "authenticated", "change_visibility"),
            ("apikey", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("apikey", 1, "private", ""),
            False,
        ),
    ],
)
def test_check_authenticated_access_to_apikeys(access, target, expected):
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
        # authenticated -> self-owned private preferences
        ((2, "authenticated", "list"), ("preference", 2, "private", ""), True),
        ((2, "authenticated", "view"), ("preference", 2, "private", ""), True),
        (
            (2, "authenticated", "create"),
            ("preference", 2, "private", ""),
            False,
        ),
        ((2, "authenticated", "edit"), ("preference", 2, "private", ""), True),
        (
            (2, "authenticated", "delete"),
            ("preference", 2, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("preference", 2, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("preference", 2, "private", ""),
            False,
        ),
        # authenticated -> self-owned shared preferences
        ((2, "authenticated", "list"), ("preference", 2, "shared", ""), False),
        ((2, "authenticated", "view"), ("preference", 2, "shared", ""), False),
        (
            (2, "authenticated", "create"),
            ("preference", 2, "shared", ""),
            False,
        ),
        ((2, "authenticated", "edit"), ("preference", 2, "shared", ""), False),
        (
            (2, "authenticated", "delete"),
            ("preference", 2, "shared", ""),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("preference", 2, "shared", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("preference", 2, "shared", ""),
            False,
        ),
        # authenticated -> self-owned public preferences (should all fail)
        ((2, "authenticated", "list"), ("preference", 2, "public", ""), False),
        ((2, "authenticated", "view"), ("preference", 2, "public", ""), False),
        (
            (2, "authenticated", "create"),
            ("preference", 2, "public", ""),
            False,
        ),
        ((2, "authenticated", "edit"), ("preference", 2, "public", ""), False),
        (
            (2, "authenticated", "delete"),
            ("preference", 2, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("preference", 2, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("preference", 2, "public", ""),
            False,
        ),
        # authenticated -> public preferences from others (should all fail)
        ((2, "authenticated", "list"), ("preference", 1, "public", ""), False),
        ((2, "authenticated", "view"), ("preference", 1, "public", ""), False),
        (
            (2, "authenticated", "create"),
            ("preference", 1, "public", ""),
            False,
        ),
        ((2, "authenticated", "edit"), ("preference", 1, "public", ""), False),
        (
            (2, "authenticated", "delete"),
            ("preference", 1, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("preference", 1, "public", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("preference", 1, "public", ""),
            False,
        ),
        # authenticated -> shared preferences from others (should all fail)
        (
            (2, "authenticated", "list"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "view"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "create"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "edit"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "delete"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        # authenticated -> shared from others but not shared to this
        # user (should all fail)
        (
            (2, "authenticated", "list"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "view"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "create"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "edit"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "delete"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        # authenticated -> private preferences from others (should all fail)
        (
            (2, "authenticated", "list"),
            ("preference", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "view"),
            ("preference", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "create"),
            ("preference", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "edit"),
            ("preference", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "delete"),
            ("preference", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_visibility"),
            ("preference", 1, "private", ""),
            False,
        ),
        (
            (2, "authenticated", "change_owner"),
            ("preference", 1, "private", ""),
            False,
        ),
    ],
)
def test_check_authenticated_access_to_preferences(access, target, expected):
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
