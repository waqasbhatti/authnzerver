# -*- coding: utf-8 -*-
# test_permissions_superuser.py - Waqas Bhatti (wbhatti@astro.princeton.edu) -
# Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""This tests permissions for superusers.

"""

import os.path
import pytest
from authnzerver import permissions


######################
## SUPERUSER ACCESS ##
######################


@pytest.mark.parametrize(
    "access,target,expected",
    [
        # superuser -> self-owned private collection
        ((2, "superuser", "list"), ("collection", 2, "private", ""), True),
        ((2, "superuser", "view"), ("collection", 2, "private", ""), True),
        ((2, "superuser", "create"), ("collection", 2, "private", ""), True),
        ((2, "superuser", "edit"), ("collection", 2, "private", ""), True),
        ((2, "superuser", "delete"), ("collection", 2, "private", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("collection", 2, "private", ""),
            True,
        ),
        (
            (2, "superuser", "change_owner"),
            ("collection", 2, "private", ""),
            True,
        ),
        # superuser -> self-owned shared collection
        ((2, "superuser", "list"), ("collection", 2, "shared", ""), True),
        ((2, "superuser", "view"), ("collection", 2, "shared", ""), True),
        ((2, "superuser", "create"), ("collection", 2, "shared", ""), True),
        ((2, "superuser", "edit"), ("collection", 2, "shared", ""), True),
        ((2, "superuser", "delete"), ("collection", 2, "shared", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("collection", 2, "shared", ""),
            True,
        ),
        (
            (2, "superuser", "change_owner"),
            ("collection", 2, "shared", ""),
            True,
        ),
        # superuser -> self-owned public collection
        ((2, "superuser", "list"), ("collection", 2, "public", ""), True),
        ((2, "superuser", "view"), ("collection", 2, "public", ""), True),
        ((2, "superuser", "create"), ("collection", 2, "public", ""), True),
        ((2, "superuser", "edit"), ("collection", 2, "public", ""), True),
        ((2, "superuser", "delete"), ("collection", 2, "public", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("collection", 2, "public", ""),
            True,
        ),
        (
            (2, "superuser", "change_owner"),
            ("collection", 2, "public", ""),
            True,
        ),
        # superuser -> public collection from others
        ((2, "superuser", "list"), ("collection", 1, "public", ""), True),
        ((2, "superuser", "view"), ("collection", 1, "public", ""), True),
        ((2, "superuser", "create"), ("collection", 1, "public", ""), True),
        ((2, "superuser", "edit"), ("collection", 1, "public", ""), True),
        ((2, "superuser", "delete"), ("collection", 1, "public", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("collection", 1, "public", ""),
            True,
        ),
        (
            (2, "superuser", "change_owner"),
            ("collection", 1, "public", ""),
            True,
        ),
        # superuser -> shared collection from others
        ((2, "superuser", "list"), ("collection", 1, "shared", "2,5,6"), True),
        ((2, "superuser", "view"), ("collection", 1, "shared", "2,5,6"), True),
        (
            (2, "superuser", "create"),
            ("collection", 1, "shared", "2,5,6"),
            True,
        ),
        ((2, "superuser", "edit"), ("collection", 1, "shared", "2,5,6"), True),
        (
            (2, "superuser", "delete"),
            ("collection", 1, "shared", "2,5,6"),
            True,
        ),
        (
            (2, "superuser", "change_visibility"),
            ("collection", 1, "shared", "2,5,6"),
            True,
        ),
        (
            (2, "superuser", "change_owner"),
            ("collection", 1, "shared", "2,5,6"),
            True,
        ),
        # superuser -> shared from others but not shared to this
        # user
        ((2, "superuser", "list"), ("collection", 1, "shared", "5,6"), True),
        ((2, "superuser", "view"), ("collection", 1, "shared", "5,6"), True),
        ((2, "superuser", "create"), ("collection", 1, "shared", "5,6"), True),
        ((2, "superuser", "edit"), ("collection", 1, "shared", "5,6"), True),
        ((2, "superuser", "delete"), ("collection", 1, "shared", "5,6"), True),
        (
            (2, "superuser", "change_visibility"),
            ("collection", 1, "shared", "5,6"),
            True,
        ),
        (
            (2, "superuser", "change_owner"),
            ("collection", 1, "shared", "5,6"),
            True,
        ),
        # superuser -> private collection from others
        ((2, "superuser", "list"), ("collection", 1, "private", ""), True),
        ((2, "superuser", "view"), ("collection", 1, "private", ""), True),
        ((2, "superuser", "create"), ("collection", 1, "private", ""), True),
        ((2, "superuser", "edit"), ("collection", 1, "private", ""), True),
        ((2, "superuser", "delete"), ("collection", 1, "private", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("collection", 1, "private", ""),
            True,
        ),
        (
            (2, "superuser", "change_owner"),
            ("collection", 1, "private", ""),
            True,
        ),
    ],
)
def test_superuser_access_to_collection(access, target, expected):
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
        # superuser -> self-owned private dataset
        ((2, "superuser", "list"), ("dataset", 2, "private", ""), True),
        ((2, "superuser", "view"), ("dataset", 2, "private", ""), True),
        ((2, "superuser", "create"), ("dataset", 2, "private", ""), True),
        ((2, "superuser", "edit"), ("dataset", 2, "private", ""), True),
        ((2, "superuser", "delete"), ("dataset", 2, "private", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("dataset", 2, "private", ""),
            True,
        ),
        (
            (2, "superuser", "change_owner"),
            ("dataset", 2, "private", ""),
            True,
        ),
        # superuser -> self-owned shared dataset
        ((2, "superuser", "list"), ("dataset", 2, "shared", ""), True),
        ((2, "superuser", "view"), ("dataset", 2, "shared", ""), True),
        ((2, "superuser", "create"), ("dataset", 2, "shared", ""), True),
        ((2, "superuser", "edit"), ("dataset", 2, "shared", ""), True),
        ((2, "superuser", "delete"), ("dataset", 2, "shared", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("dataset", 2, "shared", ""),
            True,
        ),
        ((2, "superuser", "change_owner"), ("dataset", 2, "shared", ""), True),
        # superuser -> self-owned public dataset
        ((2, "superuser", "list"), ("dataset", 2, "public", ""), True),
        ((2, "superuser", "view"), ("dataset", 2, "public", ""), True),
        ((2, "superuser", "create"), ("dataset", 2, "public", ""), True),
        ((2, "superuser", "edit"), ("dataset", 2, "public", ""), True),
        ((2, "superuser", "delete"), ("dataset", 2, "public", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("dataset", 2, "public", ""),
            True,
        ),
        ((2, "superuser", "change_owner"), ("dataset", 2, "public", ""), True),
        # superuser -> public dataset from others
        ((2, "superuser", "list"), ("dataset", 1, "public", ""), True),
        ((2, "superuser", "view"), ("dataset", 1, "public", ""), True),
        ((2, "superuser", "create"), ("dataset", 1, "public", ""), True),
        ((2, "superuser", "edit"), ("dataset", 1, "public", ""), True),
        ((2, "superuser", "delete"), ("dataset", 1, "public", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("dataset", 1, "public", ""),
            True,
        ),
        ((2, "superuser", "change_owner"), ("dataset", 1, "public", ""), True),
        # superuser -> shared dataset from others
        ((2, "superuser", "list"), ("dataset", 1, "shared", "2,5,6"), True),
        ((2, "superuser", "view"), ("dataset", 1, "shared", "2,5,6"), True),
        ((2, "superuser", "create"), ("dataset", 1, "shared", "2,5,6"), True),
        ((2, "superuser", "edit"), ("dataset", 1, "shared", "2,5,6"), True),
        ((2, "superuser", "delete"), ("dataset", 1, "shared", "2,5,6"), True),
        (
            (2, "superuser", "change_visibility"),
            ("dataset", 1, "shared", "2,5,6"),
            True,
        ),
        (
            (2, "superuser", "change_owner"),
            ("dataset", 1, "shared", "2,5,6"),
            True,
        ),
        # superuser -> shared from others but not shared to this
        # user
        ((2, "superuser", "list"), ("dataset", 1, "shared", "5,6"), True),
        ((2, "superuser", "view"), ("dataset", 1, "shared", "5,6"), True),
        ((2, "superuser", "create"), ("dataset", 1, "shared", "5,6"), True),
        ((2, "superuser", "edit"), ("dataset", 1, "shared", "5,6"), True),
        ((2, "superuser", "delete"), ("dataset", 1, "shared", "5,6"), True),
        (
            (2, "superuser", "change_visibility"),
            ("dataset", 1, "shared", "5,6"),
            True,
        ),
        (
            (2, "superuser", "change_owner"),
            ("dataset", 1, "shared", "5,6"),
            True,
        ),
        # superuser -> private dataset from others
        ((2, "superuser", "list"), ("dataset", 1, "private", ""), True),
        ((2, "superuser", "view"), ("dataset", 1, "private", ""), True),
        ((2, "superuser", "create"), ("dataset", 1, "private", ""), True),
        ((2, "superuser", "edit"), ("dataset", 1, "private", ""), True),
        ((2, "superuser", "delete"), ("dataset", 1, "private", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("dataset", 1, "private", ""),
            True,
        ),
        (
            (2, "superuser", "change_owner"),
            ("dataset", 1, "private", ""),
            True,
        ),
    ],
)
def test_superuser_access_to_dataset(access, target, expected):
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
        # superuser -> self-owned private object
        ((2, "superuser", "list"), ("object", 2, "private", ""), True),
        ((2, "superuser", "view"), ("object", 2, "private", ""), True),
        ((2, "superuser", "create"), ("object", 2, "private", ""), True),
        ((2, "superuser", "edit"), ("object", 2, "private", ""), True),
        ((2, "superuser", "delete"), ("object", 2, "private", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("object", 2, "private", ""),
            True,
        ),
        ((2, "superuser", "change_owner"), ("object", 2, "private", ""), True),
        # superuser -> self-owned shared object
        ((2, "superuser", "list"), ("object", 2, "shared", ""), True),
        ((2, "superuser", "view"), ("object", 2, "shared", ""), True),
        ((2, "superuser", "create"), ("object", 2, "shared", ""), True),
        ((2, "superuser", "edit"), ("object", 2, "shared", ""), True),
        ((2, "superuser", "delete"), ("object", 2, "shared", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("object", 2, "shared", ""),
            True,
        ),
        ((2, "superuser", "change_owner"), ("object", 2, "shared", ""), True),
        # superuser -> self-owned public object
        ((2, "superuser", "list"), ("object", 2, "public", ""), True),
        ((2, "superuser", "view"), ("object", 2, "public", ""), True),
        ((2, "superuser", "create"), ("object", 2, "public", ""), True),
        ((2, "superuser", "edit"), ("object", 2, "public", ""), True),
        ((2, "superuser", "delete"), ("object", 2, "public", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("object", 2, "public", ""),
            True,
        ),
        ((2, "superuser", "change_owner"), ("object", 2, "public", ""), True),
        # superuser -> public object from others (list, view OK)
        ((2, "superuser", "list"), ("object", 1, "public", ""), True),
        ((2, "superuser", "view"), ("object", 1, "public", ""), True),
        ((2, "superuser", "create"), ("object", 1, "public", ""), True),
        ((2, "superuser", "edit"), ("object", 1, "public", ""), True),
        ((2, "superuser", "delete"), ("object", 1, "public", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("object", 1, "public", ""),
            True,
        ),
        ((2, "superuser", "change_owner"), ("object", 1, "public", ""), True),
        # superuser -> shared object from others
        ((2, "superuser", "list"), ("object", 1, "shared", "2,5,6"), True),
        ((2, "superuser", "view"), ("object", 1, "shared", "2,5,6"), True),
        ((2, "superuser", "create"), ("object", 1, "shared", "2,5,6"), True),
        ((2, "superuser", "edit"), ("object", 1, "shared", "2,5,6"), True),
        ((2, "superuser", "delete"), ("object", 1, "shared", "2,5,6"), True),
        (
            (2, "superuser", "change_visibility"),
            ("object", 1, "shared", "2,5,6"),
            True,
        ),
        (
            (2, "superuser", "change_owner"),
            ("object", 1, "shared", "2,5,6"),
            True,
        ),
        # superuser -> shared from others but not shared to this
        # user
        ((2, "superuser", "list"), ("object", 1, "shared", "5,6"), True),
        ((2, "superuser", "view"), ("object", 1, "shared", "5,6"), True),
        ((2, "superuser", "create"), ("object", 1, "shared", "5,6"), True),
        ((2, "superuser", "edit"), ("object", 1, "shared", "5,6"), True),
        ((2, "superuser", "delete"), ("object", 1, "shared", "5,6"), True),
        (
            (2, "superuser", "change_visibility"),
            ("object", 1, "shared", "5,6"),
            True,
        ),
        (
            (2, "superuser", "change_owner"),
            ("object", 1, "shared", "5,6"),
            True,
        ),
        # superuser -> private object from others
        ((2, "superuser", "list"), ("object", 1, "private", ""), True),
        ((2, "superuser", "view"), ("object", 1, "private", ""), True),
        ((2, "superuser", "create"), ("object", 1, "private", ""), True),
        ((2, "superuser", "edit"), ("object", 1, "private", ""), True),
        ((2, "superuser", "delete"), ("object", 1, "private", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("object", 1, "private", ""),
            True,
        ),
        ((2, "superuser", "change_owner"), ("object", 1, "private", ""), True),
    ],
)
def test_superuser_access_to_object(access, target, expected):
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
        # superuser -> self-owned private users
        ((2, "superuser", "list"), ("user", 2, "private", ""), False),
        ((2, "superuser", "view"), ("user", 2, "private", ""), False),
        ((2, "superuser", "create"), ("user", 2, "private", ""), False),
        ((2, "superuser", "edit"), ("user", 2, "private", ""), False),
        ((2, "superuser", "delete"), ("user", 2, "private", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("user", 2, "private", ""),
            False,
        ),
        ((2, "superuser", "change_owner"), ("user", 2, "private", ""), False),
        # superuser -> self-owned shared users
        ((2, "superuser", "list"), ("user", 2, "shared", ""), False),
        ((2, "superuser", "view"), ("user", 2, "shared", ""), False),
        ((2, "superuser", "create"), ("user", 2, "shared", ""), False),
        ((2, "superuser", "edit"), ("user", 2, "shared", ""), False),
        ((2, "superuser", "delete"), ("user", 2, "shared", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("user", 2, "shared", ""),
            False,
        ),
        ((2, "superuser", "change_owner"), ("user", 2, "shared", ""), False),
        # superuser -> self-owned public users
        ((2, "superuser", "list"), ("user", 2, "public", ""), False),
        ((2, "superuser", "view"), ("user", 2, "public", ""), False),
        ((2, "superuser", "create"), ("user", 2, "public", ""), False),
        ((2, "superuser", "edit"), ("user", 2, "public", ""), False),
        ((2, "superuser", "delete"), ("user", 2, "public", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("user", 2, "public", ""),
            False,
        ),
        ((2, "superuser", "change_owner"), ("user", 2, "public", ""), False),
        # superuser -> public users from others
        ((2, "superuser", "list"), ("user", 1, "public", ""), False),
        ((2, "superuser", "view"), ("user", 1, "public", ""), False),
        ((2, "superuser", "create"), ("user", 1, "public", ""), False),
        ((2, "superuser", "edit"), ("user", 1, "public", ""), False),
        ((2, "superuser", "delete"), ("user", 1, "public", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("user", 1, "public", ""),
            False,
        ),
        ((2, "superuser", "change_owner"), ("user", 1, "public", ""), False),
        # superuser -> shared users from others
        ((2, "superuser", "list"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "superuser", "view"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "superuser", "create"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "superuser", "edit"), ("user", 1, "shared", "2,5,6"), False),
        ((2, "superuser", "delete"), ("user", 1, "shared", "2,5,6"), False),
        (
            (2, "superuser", "change_visibility"),
            ("user", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("user", 1, "shared", "2,5,6"),
            False,
        ),
        # superuser -> shared from others but not shared to this
        # user
        ((2, "superuser", "list"), ("user", 1, "shared", "5,6"), False),
        ((2, "superuser", "view"), ("user", 1, "shared", "5,6"), False),
        ((2, "superuser", "create"), ("user", 1, "shared", "5,6"), False),
        ((2, "superuser", "edit"), ("user", 1, "shared", "5,6"), False),
        ((2, "superuser", "delete"), ("user", 1, "shared", "5,6"), False),
        (
            (2, "superuser", "change_visibility"),
            ("user", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("user", 1, "shared", "5,6"),
            False,
        ),
        # superuser -> private users from others
        ((2, "superuser", "list"), ("user", 1, "private", ""), True),
        ((2, "superuser", "view"), ("user", 1, "private", ""), True),
        ((2, "superuser", "create"), ("user", 1, "private", ""), True),
        ((2, "superuser", "edit"), ("user", 1, "private", ""), True),
        ((2, "superuser", "delete"), ("user", 1, "private", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("user", 1, "private", ""),
            False,
        ),
        ((2, "superuser", "change_owner"), ("user", 1, "private", ""), False),
    ],
)
def test_superuser_access_to_users(access, target, expected):
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
        # superuser -> self-owned private sessions
        ((2, "superuser", "list"), ("session", 2, "private", ""), False),
        ((2, "superuser", "view"), ("session", 2, "private", ""), False),
        ((2, "superuser", "create"), ("session", 2, "private", ""), False),
        ((2, "superuser", "edit"), ("session", 2, "private", ""), False),
        ((2, "superuser", "delete"), ("session", 2, "private", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("session", 2, "private", ""),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("session", 2, "private", ""),
            False,
        ),
        # superuser -> self-owned shared sessions
        ((2, "superuser", "list"), ("session", 2, "shared", ""), False),
        ((2, "superuser", "view"), ("session", 2, "shared", ""), False),
        ((2, "superuser", "create"), ("session", 2, "shared", ""), False),
        ((2, "superuser", "edit"), ("session", 2, "shared", ""), False),
        ((2, "superuser", "delete"), ("session", 2, "shared", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("session", 2, "shared", ""),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("session", 2, "shared", ""),
            False,
        ),
        # superuser -> self-owned public sessions
        ((2, "superuser", "list"), ("session", 2, "public", ""), False),
        ((2, "superuser", "view"), ("session", 2, "public", ""), False),
        ((2, "superuser", "create"), ("session", 2, "public", ""), False),
        ((2, "superuser", "edit"), ("session", 2, "public", ""), False),
        ((2, "superuser", "delete"), ("session", 2, "public", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("session", 2, "public", ""),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("session", 2, "public", ""),
            False,
        ),
        # superuser -> public sessions from others
        ((2, "superuser", "list"), ("session", 1, "public", ""), False),
        ((2, "superuser", "view"), ("session", 1, "public", ""), False),
        ((2, "superuser", "create"), ("session", 1, "public", ""), False),
        ((2, "superuser", "edit"), ("session", 1, "public", ""), False),
        ((2, "superuser", "delete"), ("session", 1, "public", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("session", 1, "public", ""),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("session", 1, "public", ""),
            False,
        ),
        # superuser -> shared sessions from others
        ((2, "superuser", "list"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "superuser", "view"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "superuser", "create"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "superuser", "edit"), ("session", 1, "shared", "2,5,6"), False),
        ((2, "superuser", "delete"), ("session", 1, "shared", "2,5,6"), False),
        (
            (2, "superuser", "change_visibility"),
            ("session", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("session", 1, "shared", "2,5,6"),
            False,
        ),
        # superuser -> shared from others but not shared to this
        # user
        ((2, "superuser", "list"), ("session", 1, "shared", "5,6"), False),
        ((2, "superuser", "view"), ("session", 1, "shared", "5,6"), False),
        ((2, "superuser", "create"), ("session", 1, "shared", "5,6"), False),
        ((2, "superuser", "edit"), ("session", 1, "shared", "5,6"), False),
        ((2, "superuser", "delete"), ("session", 1, "shared", "5,6"), False),
        (
            (2, "superuser", "change_visibility"),
            ("session", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("session", 1, "shared", "5,6"),
            False,
        ),
        # superuser -> private sessions from others
        ((2, "superuser", "list"), ("session", 1, "private", ""), True),
        ((2, "superuser", "view"), ("session", 1, "private", ""), True),
        ((2, "superuser", "create"), ("session", 1, "private", ""), False),
        ((2, "superuser", "edit"), ("session", 1, "private", ""), False),
        ((2, "superuser", "delete"), ("session", 1, "private", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("session", 1, "private", ""),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("session", 1, "private", ""),
            False,
        ),
    ],
)
def test_superuser_access_to_sessions(access, target, expected):
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
        # superuser -> self-owned private apikeys
        ((2, "superuser", "list"), ("apikey", 2, "private", ""), True),
        ((2, "superuser", "view"), ("apikey", 2, "private", ""), True),
        ((2, "superuser", "create"), ("apikey", 2, "private", ""), True),
        ((2, "superuser", "edit"), ("apikey", 2, "private", ""), False),
        ((2, "superuser", "delete"), ("apikey", 2, "private", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("apikey", 2, "private", ""),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("apikey", 2, "private", ""),
            False,
        ),
        # superuser -> self-owned shared apikeys
        ((2, "superuser", "list"), ("apikey", 2, "shared", ""), False),
        ((2, "superuser", "view"), ("apikey", 2, "shared", ""), False),
        ((2, "superuser", "create"), ("apikey", 2, "shared", ""), False),
        ((2, "superuser", "edit"), ("apikey", 2, "shared", ""), False),
        ((2, "superuser", "delete"), ("apikey", 2, "shared", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("apikey", 2, "shared", ""),
            False,
        ),
        ((2, "superuser", "change_owner"), ("apikey", 2, "shared", ""), False),
        # superuser -> self-owned public apikeys
        ((2, "superuser", "list"), ("apikey", 2, "public", ""), False),
        ((2, "superuser", "view"), ("apikey", 2, "public", ""), False),
        ((2, "superuser", "create"), ("apikey", 2, "public", ""), False),
        ((2, "superuser", "edit"), ("apikey", 2, "public", ""), False),
        ((2, "superuser", "delete"), ("apikey", 2, "public", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("apikey", 2, "public", ""),
            False,
        ),
        ((2, "superuser", "change_owner"), ("apikey", 2, "public", ""), False),
        # superuser -> public apikeys from others
        ((2, "superuser", "list"), ("apikey", 1, "public", ""), False),
        ((2, "superuser", "view"), ("apikey", 1, "public", ""), False),
        ((2, "superuser", "create"), ("apikey", 1, "public", ""), False),
        ((2, "superuser", "edit"), ("apikey", 1, "public", ""), False),
        ((2, "superuser", "delete"), ("apikey", 1, "public", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("apikey", 1, "public", ""),
            False,
        ),
        ((2, "superuser", "change_owner"), ("apikey", 1, "public", ""), False),
        # superuser -> shared apikeys from others
        ((2, "superuser", "list"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "superuser", "view"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "superuser", "create"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "superuser", "edit"), ("apikey", 1, "shared", "2,5,6"), False),
        ((2, "superuser", "delete"), ("apikey", 1, "shared", "2,5,6"), False),
        (
            (2, "superuser", "change_visibility"),
            ("apikey", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("apikey", 1, "shared", "2,5,6"),
            False,
        ),
        # superuser -> shared from others but not shared to this
        # user
        ((2, "superuser", "list"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "superuser", "view"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "superuser", "create"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "superuser", "edit"), ("apikey", 1, "shared", "5,6"), False),
        ((2, "superuser", "delete"), ("apikey", 1, "shared", "5,6"), False),
        (
            (2, "superuser", "change_visibility"),
            ("apikey", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("apikey", 1, "shared", "5,6"),
            False,
        ),
        # superuser -> private apikeys from others
        ((2, "superuser", "list"), ("apikey", 1, "private", ""), True),
        ((2, "superuser", "view"), ("apikey", 1, "private", ""), True),
        ((2, "superuser", "create"), ("apikey", 1, "private", ""), True),
        ((2, "superuser", "edit"), ("apikey", 1, "private", ""), False),
        ((2, "superuser", "delete"), ("apikey", 1, "private", ""), True),
        (
            (2, "superuser", "change_visibility"),
            ("apikey", 1, "private", ""),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("apikey", 1, "private", ""),
            False,
        ),
    ],
)
def test_superuser_access_to_apikeys(access, target, expected):
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
        # superuser -> self-owned private preferences
        ((2, "superuser", "list"), ("preference", 2, "private", ""), True),
        ((2, "superuser", "view"), ("preference", 2, "private", ""), True),
        ((2, "superuser", "create"), ("preference", 2, "private", ""), False),
        ((2, "superuser", "edit"), ("preference", 2, "private", ""), True),
        ((2, "superuser", "delete"), ("preference", 2, "private", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("preference", 2, "private", ""),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("preference", 2, "private", ""),
            False,
        ),
        # superuser -> self-owned shared preferences
        ((2, "superuser", "list"), ("preference", 2, "shared", ""), False),
        ((2, "superuser", "view"), ("preference", 2, "shared", ""), False),
        ((2, "superuser", "create"), ("preference", 2, "shared", ""), False),
        ((2, "superuser", "edit"), ("preference", 2, "shared", ""), False),
        ((2, "superuser", "delete"), ("preference", 2, "shared", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("preference", 2, "shared", ""),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("preference", 2, "shared", ""),
            False,
        ),
        # superuser -> self-owned public preferences
        ((2, "superuser", "list"), ("preference", 2, "public", ""), False),
        ((2, "superuser", "view"), ("preference", 2, "public", ""), False),
        ((2, "superuser", "create"), ("preference", 2, "public", ""), False),
        ((2, "superuser", "edit"), ("preference", 2, "public", ""), False),
        ((2, "superuser", "delete"), ("preference", 2, "public", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("preference", 2, "public", ""),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("preference", 2, "public", ""),
            False,
        ),
        # superuser -> public preferences from others
        ((2, "superuser", "list"), ("preference", 1, "public", ""), False),
        ((2, "superuser", "view"), ("preference", 1, "public", ""), False),
        ((2, "superuser", "create"), ("preference", 1, "public", ""), False),
        ((2, "superuser", "edit"), ("preference", 1, "public", ""), False),
        ((2, "superuser", "delete"), ("preference", 1, "public", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("preference", 1, "public", ""),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("preference", 1, "public", ""),
            False,
        ),
        # superuser -> shared preferences from others
        (
            (2, "superuser", "list"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "superuser", "view"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "superuser", "create"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "superuser", "edit"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "superuser", "delete"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "superuser", "change_visibility"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("preference", 1, "shared", "2,5,6"),
            False,
        ),
        # superuser -> shared from others but not shared to this
        # user
        ((2, "superuser", "list"), ("preference", 1, "shared", "5,6"), False),
        ((2, "superuser", "view"), ("preference", 1, "shared", "5,6"), False),
        (
            (2, "superuser", "create"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        ((2, "superuser", "edit"), ("preference", 1, "shared", "5,6"), False),
        (
            (2, "superuser", "delete"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "superuser", "change_visibility"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("preference", 1, "shared", "5,6"),
            False,
        ),
        # superuser -> private preferences from others
        ((2, "superuser", "list"), ("preference", 1, "private", ""), True),
        ((2, "superuser", "view"), ("preference", 1, "private", ""), True),
        ((2, "superuser", "create"), ("preference", 1, "private", ""), False),
        ((2, "superuser", "edit"), ("preference", 1, "private", ""), True),
        ((2, "superuser", "delete"), ("preference", 1, "private", ""), False),
        (
            (2, "superuser", "change_visibility"),
            ("preference", 1, "private", ""),
            False,
        ),
        (
            (2, "superuser", "change_owner"),
            ("preference", 1, "private", ""),
            False,
        ),
    ],
)
def test_superuser_access_to_preferences(access, target, expected):
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
