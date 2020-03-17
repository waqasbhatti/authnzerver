#!/usr/bin/env python
# -*- coding: utf-8 -*-
# test_permissions_limits.py - Waqas Bhatti (wbhatti@astro.princeton.edu) -
# Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''This tests role limits.

'''

import os.path
import pytest
from authnzerver import permissions


##################
## LIMIT CHECKS ##
##################

@pytest.mark.parametrize(
    "role,limit_name,value_to_check,expected", [
        # superuser
        ('superuser','max_requests',100,True),
        ('superuser','max_requests_per_minute',100, True),
        ('superuser','max_requests',100000000, False),
        ('superuser','max_requests_per_minute',10000000, False),
        ('superuser','nonexistent_limit_name',10000000, True),
        # staff
        ('staff','max_requests',100,True),
        ('staff','max_requests_per_minute',100, True),
        ('staff','max_requests',100000000, False),
        ('staff','max_requests_per_minute',10000000, False),
        ('staff','nonexistent_limit_name',10000000, True),
        # authenticated
        ('authenticated','max_requests',100,True),
        ('authenticated','max_requests_per_minute',100, True),
        ('authenticated','max_requests',100000000, False),
        ('authenticated','max_requests_per_minute',10000000, False),
        ('authenticated','nonexistent_limit_name',10000000, True),
        # anonymous
        ('anonymous','max_requests',100,True),
        ('anonymous','max_requests_per_minute',100, True),
        ('anonymous','max_requests',100000000, False),
        ('anonymous','max_requests_per_minute',10000000, False),
        ('anonymous','nonexistent_limit_name',10000000, True),
        # locked
        ('locked','max_requests',100,False),
        ('locked','max_requests_per_minute',100, False),
        ('locked','max_requests',100000000, False),
        ('locked','max_requests_per_minute',10000000, False),
        ('locked','nonexistent_limit_name',10000000, True),
    ]
)
def test_role_limits(role, limit_name, value_to_check, expected):
    '''
    This checks role limits for the default permissions policy.

    '''

    # load the default permissions model
    modpath = os.path.abspath(os.path.dirname(__file__))
    permpath = os.path.abspath(
        os.path.join(modpath,'..','default-permissions-model.json')
    )

    assert permissions.load_policy_and_check_limits(
        permpath,
        role,
        limit_name,
        value_to_check
    ) is expected
