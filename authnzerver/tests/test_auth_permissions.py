'''test_auth_actions.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Sep 2018
License: MIT. See the LICENSE file for details.

This contains tests for the auth functions in authnzerver.actions.

'''

from .. import authdb, actions
import os.path
import os
import multiprocessing as mp


def get_test_authdb():
    '''This just makes a new test auth DB for each test function.

    '''

    authdb.create_sqlite_authdb('test-permcheck.authdb.sqlite')
    authdb.initial_authdb_inserts('sqlite:///test-permcheck.authdb.sqlite')


def test_role_permissions():
    '''
    This tests if we can check the permissions for a logged-in user.

    '''

    try:
        os.remove('test-permcheck.authdb.sqlite')
    except Exception:
        pass
    try:
        os.remove('test-permcheck.authdb.sqlite-shm')
    except Exception:
        pass
    try:
        os.remove('test-permcheck.authdb.sqlite-wal')
    except Exception:
        pass

    get_test_authdb()

    # create the user
    user_payload = {'full_name': 'Test User',
                    'email':'testuser-permcheck@test.org',
                    'password':'aROwQin9L8nNtPTEMLXd',
                    'pii_salt':'super-secret-salt',
                    'reqid':1}
    user_created = actions.create_new_user(
        user_payload,
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite'
    )
    assert user_created['success'] is True
    assert user_created['user_email'] == 'testuser-permcheck@test.org'
    assert ('User account created. Please verify your email address to log in.'
            in user_created['messages'])

    # verify our email
    emailverify = (
        actions.verify_user_email_address(
            {'email':user_payload['email'],
             'user_id': user_created['user_id'],
             'pii_salt':'super-secret-salt',
             'reqid':1},
            override_authdb_path='sqlite:///test-permcheck.authdb.sqlite'
        )
    )

    # make a non-verified user
    user_payload2 = {'full_name': 'Test User',
                     'email':'testuser-permcheck2@test.org',
                     'password':'aROwQin9L8nNtPTEMLXd',
                     'pii_salt':'super-secret-salt',
                     'reqid':1}
    user_created2 = actions.create_new_user(
        user_payload2,
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite'
    )
    assert user_created2['success'] is True
    assert user_created2['user_email'] == 'testuser-permcheck2@test.org'
    assert ('User account created. Please verify your email address to log in.'
            in user_created2['messages'])

    #
    # now run the permissions checks
    #

    # get the permissions JSON
    thisdir = os.path.dirname(__file__)
    permissions_json = os.path.abspath(
        os.path.join(thisdir, '..', 'default-permissions-model.json')
    )

    # 1. view a non-owned public object
    access_check = actions.check_user_access(
        {'user_id':emailverify['user_id'],
         'user_role':'authenticated',
         'action':'view',
         'target_name':'object',
         'target_owner':1,
         'target_visibility':'public',
         'target_sharedwith':'',
         'reqid':1,
         'pii_salt':'dummy-pii-salt'},
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite',
        override_permissions_json=permissions_json,
        raiseonfail=True,
    )
    assert access_check['success'] is True
    assert (
        "Access request check successful. Access granted: True." in
        access_check['messages']
    )

    # 2. delete a non-owned public object
    access_check = actions.check_user_access(
        {'user_id':emailverify['user_id'],
         'user_role':'authenticated',
         'action':'delete',
         'target_name':'object',
         'target_owner':1,
         'target_visibility':'public',
         'target_sharedwith':'',
         'reqid':1,
         'pii_salt':'dummy-pii-salt'},
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite',
        override_permissions_json=permissions_json,
        raiseonfail=True,
    )
    assert access_check['success'] is False
    assert (
        "Access request check successful. Access granted: False." in
        access_check['messages']
    )

    # 3. edit a self owned dataset
    access_check = actions.check_user_access(
        {'user_id':emailverify['user_id'],
         'user_role':'authenticated',
         'action':'edit',
         'target_name':'dataset',
         'target_owner':emailverify['user_id'],
         'target_visibility':'private',
         'target_sharedwith':'',
         'reqid':1,
         'pii_salt':'dummy-pii-salt'},
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite',
        override_permissions_json=permissions_json,
        raiseonfail=True,
    )
    assert access_check['success'] is True
    assert (
        "Access request check successful. Access granted: True." in
        access_check['messages']
    )

    # 3. as superuser, delete someone else's private dataset
    access_check = actions.check_user_access(
        {'user_id':1,
         'user_role':'superuser',
         'action':'delete',
         'target_name':'dataset',
         'target_owner':4,
         'target_visibility':'private',
         'target_sharedwith':'',
         'reqid':1,
         'pii_salt':'dummy-pii-salt'},
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite',
        override_permissions_json=permissions_json,
        raiseonfail=True,
    )
    assert access_check['success'] is True
    assert (
        "Access request check successful. Access granted: True." in
        access_check['messages']
    )

    # 4. as locked user, try to view a public collection
    access_check = actions.check_user_access(
        {'user_id': 3,
         'user_role':'locked',
         'action':'view',
         'target_name':'collection',
         'target_owner':1,
         'target_visibility':'public',
         'target_sharedwith':'',
         'reqid':1,
         'pii_salt':'dummy-pii-salt'},
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite',
        override_permissions_json=permissions_json,
        raiseonfail=True,
    )
    assert access_check['success'] is False
    assert (
        "Access request check successful. Access granted: False." in
        access_check['messages']
    )

    # 5. as an unknown user with superuser privileges, try to edit a private
    # dataset
    access_check = actions.check_user_access(
        {'user_id':10,
         'user_role':'superuser',
         'action':'edit',
         'target_name':'dataset',
         'target_owner':1,
         'target_visibility':'private',
         'target_sharedwith':'',
         'reqid':1,
         'pii_salt':'dummy-pii-salt'},
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite',
        override_permissions_json=permissions_json,
        raiseonfail=True,
    )
    assert access_check['success'] is False
    assert (
        "Access request check successful. Access granted: False." in
        access_check['messages']
    )

    # 6. as a known user but non-activated account, try to view a collection
    access_check = actions.check_user_access(
        {'user_id':5,
         'user_role':'authenticated',
         'action':'view',
         'target_name':'collection',
         'target_owner':1,
         'target_visibility':'public',
         'target_sharedwith':'',
         'reqid':1,
         'pii_salt':'dummy-pii-salt'},
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite',
        override_permissions_json=permissions_json,
        raiseonfail=True,
    )
    assert access_check['success'] is False
    assert (
        "Access request check successful. Access granted: False." in
        access_check['messages']
    )

    #
    # teardown
    #

    currproc = mp.current_process()
    if getattr(currproc, 'authdb_meta', None):
        del currproc.authdb_meta

    if getattr(currproc, 'connection', None):
        currproc.authdb_conn.close()
        del currproc.authdb_conn

    if getattr(currproc, 'authdb_engine', None):
        currproc.authdb_engine.dispose()
        del currproc.authdb_engine

    try:
        os.remove('test-permcheck.authdb.sqlite')
    except Exception:
        pass
    try:
        os.remove('test-permcheck.authdb.sqlite-shm')
    except Exception:
        pass
    try:
        os.remove('test-permcheck.authdb.sqlite-wal')
    except Exception:
        pass


def test_role_limits():
    '''
    This tests if we can check the permissions for a logged-in user.

    '''

    try:
        os.remove('test-permcheck.authdb.sqlite')
    except Exception:
        pass
    try:
        os.remove('test-permcheck.authdb.sqlite-shm')
    except Exception:
        pass
    try:
        os.remove('test-permcheck.authdb.sqlite-wal')
    except Exception:
        pass

    get_test_authdb()

    # create the user
    user_payload = {'full_name': 'Test User',
                    'email':'testuser-permcheck@test.org',
                    'password':'aROwQin9L8nNtPTEMLXd',
                    'pii_salt':'super-secret-salt',
                    'reqid':1}
    user_created = actions.create_new_user(
        user_payload,
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite'
    )
    assert user_created['success'] is True
    assert user_created['user_email'] == 'testuser-permcheck@test.org'
    assert ('User account created. Please verify your email address to log in.'
            in user_created['messages'])

    # verify our email
    emailverify = (
        actions.verify_user_email_address(
            {'email':user_payload['email'],
             'user_id': user_created['user_id'],
             'pii_salt':'super-secret-salt',
             'reqid':1},
            override_authdb_path='sqlite:///test-permcheck.authdb.sqlite'
        )
    )

    # make a non-verified user
    user_payload2 = {'full_name': 'Test User',
                     'email':'testuser-permcheck2@test.org',
                     'password':'aROwQin9L8nNtPTEMLXd',
                     'pii_salt':'super-secret-salt',
                     'reqid':1}
    user_created2 = actions.create_new_user(
        user_payload2,
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite'
    )
    assert user_created2['success'] is True
    assert user_created2['user_email'] == 'testuser-permcheck2@test.org'
    assert ('User account created. Please verify your email address to log in.'
            in user_created2['messages'])

    #
    # now run the limit checks
    #

    # get the permissions JSON
    thisdir = os.path.dirname(__file__)
    permissions_json = os.path.abspath(
        os.path.join(thisdir, '..', 'default-permissions-model.json')
    )

    # 1. superuser 10000 requests
    limit_check = actions.check_user_limit(
        {'user_id':1,
         'user_role':'superuser',
         'limit_name':'max_requests',
         'value_to_check':10000,
         'reqid':1,
         'pii_salt':'dummy-pii-salt'},
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite',
        override_permissions_json=permissions_json,
        raiseonfail=True,
    )
    assert limit_check['success'] is True
    assert (
        "Limit check successful. Limit check passed: True." in
        limit_check['messages']
    )

    # 2. superuser 10000000 requests/minute
    # (this would probably melt the Ethernet card before it hits our server)
    limit_check = actions.check_user_limit(
        {'user_id':1,
         'user_role':'superuser',
         'limit_name':'max_requests_per_minute',
         'value_to_check':10000000,
         'reqid':1,
         'pii_salt':'dummy-pii-salt'},
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite',
        override_permissions_json=permissions_json,
        raiseonfail=True,
    )
    assert limit_check['success'] is False
    assert (
        "Limit check successful. Limit check passed: False." in
        limit_check['messages']
    )

    # 3. authenticated 10000 requests
    limit_check = actions.check_user_limit(
        {'user_id':emailverify['user_id'],
         'user_role':'authenticated',
         'limit_name':'max_requests',
         'value_to_check':10000,
         'reqid':1,
         'pii_salt':'dummy-pii-salt'},
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite',
        override_permissions_json=permissions_json,
        raiseonfail=True,
    )
    assert limit_check['success'] is True
    assert (
        "Limit check successful. Limit check passed: True." in
        limit_check['messages']
    )

    # 4. authenticated 10000000 requests/minute
    # (this would probably melt the Ethernet card before it hits our server)
    limit_check = actions.check_user_limit(
        {'user_id':emailverify['user_id'],
         'user_role':'authenticated',
         'limit_name':'max_requests_per_minute',
         'value_to_check':10000000,
         'reqid':1,
         'pii_salt':'dummy-pii-salt'},
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite',
        override_permissions_json=permissions_json,
        raiseonfail=True,
    )
    assert limit_check['success'] is False
    assert (
        "Limit check successful. Limit check passed: False." in
        limit_check['messages']
    )

    # 5. invalid superuser 1000 requests
    limit_check = actions.check_user_limit(
        {'user_id':emailverify['user_id'],
         'user_role':'superuser',
         'limit_name':'max_requests',
         'value_to_check':1000,
         'reqid':1,
         'pii_salt':'dummy-pii-salt'},
        override_authdb_path='sqlite:///test-permcheck.authdb.sqlite',
        override_permissions_json=permissions_json,
        raiseonfail=True,
    )
    assert limit_check['success'] is False
    assert (
        "Limit check successful. Limit check passed: False." in
        limit_check['messages']
    )

    #
    # teardown
    #

    currproc = mp.current_process()
    if getattr(currproc, 'authdb_meta', None):
        del currproc.authdb_meta

    if getattr(currproc, 'connection', None):
        currproc.authdb_conn.close()
        del currproc.authdb_conn

    if getattr(currproc, 'authdb_engine', None):
        currproc.authdb_engine.dispose()
        del currproc.authdb_engine

    try:
        os.remove('test-permcheck.authdb.sqlite')
    except Exception:
        pass
    try:
        os.remove('test-permcheck.authdb.sqlite-shm')
    except Exception:
        pass
    try:
        os.remove('test-permcheck.authdb.sqlite-wal')
    except Exception:
        pass
