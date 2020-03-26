'''test_auth_actions.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Sep 2018
License: MIT. See the LICENSE file for details.

This contains tests for the auth functions in authnzerver.actions.

'''

from .. import authdb, actions
import os.path
import os
from datetime import datetime, timedelta
import multiprocessing as mp


def get_test_authdb():
    '''This just makes a new test auth DB for each test function.

    '''

    authdb.create_sqlite_authdb('test-userlock.authdb.sqlite')
    authdb.initial_authdb_inserts('sqlite:///test-userlock.authdb.sqlite')


def test_user_lock():
    '''
    This tests if we can add session info to a session dict.

    '''

    try:
        os.remove('test-userlock.authdb.sqlite')
    except Exception:
        pass
    try:
        os.remove('test-userlock.authdb.sqlite-shm')
    except Exception:
        pass
    try:
        os.remove('test-userlock.authdb.sqlite-wal')
    except Exception:
        pass

    get_test_authdb()

    # create the user
    user_payload = {'full_name':'Test User',
                    'email':'testuser-userlock@test.org',
                    'password':'aROwQin9L8nNtPTEMLXd',
                    'pii_salt':'super-secret-salt',
                    'reqid':1}
    user_created = actions.create_new_user(
        user_payload,
        override_authdb_path='sqlite:///test-userlock.authdb.sqlite'
    )
    assert user_created['success'] is True
    assert user_created['user_email'] == 'testuser-userlock@test.org'
    assert ('User account created. Please verify your email address to log in.'
            in user_created['messages'])

    # create a new session token
    session_payload = {
        'user_id':2,
        'user_agent':'Mozzarella Killerwhale',
        'expires':datetime.utcnow()+timedelta(hours=1),
        'ip_address': '1.1.1.1',
        'extra_info_json':{'pref_datasets_always_private':True},
        'pii_salt':'super-secret-salt',
        'reqid':1
    }

    # check creation of session
    session_token1 = actions.auth_session_new(
        session_payload,
        override_authdb_path='sqlite:///test-userlock.authdb.sqlite'
    )
    assert session_token1['success'] is True
    assert session_token1['session_token'] is not None

    # verify our email
    emailverify = (
        actions.verify_user_email_address(
            {'email':user_payload['email'],
             'user_id': user_created['user_id'],
             'pii_salt':'super-secret-salt',
             'reqid':1},
            override_authdb_path='sqlite:///test-userlock.authdb.sqlite'
        )
    )

    assert emailverify['success'] is True
    assert emailverify['user_id'] == user_created['user_id']
    assert emailverify['is_active'] is True
    assert emailverify['user_role'] == 'authenticated'

    # now make a new session token
    session_payload = {
        'user_id':emailverify['user_id'],
        'user_agent':'Mozzarella Killerwhale',
        'expires':datetime.utcnow()+timedelta(hours=1),
        'ip_address': '1.1.1.1',
        'extra_info_json':{'pref_datasets_always_private':True},
        'pii_salt':'super-secret-salt',
        'reqid':1
    }

    # check creation of session
    session_token2 = actions.auth_session_new(
        session_payload,
        override_authdb_path='sqlite:///test-userlock.authdb.sqlite'
    )
    assert session_token2['success'] is True
    assert session_token2['session_token'] is not None

    #
    # 1. try to lock this user
    #

    user_locked = actions.internal_toggle_user_lock(
        {'target_userid': emailverify['user_id'],
         'action': 'lock',
         'pii_salt':'super-secret-salt',
         'reqid':1},
        override_authdb_path='sqlite:///test-userlock-authdb.sqlite',
        raiseonfail=True
    )

    assert user_locked['success'] is True
    assert user_locked['user_info']['user_role'] == 'locked'
    assert user_locked['user_info']['is_active'] is False

    # check if the session token for this logged in user still exists
    info_check = actions.auth_session_exists(
        {'session_token':session_token2['session_token'],
         'pii_salt':'super-secret-salt',
         'reqid':1},
        override_authdb_path='sqlite:///test-userlock.authdb.sqlite'
    )
    assert info_check['success'] is False

    # try to login as this user using another session
    session_payload = {
        'user_id':2,
        'user_agent':'Mozzarella Killerwhale',
        'expires':datetime.utcnow()+timedelta(hours=1),
        'ip_address': '1.1.1.1',
        'extra_info_json':{'pref_datasets_always_private':True},
        'pii_salt':'super-secret-salt',
        'reqid':1
    }

    # check creation of session
    session_token3 = actions.auth_session_new(
        session_payload,
        override_authdb_path='sqlite:///test-userlock.authdb.sqlite'
    )
    assert session_token3['success'] is True
    assert session_token3['session_token'] is not None

    # try logging in now
    login = actions.auth_user_login(
        {'session_token':session_token3['session_token'],
         'email': user_payload['email'],
         'password':user_payload['password'],
         'pii_salt':'super-secret-salt',
         'reqid':1},
        override_authdb_path='sqlite:///test-userlock.authdb.sqlite'
    )

    # this should fail
    assert login['success'] is False

    #
    # 2. unlock the user now
    #

    user_unlocked = actions.internal_toggle_user_lock(
        {'target_userid': emailverify['user_id'],
         'action': 'unlock',
         'pii_salt':'super-secret-salt',
         'reqid':1},
        override_authdb_path='sqlite:///test-userlock-authdb.sqlite',
        raiseonfail=True
    )
    assert user_unlocked['success'] is True
    assert user_unlocked['user_info']['user_role'] == 'authenticated'
    assert user_unlocked['user_info']['is_active'] is True

    # try to login
    session_payload = {
        'user_id':2,
        'user_agent':'Mozzarella Killerwhale',
        'expires':datetime.utcnow()+timedelta(hours=1),
        'ip_address': '1.1.1.1',
        'extra_info_json':{'pref_datasets_always_private':True},
        'pii_salt':'super-secret-salt',
        'reqid':1
    }

    # check creation of session
    session_token3 = actions.auth_session_new(
        session_payload,
        override_authdb_path='sqlite:///test-userlock.authdb.sqlite'
    )
    assert session_token3['success'] is True
    assert session_token3['session_token'] is not None

    # try logging in now with correct password
    login = actions.auth_user_login(
        {'session_token':session_token3['session_token'],
         'email': user_payload['email'],
         'password':user_payload['password'],
         'pii_salt':'super-secret-salt',
         'reqid':1},
        override_authdb_path='sqlite:///test-userlock.authdb.sqlite'
    )

    # this should succeed
    assert login['success'] is True

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
        os.remove('test-userlock.authdb.sqlite')
    except Exception:
        pass
    try:
        os.remove('test-userlock.authdb.sqlite-shm')
    except Exception:
        pass
    try:
        os.remove('test-userlock.authdb.sqlite-wal')
    except Exception:
        pass
