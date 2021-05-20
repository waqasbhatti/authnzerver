'''test_internal_user_edit.py -
   Waqas Bhatti (wbhatti@astro.princeton.edu) - Sep 2018
License: MIT. See the LICENSE file for details.

This contains a test for actions.internal_user_edit().

'''

from .. import authdb, actions
import os.path
import os
import multiprocessing as mp
from .test_support import get_public_suffix_list


def get_test_authdb():
    '''This just makes a new test auth DB for each test function.

    '''

    authdb.create_sqlite_authdb('test-userinfo.authdb.sqlite')
    authdb.initial_authdb_inserts('sqlite:///test-userinfo.authdb.sqlite')


def test_internal_user_edit():
    '''
    This tests if we can add user info to a user dict.

    '''

    try:
        os.remove('test-userinfo.authdb.sqlite')
    except Exception:
        pass
    try:
        os.remove('test-userinfo.authdb.sqlite-shm')
    except Exception:
        pass
    try:
        os.remove('test-userinfo.authdb.sqlite-wal')
    except Exception:
        pass

    get_test_authdb()
    get_public_suffix_list()

    # create the user
    user_payload = {'full_name':'Test User',
                    'email':'testuser-userinfo@test.org',
                    'password':'aROwQin9L8nNtPTEMLXd',
                    'pii_salt':'super-secret-salt',
                    'reqid':1,
                    'extra_info':{'pref_thing_always_private':True,
                                  'pref_advancedbits':'this should be deleted'}}
    user_created = actions.create_new_user(
        user_payload,
        override_authdb_path='sqlite:///test-userinfo.authdb.sqlite'
    )
    assert user_created['success'] is True
    assert user_created['user_email'] == 'testuser-userinfo@test.org'
    assert ('User account created. Please verify your email address to log in.'
            in user_created['messages'])

    #
    # now try to edit info for the user
    #

    user_info_added = actions.internal_edit_user(
        {'target_userid':user_created['user_id'],
         'update_dict':{'extra_info': {'this':'is','a':'test',
                                       'pref_thing_always_private':False,
                                       'pref_advancedbits':'__delete__'},
                        'is_active':True,
                        'email_verified':True,
                        'full_name':'Test Middle Named User'},
         'pii_salt':'super-secret-salt',
         'reqid':1},
        override_authdb_path='sqlite:///test-userinfo.authdb.sqlite',
        raiseonfail=True
    )
    assert user_info_added['success'] is True

    new_user_info = user_info_added["user_info"]

    assert new_user_info['email_verified'] is True
    assert new_user_info['is_active'] is True
    assert isinstance(
        new_user_info['extra_info'],
        dict
    )
    assert new_user_info['extra_info']['this'] == 'is'
    assert new_user_info['extra_info']['a'] == 'test'
    assert new_user_info['extra_info'][
        'pref_thing_always_private'
    ] is False
    assert new_user_info['extra_info'].get('pref_advancedbits', None) is None

    # now try to update some disallowed fields and see if it fails as expected
    user_info_added = actions.internal_edit_user(
        {'target_userid':user_created['user_id'],
         'update_dict':{'user_id':10,
                        'system_id':'pwned',
                        'password':'pwnedx2'},
         'pii_salt':'super-secret-salt',
         'reqid':1},
        override_authdb_path='sqlite:///test-userinfo.authdb.sqlite',
        raiseonfail=True
    )
    print(user_info_added['failure_reason'])
    assert user_info_added['success'] is False
    assert ("invalid request: disallowed keys in update_dict" in
            user_info_added['failure_reason'])
    assert ("password" in user_info_added['failure_reason'])
    assert ("user_id" in user_info_added['failure_reason'])
    assert ("system_id" in user_info_added['failure_reason'])

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
        os.remove('test-userinfo.authdb.sqlite')
    except Exception:
        pass
    try:
        os.remove('test-userinfo.authdb.sqlite-shm')
    except Exception:
        pass
    try:
        os.remove('test-userinfo.authdb.sqlite-wal')
    except Exception:
        pass
