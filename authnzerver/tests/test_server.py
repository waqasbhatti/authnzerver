'''test_server.py - Waqas Bhatti (waqas.afzal.bhatti@gmail.com) - Mar 2020
License: MIT. See the LICENSE file for details.

This tests the actual running server.

'''

import secrets
import subprocess
import requests
import os.path
import time
from datetime import datetime, timedelta

from authnzerver.autosetup import autogen_secrets_authdb
from authnzerver.handlers import encrypt_response, decrypt_request


def test_server_with_env(monkeypatch, tmpdir):
    '''
    This tests if the server starts fine with all config in the environment.

    '''

    # the basedir will be the pytest provided temporary directory
    basedir = str(tmpdir)

    # we'll make the auth DB and secrets file first
    authdb_path, creds, secrets_file, salt_file = autogen_secrets_authdb(
        basedir,
        interactive=False
    )

    # read in the secrets file for the secret
    with open(secrets_file,'r') as infd:
        secret = infd.read().strip('\n')

    # read in the salts file for the salt
    with open(salt_file,'r') as infd:
        salt = infd.read().strip('\n')

    # read the creds file so we can try logging in
    with open(creds,'r') as infd:
        useremail, password = infd.read().strip('\n').split()

    # get a temp directory
    tmpdir = os.path.join('/tmp', 'authnzrv-%s' % secrets.token_urlsafe(8))

    server_listen = '127.0.0.1'
    server_port = '18158'

    # set up the environment
    monkeypatch.setenv("AUTHNZERVER_AUTHDB", authdb_path)
    monkeypatch.setenv("AUTHNZERVER_BASEDIR", basedir)
    monkeypatch.setenv("AUTHNZERVER_CACHEDIR", tmpdir)
    monkeypatch.setenv("AUTHNZERVER_DEBUGMODE", "0")
    monkeypatch.setenv("AUTHNZERVER_LISTEN", server_listen)
    monkeypatch.setenv("AUTHNZERVER_PORT", server_port)
    monkeypatch.setenv("AUTHNZERVER_SECRET", secret)
    monkeypatch.setenv("AUTHNZERVER_PIISALT", salt)
    monkeypatch.setenv("AUTHNZERVER_SESSIONEXPIRY", "60")
    monkeypatch.setenv("AUTHNZERVER_WORKERS", "1")
    monkeypatch.setenv("AUTHNZERVER_EMAILSERVER", "smtp.test.org")
    monkeypatch.setenv("AUTHNZERVER_EMAILPORT", "25")
    monkeypatch.setenv("AUTHNZERVER_EMAILUSER", "testuser")
    monkeypatch.setenv("AUTHNZERVER_EMAILPASS", "testpass")

    # launch the server subprocess
    p = subprocess.Popen("authnzrv", shell=True)

    # wait 2.5 seconds for the server to start
    time.sleep(2.5)

    try:

        #
        # 1. hit the server with a request for a new session
        #

        # create a new anonymous session token
        session_payload = {
            'user_id':2,
            'user_agent':'Mozzarella Killerwhale',
            'expires':datetime.utcnow()+timedelta(hours=1),
            'ip_address': '1.1.1.1',
            'extra_info_json':{'pref_datasets_always_private':True}
        }

        request_dict = {'request':'session-new',
                        'body':session_payload,
                        'reqid':101}

        encrypted_request = encrypt_response(request_dict, secret)

        # send the request to the authnzerver
        resp = requests.post(
            'http://%s:%s' % (server_listen, server_port),
            data=encrypted_request,
            timeout=1.0
        )
        resp.raise_for_status()

        # decrypt the response
        response_dict = decrypt_request(resp.text, secret)

        assert response_dict['reqid'] == request_dict['reqid']
        assert response_dict['success'] is True
        assert isinstance(response_dict['response'], dict)
        assert response_dict['response']['session_token'] is not None

        #
        # 2. login as the superuser
        #
        request_dict = {
            'request':'user-login',
            'body':{
                'session_token':response_dict['response']['session_token'],
                'email':useremail,
                'password':password
            },
            'reqid':102
        }

        encrypted_request = encrypt_response(request_dict, secret)

        # send the request to the authnzerver
        resp = requests.post(
            'http://%s:%s' % (server_listen, server_port),
            data=encrypted_request,
            timeout=1.0
        )
        resp.raise_for_status()

        # decrypt the response
        response_dict = decrypt_request(resp.text, secret)

        assert response_dict['reqid'] == request_dict['reqid']
        assert response_dict['success'] is True
        assert isinstance(response_dict['response'], dict)
        assert response_dict['response']['user_id'] == 1

        #
        # kill the server at the end
        #

    finally:

        p.kill()
        try:
            p.communicate(timeout=1.0)
            p.kill()
        except Exception:
            pass

        # make sure to kill authnzrv on some Linux machines.  use lsof and the
        # port number to find the remaining authnzrv processes and kill them
        subprocess.call(
            "lsof | grep 18158 | awk '{ print $2 }' | sort | uniq | xargs kill",
            shell=True
        )


def test_server_invalid_logins(monkeypatch, tmpdir):
    '''This tests if the server responds appropriately to invalid logins.

    The timing difference between successive failed logins should increase
    roughly exponentially.

    '''

    # the basedir will be the pytest provided temporary directory
    basedir = str(tmpdir)

    # we'll make the auth DB and secrets file first
    authdb_path, creds, secrets_file, salt_file = autogen_secrets_authdb(
        basedir,
        interactive=False
    )

    # read in the secrets file for the secret
    with open(secrets_file,'r') as infd:
        secret = infd.read().strip('\n')

    # read in the salts file for the salt
    with open(salt_file,'r') as infd:
        salt = infd.read().strip('\n')

    # read the creds file so we can try logging in
    with open(creds,'r') as infd:
        useremail, password = infd.read().strip('\n').split()

    # get a temp directory
    tmpdir = os.path.join('/tmp', 'authnzrv-%s' % secrets.token_urlsafe(8))

    server_listen = '127.0.0.1'
    server_port = '18158'

    # set up the environment
    monkeypatch.setenv("AUTHNZERVER_AUTHDB", authdb_path)
    monkeypatch.setenv("AUTHNZERVER_BASEDIR", basedir)
    monkeypatch.setenv("AUTHNZERVER_CACHEDIR", tmpdir)
    monkeypatch.setenv("AUTHNZERVER_DEBUGMODE", "0")
    monkeypatch.setenv("AUTHNZERVER_LISTEN", server_listen)
    monkeypatch.setenv("AUTHNZERVER_PORT", server_port)
    monkeypatch.setenv("AUTHNZERVER_SECRET", secret)
    monkeypatch.setenv("AUTHNZERVER_PIISALT", salt)
    monkeypatch.setenv("AUTHNZERVER_SESSIONEXPIRY", "60")
    monkeypatch.setenv("AUTHNZERVER_WORKERS", "1")
    monkeypatch.setenv("AUTHNZERVER_EMAILSERVER", "smtp.test.org")
    monkeypatch.setenv("AUTHNZERVER_EMAILPORT", "25")
    monkeypatch.setenv("AUTHNZERVER_EMAILUSER", "testuser")
    monkeypatch.setenv("AUTHNZERVER_EMAILPASS", "testpass")

    # launch the server subprocess
    p = subprocess.Popen("authnzrv", shell=True)

    # wait 2.5 seconds for the server to start
    time.sleep(2.5)

    timing = []

    try:

        #
        # attempt to login as the superuser several times with the wrong
        # password
        #
        for i in range(5):

            # create a new anonymous session token
            session_payload = {
                'user_id':2,
                'user_agent':'Mozzarella Killerwhale',
                'expires':datetime.utcnow()+timedelta(hours=1),
                'ip_address': '1.1.1.1',
                'extra_info_json':{'pref_datasets_always_private':True}
            }

            request_dict = {'request':'session-new',
                            'body':session_payload,
                            'reqid':i}

            encrypted_request = encrypt_response(request_dict, secret)

            # send the request to the authnzerver
            resp = requests.post(
                'http://%s:%s' % (server_listen, server_port),
                data=encrypted_request,
                timeout=1.0
            )
            resp.raise_for_status()

            # decrypt the response
            session_dict = decrypt_request(resp.text, secret)

            assert session_dict['reqid'] == request_dict['reqid']
            assert session_dict['success'] is True
            assert isinstance(session_dict['response'], dict)
            assert session_dict['response']['session_token'] is not None

            request_dict = {
                'request':'user-login',
                'body':{
                    'session_token':session_dict['response']['session_token'],
                    'email':useremail,
                    'password':'%s-%i' % (password,i)
                },
                'reqid':10*i + 10
            }

            encrypted_request = encrypt_response(request_dict, secret)

            start_login_time = time.monotonic()

            # send the request to the authnzerver
            resp = requests.post(
                'http://%s:%s' % (server_listen, server_port),
                data=encrypted_request,
                timeout=60.0
            )
            resp.raise_for_status()

            timing.append(time.monotonic() - start_login_time)

            # decrypt the response
            response_dict = decrypt_request(resp.text, secret)

            assert response_dict['reqid'] == request_dict['reqid']
            assert response_dict['success'] is False
            assert isinstance(response_dict['response'], dict)
            assert response_dict['response']['user_id'] is None

        #
        # check if the timings follow the expected trend
        #
        diffs = [timing[x+1]-timing[x] for x in range(4)]
        diffs_increasing = all(diffs[x+1] > diffs[x] for x in range(3))
        assert diffs_increasing is True

        # now login wih the correct password and see if the login time goes back
        # to normal
        session_payload = {
            'user_id':2,
            'user_agent':'Mozzarella Killerwhale',
            'expires':datetime.utcnow()+timedelta(hours=1),
            'ip_address': '1.1.1.1',
            'extra_info_json':{'pref_datasets_always_private':True}
        }

        request_dict = {'request':'session-new',
                        'body':session_payload,
                        'reqid':1004}

        encrypted_request = encrypt_response(request_dict, secret)

        # send the request to the authnzerver
        resp = requests.post(
            'http://%s:%s' % (server_listen, server_port),
            data=encrypted_request,
            timeout=1.0
        )
        resp.raise_for_status()

        # decrypt the response
        session_dict = decrypt_request(resp.text, secret)

        assert session_dict['reqid'] == request_dict['reqid']
        assert session_dict['success'] is True
        assert isinstance(session_dict['response'], dict)
        assert session_dict['response']['session_token'] is not None

        request_dict = {
            'request':'user-login',
            'body':{
                'session_token':session_dict['response']['session_token'],
                'email':useremail,
                'password':password
            },
            'reqid':1005
        }

        encrypted_request = encrypt_response(request_dict, secret)

        start_login_time = time.monotonic()

        # send the request to the authnzerver
        resp = requests.post(
            'http://%s:%s' % (server_listen, server_port),
            data=encrypted_request,
            timeout=60.0
        )
        resp.raise_for_status()

        timing.append(time.monotonic() - start_login_time)

        # decrypt the response
        response_dict = decrypt_request(resp.text, secret)

        assert response_dict['reqid'] == request_dict['reqid']
        assert response_dict['success'] is True
        assert isinstance(response_dict['response'], dict)
        assert response_dict['response']['user_id'] == 1

        # the latest time should be less than the 1st time (when throttling was
        # activated) and also less than the immediately previous time
        assert ((timing[-1] < timing[0]) and (timing[-1] < timing[-2]))

    finally:

        #
        # kill the server at the end
        #

        p.kill()
        try:
            p.communicate(timeout=1.0)
            p.kill()
        except Exception:
            pass

        # make sure to kill authnzrv on some Linux machines.  use lsof and the
        # port number to find the remaining authnzrv processes and kill them
        subprocess.call(
            "lsof | grep 18158 | awk '{ print $2 }' | sort | uniq | xargs kill",
            shell=True
        )
