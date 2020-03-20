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
    authdb_path, creds, secrets_file = autogen_secrets_authdb(
        basedir,
        interactive=False
    )

    # read in the secrets file for the secret
    with open(secrets_file,'r') as infd:
        secret = infd.read().strip('\n')

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
    # 2. TODO: login as the superuser
    #

    #
    # 3. TODO: try to access a few items as superuser
    #

    #
    # 4. TODO: log out the superuser
    #

    #
    # kill the server at the end
    #

    p.kill()
    try:
        p.communicate(timeout=1.0)
        p.kill()
    except Exception:
        pass
