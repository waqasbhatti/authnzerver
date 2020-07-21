'''test_server_ratelimits.py -
   Waqas Bhatti (waqas.afzal.bhatti@gmail.com) - Mar 2020
License: MIT. See the LICENSE file for details.

This tests the rate-limiting for a running authnzerver.

'''

import secrets
import subprocess
import requests
import os.path
import time
from datetime import datetime, timedelta
from collections import Counter

from pytest import mark, approx

from authnzerver.autosetup import autogen_secrets_authdb
from authnzerver.messaging import encrypt_message


@mark.skipif(
    os.environ.get("GITHUB_WORKFLOW", None) is not None,
    reason="github doesn't allow server tests probably"
)
def test_ratelimits(monkeypatch, tmpdir):
    '''
    This tests if the server does rate-limiting correctly.

    '''

    # the basedir will be the pytest provided temporary directory
    basedir = str(tmpdir)

    # we'll make the auth DB and secrets file first
    authdb_path, creds, secrets_file, salt_file, env_file = (
        autogen_secrets_authdb(
            basedir,
            interactive=False
        )
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

    # set the session request rate-limit to 120 per 60 seconds
    monkeypatch.setenv("AUTHNZERVER_RATELIMITS",
                       "all:15000;user:360;session:120;apikey:720;burst:150")

    # launch the server subprocess
    p = subprocess.Popen("authnzrv", shell=True)

    # wait 2.5 seconds for the server to start
    time.sleep(2.5)

    try:

        #
        # 1. hit the server with 300 session-new requests
        #
        nreqs = 300

        resplist = []
        for req_ind in range(1,nreqs+1):

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
                            'reqid':req_ind}

            encrypted_request = encrypt_message(request_dict, secret)

            # send the request to the authnzerver
            resp = requests.post(
                'http://%s:%s' % (server_listen, server_port),
                data=encrypted_request,
                timeout=1.0
            )
            resplist.append(resp.status_code)

        # now check if we have about the right number of successful requests
        # should be around 150 (max burst allowed) after which we get all 429s
        respcounter = Counter(resplist)
        assert respcounter[200]/nreqs == approx(150/nreqs, rel=0.01)
        assert respcounter[429]/nreqs == approx(150/nreqs, rel=0.01)

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
