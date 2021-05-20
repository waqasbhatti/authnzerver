"""
This contains tests for the authnzerver client module.

"""

import secrets
import subprocess
import os.path
import time

import pytest

from authnzerver.autosetup import autogen_secrets_authdb
from authnzerver.client import Authnzerver


@pytest.mark.skipif(
    os.environ.get("GITHUB_WORKFLOW", None) is not None,
    reason="github doesn't allow server tests probably"
)
def test_client(monkeypatch, tmpdir):
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
                       "ipaddr:720;user:360;session:120;apikey:720;burst:150")

    # launch the server subprocess
    p = subprocess.Popen("authnzrv", shell=True)

    # wait 2.5 seconds for the server to start
    time.sleep(2.5)

    #
    # start tests
    #
    try:

        client = Authnzerver(
            authnzerver_url=f"http://{server_listen}:{server_port}",
            authnzerver_secret=secret
        )

        # create a new user
        resp = client.request(
            "user-new",
            {"email":"test-user@test.org",
             "password":"atYSE6m3bsBL",
             "full_name":"New User",
             "client_ipaddr": "1.2.3.4"}
        )
        assert resp.success is True
        assert resp.response["user_id"] == 4
        assert resp.response["send_verification"] is True

        # edit their info
        resp = client.request(
            "internal-user-edit",
            {"target_userid":4,
             "client_ipaddr": "1.2.3.4",
             "update_dict":{"email_verified":True,
                            "is_active":True,
                            "extra_info":{"provenance":"pytest-user",
                                          "type":"test",
                                          "hello":"world"}}}
        )
        assert resp.success is True
        assert resp.response.get("user_info", None) is not None
        assert (
            resp.response["user_info"]["extra_info"]["provenance"]
            == "pytest-user"
        )
        assert (
            resp.response["user_info"]["extra_info"]["type"]
            == "test"
        )
        assert (
            resp.response["user_info"]["extra_info"]["hello"]
            == "world"
        )
        assert resp.response["user_info"]["email_verified"] is True
        assert resp.response["user_info"]["is_active"] is True

    #
    # kill the server at the end
    #
    finally:

        p.terminate()
        try:
            p.communicate(timeout=3.0)
            p.kill()
        except Exception:
            pass

        # make sure to kill authnzrv on some Linux machines.  use lsof and the
        # port number to find the remaining authnzrv processes and kill them
        # subprocess.call(
        #     "lsof | grep 18158 | awk '{ print $2 }' | sort | uniq | xargs kill",
        #     shell=True
        # )
