"""
Contains project-wide pytest fixtures.

"""

import secrets
import subprocess
import os.path
import time

import pytest

from authnzerver.autosetup import autogen_secrets_authdb


@pytest.fixture
def new_authnzerver(monkeypatch, tmpdir):
    """
    This sets up an authnzerver and then returns connection params.

    Tears it down later.

    """

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
    with open(secrets_file, 'r') as infd:
        secret = infd.read().strip('\n')

    # read in the salts file for the salt
    with open(salt_file, 'r') as infd:
        salt = infd.read().strip('\n')

    # read the creds file so we can try logging in
    with open(creds, 'r') as infd:
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

    # return the needed bits for the test
    yield f"http://{server_listen}:{server_port}", secret

    #
    # teardown
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
        "lsof | grep 18158 | awk '{ print $2 }' | sort | uniq | xargs kill -2",
        shell=True
    )
