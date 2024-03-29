"""
This tests loading conf variables from the environment or tornado options.

"""

from textwrap import dedent
import os
import os.path
import getpass
import base64

import requests

from tornado.options import OptionParser

from authnzerver import confvars, confload
from authnzerver.permissions import load_permissions_json


def generate_secret_file(filepath):

    with open(filepath.join("secret-file.secret"), "w") as outfd:
        outfd.write("super-secret-secret\n")

    return str(filepath.join("secret-file.secret"))


def generate_salt_file(filepath):

    with open(filepath.join("salt-file.secret"), "w") as outfd:
        outfd.write("super-secret-salt\n")

    return str(filepath.join("salt-file.secret"))


def generate_permissions_json(filepath):

    # get the file pointing to the default permissions model
    thisdir = os.path.dirname(__file__)
    permfile = os.path.abspath(
        os.path.join(thisdir, "..", "default-permissions-model.json")
    )

    return permfile


def generate_envfile(
    filepath,
    authdb=None,
    basedir=None,
    debugmode=None,
    listen=None,
    permissions=None,
    port=None,
    secret=None,
    piisalt=None,
    sessionexpiry=None,
    workers=None,
    emailserver=None,
    emailport=None,
    emailuser=None,
    emailpass=None,
):

    envfile_path = filepath.join(".env")

    with open(envfile_path, "w") as outfd:

        outfd.write(
            dedent(
                f"""\
                AUTHNZERVER_AUTHDB={authdb}
                AUTHNZERVER_BASEDIR={basedir}
                AUTHNZERVER_DEBUGMODE={debugmode}
                AUTHNZERVER_LISTEN={listen}
                AUTHNZERVER_PERMISSIONS={permissions}
                AUTHNZERVER_PORT={port}
                AUTHNZERVER_SECRET={secret}
                AUTHNZERVER_PIISALT={piisalt}
                AUTHNZERVER_SESSIONEXPIRY={sessionexpiry}
                AUTHNZERVER_WORKERS={workers}
                AUTHNZERVER_EMAILSERVER={emailserver}
                AUTHNZERVER_EMAILPORT={emailport}
                AUTHNZERVER_EMAILUSER={emailuser}
                AUTHNZERVER_EMAILPASS={emailpass}
                """
            )
        )

    return str(envfile_path)


def generate_options(envfile=None, autosetup=False):
    """
    This generates a Tornado options object for use in testing.

    """

    generated_options = OptionParser()

    # load all of the conf vars as command-line options
    for cv in confvars.CONF:
        generated_options.define(
            confvars.CONF[cv]["cmdline"],
            default=confvars.CONF[cv]["default"],
            help=confvars.CONF[cv]["help"],
            type=confvars.CONF[cv]["type"],
        )

    # the path to an env file containing environment variables
    generated_options.define(
        "envfile",
        default=envfile,
        help=(
            "Path to a file containing environ variables "
            "for testing/development."
        ),
        type=str,
    )

    # whether to make a new authdb if none exists
    generated_options.define(
        "autosetup",
        default=autosetup,
        help=(
            "If this is True, will automatically generate an SQLite "
            "authentication database in the basedir if there isn't one "
            "present and the value of the authdb option is also None."
        ),
        type=bool,
    )

    return generated_options


def test_load_config_from_env_filesecret(monkeypatch, tmpdir):

    # generate the secret files
    secret_file = generate_secret_file(tmpdir)
    salt_file = generate_salt_file(tmpdir)

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    monkeypatch.setenv("AUTHNZERVER_AUTHDB", "sqlite:///test/db/path")
    monkeypatch.setenv("AUTHNZERVER_BASEDIR", "/test/base/dir")
    monkeypatch.setenv("AUTHNZERVER_DEBUGMODE", "0")
    monkeypatch.setenv("AUTHNZERVER_LISTEN", "127.0.0.1")
    monkeypatch.setenv("AUTHNZERVER_PERMISSIONS", permissions_json)
    monkeypatch.setenv("AUTHNZERVER_PORT", "13431")
    monkeypatch.setenv("AUTHNZERVER_SECRET", secret_file)
    monkeypatch.setenv("AUTHNZERVER_PIISALT", salt_file)
    monkeypatch.setenv("AUTHNZERVER_SESSIONEXPIRY", "60")
    monkeypatch.setenv("AUTHNZERVER_WORKERS", "4")
    monkeypatch.setenv("AUTHNZERVER_EMAILSERVER", "smtp.test.org")
    monkeypatch.setenv("AUTHNZERVER_EMAILPORT", "25")
    monkeypatch.setenv("AUTHNZERVER_EMAILUSER", "testuser")
    monkeypatch.setenv("AUTHNZERVER_EMAILPASS", "testpass")

    # load the config items now
    loaded_config = confload.load_config(
        confvars.CONF, generated_options, envfile=generated_options.envfile
    )

    assert loaded_config.authdb == "sqlite:///test/db/path"
    assert loaded_config.basedir == "/test/base/dir"
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == "127.0.0.1"

    # check if the permission model was loaded correctly
    loaded_permissions = load_permissions_json(loaded_config.permissions)
    assert isinstance(loaded_permissions, dict)
    assert loaded_permissions["roles"] == {
        "superuser",
        "staff",
        "authenticated",
        "anonymous",
        "locked",
    }

    assert loaded_config.port == 13431
    assert loaded_config.secret == "super-secret-secret"
    assert loaded_config.piisalt == "super-secret-salt"

    assert loaded_config.sessionexpiry == 60
    assert loaded_config.workers == 4

    # email setup check
    assert loaded_config.emailserver == "smtp.test.org"
    assert loaded_config.emailport == 25
    assert loaded_config.emailuser == "testuser"
    assert loaded_config.emailpass == "testpass"


def test_load_config_from_env_textsecret(monkeypatch, tmpdir):

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    monkeypatch.setenv("AUTHNZERVER_AUTHDB", "sqlite:///test/db/path")
    monkeypatch.setenv("AUTHNZERVER_BASEDIR", "/test/base/dir")
    monkeypatch.setenv("AUTHNZERVER_DEBUGMODE", "0")
    monkeypatch.setenv("AUTHNZERVER_LISTEN", "127.0.0.1")
    monkeypatch.setenv("AUTHNZERVER_PERMISSIONS", permissions_json)
    monkeypatch.setenv("AUTHNZERVER_PORT", "13431")
    monkeypatch.setenv("AUTHNZERVER_SECRET", "this is a direct text secret")
    monkeypatch.setenv("AUTHNZERVER_PIISALT", "this is a direct text salt")
    monkeypatch.setenv("AUTHNZERVER_SESSIONEXPIRY", "60")
    monkeypatch.setenv("AUTHNZERVER_WORKERS", "4")
    monkeypatch.setenv("AUTHNZERVER_EMAILSERVER", "smtp.test.org")
    monkeypatch.setenv("AUTHNZERVER_EMAILPORT", "25")
    monkeypatch.setenv("AUTHNZERVER_EMAILUSER", "testuser")
    monkeypatch.setenv("AUTHNZERVER_EMAILPASS", "testpass")

    # load the config items now
    loaded_config = confload.load_config(
        confvars.CONF, generated_options, envfile=generated_options.envfile
    )

    assert loaded_config.authdb == "sqlite:///test/db/path"
    assert loaded_config.basedir == "/test/base/dir"
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == "127.0.0.1"

    # check if the permission model was loaded correctly
    loaded_permissions = load_permissions_json(loaded_config.permissions)
    assert isinstance(loaded_permissions, dict)
    assert loaded_permissions["roles"] == {
        "superuser",
        "staff",
        "authenticated",
        "anonymous",
        "locked",
    }

    assert loaded_config.port == 13431
    assert loaded_config.secret == "this is a direct text secret"
    assert loaded_config.piisalt == "this is a direct text salt"

    assert loaded_config.sessionexpiry == 60
    assert loaded_config.workers == 4

    # email setup check
    assert loaded_config.emailserver == "smtp.test.org"
    assert loaded_config.emailport == 25
    assert loaded_config.emailuser == "testuser"
    assert loaded_config.emailpass == "testpass"


def test_load_config_from_options(monkeypatch, tmpdir):

    # generate the secret files
    secret_file = generate_secret_file(tmpdir)
    salt_file = generate_salt_file(tmpdir)

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    generated_options.authdb = "sqlite:///path/to/auth-db-opt"
    generated_options.basedir = "/path/to/basedir-opt"
    generated_options.listen = "192.168.1.1"
    generated_options.port = 15000
    generated_options.sessionexpiry = 7
    generated_options.workers = 8

    generated_options.permissions = permissions_json
    generated_options.secret = secret_file
    generated_options.piisalt = salt_file

    generated_options.emailserver = "smtp.test.org"
    generated_options.emailport = 25
    generated_options.emailuser = "me"
    generated_options.emailpass = "them"

    # load the config items now
    loaded_config = confload.load_config(
        confvars.CONF, generated_options, envfile=None
    )

    assert loaded_config.authdb == "sqlite:///path/to/auth-db-opt"
    assert loaded_config.basedir == "/path/to/basedir-opt"
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == "192.168.1.1"

    # check if the permission model was loaded correctly
    loaded_permissions = load_permissions_json(loaded_config.permissions)
    assert isinstance(loaded_permissions, dict)
    assert loaded_permissions["roles"] == {
        "superuser",
        "staff",
        "authenticated",
        "anonymous",
        "locked",
    }

    assert loaded_config.port == 15000
    assert loaded_config.secret == "super-secret-secret"
    assert loaded_config.piisalt == "super-secret-salt"

    assert loaded_config.sessionexpiry == 7
    assert loaded_config.workers == 8

    # email setup check
    assert loaded_config.emailserver == generated_options.emailserver
    assert loaded_config.emailport == generated_options.emailport
    assert loaded_config.emailuser == generated_options.emailuser
    assert loaded_config.emailpass == generated_options.emailpass


def test_load_config_from_envfile_filesecret(monkeypatch, tmpdir):

    # generate the secret files
    secret_file = generate_secret_file(tmpdir)
    salt_file = generate_salt_file(tmpdir)

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    # generate the envfile
    generated_envfile = generate_envfile(
        tmpdir,
        authdb="sqlite:///path/to/authdb-envfile",
        basedir="/path/to/basedir-envfile",
        debugmode=0,
        listen="10.0.0.10",
        permissions=permissions_json,
        port=5005,
        secret=secret_file,
        piisalt=salt_file,
        sessionexpiry=25,
        workers=1,
        emailserver="smtp.test.org",
        emailport=25,
        emailuser="testuser",
        emailpass="testpass",
    )

    # load the config items now
    loaded_config = confload.load_config(
        confvars.CONF, generated_options, envfile=generated_envfile
    )

    assert loaded_config.authdb == "sqlite:///path/to/authdb-envfile"
    assert loaded_config.basedir == "/path/to/basedir-envfile"
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == "10.0.0.10"

    # check if the permission model was loaded correctly
    loaded_permissions = load_permissions_json(loaded_config.permissions)
    assert isinstance(loaded_permissions, dict)
    assert loaded_permissions["roles"] == {
        "superuser",
        "staff",
        "authenticated",
        "anonymous",
        "locked",
    }

    assert loaded_config.port == 5005
    assert loaded_config.secret == "super-secret-secret"
    assert loaded_config.piisalt == "super-secret-salt"

    assert loaded_config.sessionexpiry == 25
    assert loaded_config.workers == 1

    # email setup check
    assert loaded_config.emailserver == "smtp.test.org"
    assert loaded_config.emailport == 25
    assert loaded_config.emailuser == "testuser"
    assert loaded_config.emailpass == "testpass"


def test_load_config_from_envfile_textsecret(monkeypatch, tmpdir):

    # generate the secrets
    secret = "this is a direct secret bit"
    piisalt = "this is a direct secret salt"

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    # generate the envfile
    generated_envfile = generate_envfile(
        tmpdir,
        authdb="sqlite:///path/to/authdb-envfile",
        basedir="/path/to/basedir-envfile",
        debugmode=0,
        listen="10.0.0.10",
        permissions=permissions_json,
        port=5005,
        secret=secret,
        piisalt=piisalt,
        sessionexpiry=25,
        workers=1,
        emailserver="smtp.test.org",
        emailport=25,
        emailuser="testuser",
        emailpass="testpass",
    )

    # load the config items now
    loaded_config = confload.load_config(
        confvars.CONF, generated_options, envfile=generated_envfile
    )

    assert loaded_config.authdb == "sqlite:///path/to/authdb-envfile"
    assert loaded_config.basedir == "/path/to/basedir-envfile"
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == "10.0.0.10"

    # check if the permission model was loaded correctly
    loaded_permissions = load_permissions_json(loaded_config.permissions)
    assert isinstance(loaded_permissions, dict)
    assert loaded_permissions["roles"] == {
        "superuser",
        "staff",
        "authenticated",
        "anonymous",
        "locked",
    }

    assert loaded_config.port == 5005
    assert loaded_config.secret == "this is a direct secret bit"
    assert loaded_config.piisalt == "this is a direct secret salt"

    assert loaded_config.sessionexpiry == 25
    assert loaded_config.workers == 1

    # email setup check
    assert loaded_config.emailserver == "smtp.test.org"
    assert loaded_config.emailport == 25
    assert loaded_config.emailuser == "testuser"
    assert loaded_config.emailpass == "testpass"


def test_load_config_env_and_defaults(monkeypatch, tmpdir):

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    monkeypatch.setenv("AUTHNZERVER_AUTHDB", "sqlite:///test/db/path")
    monkeypatch.setenv("AUTHNZERVER_DEBUGMODE", "0")
    monkeypatch.setenv("AUTHNZERVER_PERMISSIONS", permissions_json)
    monkeypatch.setenv("AUTHNZERVER_SECRET", "this is a direct text secret")
    monkeypatch.setenv("AUTHNZERVER_PIISALT", "this is a direct text salt")

    # load the config items now
    loaded_config = confload.load_config(
        confvars.CONF, generated_options, envfile=generated_options.envfile
    )

    assert loaded_config.authdb == "sqlite:///test/db/path"
    assert loaded_config.basedir == os.getcwd()
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == "127.0.0.1"

    # check if the permission model was loaded correctly
    loaded_permissions = load_permissions_json(loaded_config.permissions)
    assert isinstance(loaded_permissions, dict)
    assert loaded_permissions["roles"] == {
        "superuser",
        "staff",
        "authenticated",
        "anonymous",
        "locked",
    }

    assert loaded_config.port == 13431
    assert loaded_config.secret == "this is a direct text secret"
    assert loaded_config.piisalt == "this is a direct text salt"

    assert loaded_config.sessionexpiry == 30
    assert loaded_config.workers == 4

    # email setup check
    assert loaded_config.emailserver == "localhost"
    assert loaded_config.emailport == 25
    assert loaded_config.emailuser == getpass.getuser()
    assert loaded_config.emailpass == ""


def test_load_config_options_and_defaults(monkeypatch, tmpdir):

    # generate the secret file
    secret_file = generate_secret_file(tmpdir)

    # generate the salt file
    salt_file = generate_salt_file(tmpdir)

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    generated_options.authdb = "sqlite:///path/to/auth-db-opt"
    generated_options.listen = "192.168.1.1"
    generated_options.port = 4002
    generated_options.permissions = permissions_json
    generated_options.secret = secret_file
    generated_options.piisalt = salt_file

    # load the config items now
    loaded_config = confload.load_config(
        confvars.CONF, generated_options, envfile=None
    )

    assert loaded_config.authdb == "sqlite:///path/to/auth-db-opt"
    assert loaded_config.basedir == os.getcwd()
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == "192.168.1.1"

    # check if the permission model was loaded correctly
    loaded_permissions = load_permissions_json(loaded_config.permissions)
    assert isinstance(loaded_permissions, dict)
    assert loaded_permissions["roles"] == {
        "superuser",
        "staff",
        "authenticated",
        "anonymous",
        "locked",
    }

    assert loaded_config.port == 4002
    assert loaded_config.secret == "super-secret-secret"
    assert loaded_config.piisalt == "super-secret-salt"

    assert loaded_config.sessionexpiry == 30
    assert loaded_config.workers == 4

    # email setup check
    assert loaded_config.emailserver == "localhost"
    assert loaded_config.emailport == 25
    assert loaded_config.emailuser == getpass.getuser()
    assert loaded_config.emailpass == ""


def test_item_from_file(tmpdir):
    """
    This tests if the config can be loaded from env + a file.

    """

    # generate the secret files
    secret_file = generate_secret_file(tmpdir)

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    #
    # 1. test we can load the secret file
    #
    loaded_item = confload.item_from_file(secret_file, "string")
    assert loaded_item == "super-secret-secret"

    #
    # 2. test we can load an entire JSON
    #
    loaded_item = confload.item_from_file(permissions_json, "json")
    assert isinstance(loaded_item, dict)
    assert loaded_item["roles"] == [
        "superuser",
        "staff",
        "authenticated",
        "anonymous",
        "locked",
    ]

    #
    # 3. test we can load a specific item inside a JSON
    #
    loaded_item = confload.item_from_file(
        permissions_json,
        (
            "json",
            "role_policy.staff.allowed_actions_for_other.unlisted._arr_2",
        ),
    )
    assert loaded_item == "delete"


def test_item_from_url(monkeypatch, requests_mock):
    """
    This tests if the config can be loaded from env + remote URLs.

    """

    # set the env
    monkeypatch.setenv("GCP_APIKEY", "super-secret-token")
    monkeypatch.setenv("GCP_PROJECTID", "abcproj")

    #
    # 0. mock the URL bits
    #

    # GET URL
    # NOTE: the z-access here should technically be z:access
    # but request-mock=1.9.1 quotes the ':' character differently
    # from actual requests, so the URL doesn't match and the assert fails
    # see: https://github.com/jamielennox/requests-mock/pull/167
    get_url = (
        "https://secretmanager.googleapis.com/v1/"
        "projects/abcproj/secrets/abc/versions/z-access"
    )
    get_expect_headers = {
        "Authorization": "Bearer super-secret-token",
        "Content-Type": "application/json",
        "x-goog-user-project": "abcproj",
    }
    get_response = "this-should-be-base64-but-whatever"

    requests_mock.get(
        get_url, request_headers=get_expect_headers, text=get_response
    )

    #
    # 1. test requests itself works fine with the mocked bits
    #

    resp = requests.get(
        get_url,
        headers=get_expect_headers,
    )
    assert resp.text == get_response
    resp.close()

    #
    # 2. now test if the item_from_url function works fine with a string
    #
    send_headers = {
        "Authorization": "Bearer [[GCP_APIKEY]]",
        "Content-Type": "application/json",
        "x-goog-user-project": "[[GCP_PROJECTID]]",
    }

    url_spec = (
        "http",
        {
            "method": "get",
            "headers": send_headers,
            "data": None,
            "timeout": 5.0,
        },
        "string",
    )

    loaded_item = confload.item_from_url(
        get_url,
        url_spec,
        os.environ,
    )

    assert loaded_item == get_response

    #
    # 3. now test if the item_from_url function works fine with a JSON item
    #

    get_url = (
        "https://secretmanager.googleapis.com/v1/"
        "projects/abcproj/secrets/abc/versions/z-access"
    )
    get_expect_headers = {
        "Authorization": "Bearer super-secret-token",
        "Content-Type": "application/json",
        "x-goog-user-project": "abcproj",
    }
    get_response = {
        "secret": "very-yes",
        "testbit": {"available": ["maybe", "yes", "no"]},
    }

    requests_mock.get(
        get_url, request_headers=get_expect_headers, json=get_response
    )
    send_headers = {
        "Authorization": "Bearer [[GCP_APIKEY]]",
        "Content-Type": "application/json",
        "x-goog-user-project": "[[GCP_PROJECTID]]",
    }

    url_spec = (
        "http",
        {
            "method": "get",
            "headers": send_headers,
            "data": None,
            "timeout": 5.0,
        },
        "json",
        "testbit.available._arr_2",
    )

    loaded_item = confload.item_from_url(
        get_url,
        url_spec,
        os.environ,
    )

    assert loaded_item == "no"


def test_get_conf_item_postprocess(monkeypatch, requests_mock, tmpdir):
    """Tests if the item can be loaded and post-processed by a custom function."""

    #
    # 0. mock the URL bits
    #

    # GET URL
    get_url = (
        "https://secretmanager.googleapis.com/v1/"
        "projects/abcproj/secrets/abc/versions/z-access"
    )
    get_expect_headers = {
        "Authorization": "Bearer super-secret-token",
        "Content-Type": "application/json",
        "x-goog-user-project": "abcproj",
    }
    get_response = {
        "payload": {
            "data": (base64.b64encode(b"hello-world-im-secret")).decode(
                "utf-8"
            )
        }
    }

    requests_mock.get(
        get_url, request_headers=get_expect_headers, json=get_response
    )

    #
    # 1. write the postproc function to the file
    #
    function_file = os.path.abspath(str(tmpdir.join("proc_module.py")))

    with open(function_file, "w") as outfd:
        outfd.write(
            """
import base64

def custom_b64decode(input):
    return base64.b64decode(input.encode('utf-8')).decode('utf-8')
"""
        )

    #
    # 2. set up the env and config dict
    #

    monkeypatch.setenv("GCP_SECMAN_URL", get_url)
    monkeypatch.setenv("GCP_AUTH_TOKEN", "super-secret-token")

    readable_from_file = (
        "http",
        {
            "method": "get",
            "headers": {
                "Authorization": "Bearer [[GCP_AUTH_TOKEN]]",
                "Content-Type": "application/json",
                "x-goog-user-project": "abcproj",
            },
            "data": None,
            "timeout": 5.0,
        },
        "json",
        "payload.data",
    )

    # set up the config_dict
    conf_dict = {
        "secret": {
            "env": "GCP_SECMAN_URL",
            "cmdline": "secret",
            "type": str,
            "default": None,
            "help": (
                "The shared secret key used to secure "
                "communications between authnzerver and "
                "any frontend servers."
            ),
            "readable_from_file": readable_from_file,
            "postprocess_value": "%s::custom_b64decode" % function_file,
        }
    }

    #
    # 4. try the process
    #
    conf_item = confload.get_conf_item(
        conf_dict["secret"]["env"],
        os.environ,
        None,
        options_key=None,
        vartype=conf_dict["secret"]["type"],
        default=conf_dict["secret"]["default"],
        readable_from_file=conf_dict["secret"]["readable_from_file"],
        postprocess_value=conf_dict["secret"]["postprocess_value"],
    )

    assert conf_item == "hello-world-im-secret"
