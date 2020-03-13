'''
This tests loading conf variables from the environment or tornado options.

'''

import json
from textwrap import dedent

from tornado.options import OptionParser
from authnzerver import confvars, confload


def generate_secret_file(filepath):

    with open(filepath.join('secret-file.secret'),'w') as outfd:
        outfd.write('super-secret-secret\n')

    return str(filepath.join('secret-file.secret'))


def generate_permissions_json(filepath):

    json_fpath = filepath.join('permissions-model.json')

    model = {'test':'yes',
             'no':1}
    with open(json_fpath,'w') as outfd:
        json.dump(model, outfd)

    return str(json_fpath)


def generate_envfile(
        filepath,
        authdb=None,
        basedir=None,
        cachedir=None,
        debugmode=None,
        listen=None,
        permissions=None,
        port=None,
        secret=None,
        sessionexpiry=None,
        workers=None
):

    envfile_path = filepath.join('.env')

    with open(envfile_path,'w') as outfd:

        outfd.write(
            dedent(
                f"""\
                AUTHNZERVER_AUTHDB={authdb}
                AUTHNZERVER_BASEDIR={basedir}
                AUTHNZERVER_CACHEDIR={cachedir}
                AUTHNZERVER_DEBUGMODE={debugmode}
                AUTHNZERVER_LISTEN={listen}
                AUTHNZERVER_PERMISSIONS={permissions}
                AUTHNZERVER_PORT={port}
                AUTHNZERVER_SECRET={secret}
                AUTHNZERVER_SESSIONEXPIRY={sessionexpiry}
                AUTHNZERVER_WORKERS={workers}
                """
            )
        )

    return str(envfile_path)


def generate_options(envfile=None,
                     autosetup=False):
    '''
    This generates a Tornado options object for use in testing.

    '''

    generated_options = OptionParser()

    # load all of the conf vars as command-line options
    for cv in confvars.CONF:
        generated_options.define(confvars.CONF[cv]['cmdline'],
                                 default=confvars.CONF[cv]['default'],
                                 help=confvars.CONF[cv]['help'],
                                 type=confvars.CONF[cv]['type'])

    # the path to an env file containing environment variables
    generated_options.define(
        'envfile',
        default=envfile,
        help=('Path to a file containing environ variables '
              'for testing/development.'),
        type=str
    )

    # whether to make a new authdb if none exists
    generated_options.define(
        'autosetup',
        default=autosetup,
        help=("If this is True, will automatically generate an SQLite "
              "authentication database in the basedir if there isn't one "
              "present and the value of the authdb option is also None."),
        type=bool
    )

    return generated_options


def test_load_config_from_env_filesecret(monkeypatch, tmpdir):

    # generate the secret file
    secret_file = generate_secret_file(tmpdir)

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    monkeypatch.setenv("AUTHNZERVER_AUTHDB",
                       "sqlite:///test/db/path")
    monkeypatch.setenv("AUTHNZERVER_BASEDIR",
                       "/test/base/dir")
    monkeypatch.setenv("AUTHNZERVER_CACHEDIR",
                       "/test/authnzerver/cachedir")
    monkeypatch.setenv("AUTHNZERVER_DEBUGMODE",
                       "0")
    monkeypatch.setenv("AUTHNZERVER_LISTEN",
                       "127.0.0.1")
    monkeypatch.setenv("AUTHNZERVER_PERMISSIONS",
                       permissions_json)
    monkeypatch.setenv("AUTHNZERVER_PORT",
                       "13431")
    monkeypatch.setenv("AUTHNZERVER_SECRET",
                       secret_file)
    monkeypatch.setenv("AUTHNZERVER_SESSIONEXPIRY",
                       "60")
    monkeypatch.setenv("AUTHNZERVER_WORKERS",
                       "4")

    # load the config items now
    loaded_config = confload.load_config(confvars.CONF,
                                         generated_options,
                                         envfile=generated_options.envfile)

    assert loaded_config.authdb == "sqlite:///test/db/path"
    assert loaded_config.basedir == "/test/base/dir"
    assert loaded_config.cachedir == "/test/authnzerver/cachedir"
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == '127.0.0.1'

    assert isinstance(loaded_config.permissions, dict)
    assert loaded_config.permissions['test'] == 'yes'
    assert loaded_config.permissions['no'] == 1

    assert loaded_config.port == 13431
    assert loaded_config.secret == 'super-secret-secret'

    assert loaded_config.sessionexpiry == 60
    assert loaded_config.workers == 4


def test_load_config_from_env_textsecret(monkeypatch, tmpdir):

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    monkeypatch.setenv("AUTHNZERVER_AUTHDB",
                       "sqlite:///test/db/path")
    monkeypatch.setenv("AUTHNZERVER_BASEDIR",
                       "/test/base/dir")
    monkeypatch.setenv("AUTHNZERVER_CACHEDIR",
                       "/test/authnzerver/cachedir")
    monkeypatch.setenv("AUTHNZERVER_DEBUGMODE",
                       "0")
    monkeypatch.setenv("AUTHNZERVER_LISTEN",
                       "127.0.0.1")
    monkeypatch.setenv("AUTHNZERVER_PERMISSIONS",
                       permissions_json)
    monkeypatch.setenv("AUTHNZERVER_PORT",
                       "13431")
    monkeypatch.setenv("AUTHNZERVER_SECRET",
                       'this is a direct text secret')
    monkeypatch.setenv("AUTHNZERVER_SESSIONEXPIRY",
                       "60")
    monkeypatch.setenv("AUTHNZERVER_WORKERS",
                       "4")

    # load the config items now
    loaded_config = confload.load_config(confvars.CONF,
                                         generated_options,
                                         envfile=generated_options.envfile)

    assert loaded_config.authdb == "sqlite:///test/db/path"
    assert loaded_config.basedir == "/test/base/dir"
    assert loaded_config.cachedir == "/test/authnzerver/cachedir"
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == '127.0.0.1'

    assert isinstance(loaded_config.permissions, dict)
    assert loaded_config.permissions['test'] == 'yes'
    assert loaded_config.permissions['no'] == 1

    assert loaded_config.port == 13431
    assert loaded_config.secret == 'this is a direct text secret'

    assert loaded_config.sessionexpiry == 60
    assert loaded_config.workers == 4


def test_load_config_from_options(monkeypatch, tmpdir):

    # generate the secret file
    secret_file = generate_secret_file(tmpdir)

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    generated_options.authdb = '/path/to/auth-db-opt'
    generated_options.basedir = '/path/to/basedir-opt'
    generated_options.listen = '192.168.1.1'
    generated_options.port = 15000
    generated_options.sessionexpiry = 7
    generated_options.workers = 8

    generated_options.permissions = permissions_json
    generated_options.secret = secret_file

    # load the config items now
    loaded_config = confload.load_config(confvars.CONF,
                                         generated_options,
                                         envfile=None)

    assert loaded_config.authdb == '/path/to/auth-db-opt'
    assert loaded_config.basedir == '/path/to/basedir-opt'
    assert loaded_config.cachedir == '/tmp/authnzerver-cache'
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == '192.168.1.1'

    assert isinstance(loaded_config.permissions, dict)
    assert loaded_config.permissions['test'] == 'yes'
    assert loaded_config.permissions['no'] == 1

    assert loaded_config.port == 15000
    assert loaded_config.secret == 'super-secret-secret'

    assert loaded_config.sessionexpiry == 7
    assert loaded_config.workers == 8


def test_load_config_from_envfile_filesecret(monkeypatch, tmpdir):

    # generate the secret file
    secret_file = generate_secret_file(tmpdir)

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    # generate the envfile
    generated_envfile = generate_envfile(
        tmpdir,
        authdb='/path/to/authdb-envfile',
        basedir='/path/to/basedir-envfile',
        cachedir='/tmp/authnzerver/cachedir-envfile',
        debugmode=0,
        listen='10.0.0.10',
        permissions=permissions_json,
        port=5005,
        secret=secret_file,
        sessionexpiry=25,
        workers=1
    )

    # load the config items now
    loaded_config = confload.load_config(confvars.CONF,
                                         generated_options,
                                         envfile=generated_envfile)

    assert loaded_config.authdb == "/path/to/authdb-envfile"
    assert loaded_config.basedir == "/path/to/basedir-envfile"
    assert loaded_config.cachedir == "/tmp/authnzerver/cachedir-envfile"
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == '10.0.0.10'

    assert isinstance(loaded_config.permissions, dict)
    assert loaded_config.permissions['test'] == 'yes'
    assert loaded_config.permissions['no'] == 1

    assert loaded_config.port == 5005
    assert loaded_config.secret == 'super-secret-secret'

    assert loaded_config.sessionexpiry == 25
    assert loaded_config.workers == 1


def test_load_config_from_envfile_textsecret(monkeypatch, tmpdir):

    # generate the secret
    secret = 'this is a direct secret bit'

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    # generate the envfile
    generated_envfile = generate_envfile(
        tmpdir,
        authdb='/path/to/authdb-envfile',
        basedir='/path/to/basedir-envfile',
        cachedir='/tmp/authnzerver/cachedir-envfile',
        debugmode=0,
        listen='10.0.0.10',
        permissions=permissions_json,
        port=5005,
        secret=secret,
        sessionexpiry=25,
        workers=1
    )

    # load the config items now
    loaded_config = confload.load_config(confvars.CONF,
                                         generated_options,
                                         envfile=generated_envfile)

    assert loaded_config.authdb == "/path/to/authdb-envfile"
    assert loaded_config.basedir == "/path/to/basedir-envfile"
    assert loaded_config.cachedir == "/tmp/authnzerver/cachedir-envfile"
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == '10.0.0.10'

    assert isinstance(loaded_config.permissions, dict)
    assert loaded_config.permissions['test'] == 'yes'
    assert loaded_config.permissions['no'] == 1

    assert loaded_config.port == 5005
    assert loaded_config.secret == 'this is a direct secret bit'

    assert loaded_config.sessionexpiry == 25
    assert loaded_config.workers == 1


def test_load_config_env_over_options(monkeypatch, tmpdir):
    pass


def test_load_config_env_and_defaults(monkeypatch, tmpdir):
    pass


def test_load_config_options_and_defaults(monkeypatch, tmpdir):
    pass
