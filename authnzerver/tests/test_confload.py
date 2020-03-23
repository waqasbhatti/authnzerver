'''
This tests loading conf variables from the environment or tornado options.

'''

from textwrap import dedent
import os
import os.path
import getpass

from tornado.options import OptionParser
from authnzerver import confvars, confload

from authnzerver.permissions import load_permissions_json


def generate_secret_file(filepath):

    with open(filepath.join('secret-file.secret'),'w') as outfd:
        outfd.write('super-secret-secret\n')

    return str(filepath.join('secret-file.secret'))


def generate_salt_file(filepath):

    with open(filepath.join('salt-file.secret'),'w') as outfd:
        outfd.write('super-secret-salt\n')

    return str(filepath.join('salt-file.secret'))


def generate_permissions_json(filepath):

    # get the file pointing to the default permissions model
    thisdir = os.path.dirname(__file__)
    permfile = os.path.abspath(
        os.path.join(thisdir,'..','default-permissions-model.json')
    )

    return permfile


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
        piisalt=None,
        sessionexpiry=None,
        workers=None,
        emailserver=None,
        emailport=None,
        emailuser=None,
        emailpass=None
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

    # generate the secret files
    secret_file = generate_secret_file(tmpdir)
    salt_file = generate_salt_file(tmpdir)

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
    monkeypatch.setenv("AUTHNZERVER_PIISALT",
                       salt_file)
    monkeypatch.setenv("AUTHNZERVER_SESSIONEXPIRY",
                       "60")
    monkeypatch.setenv("AUTHNZERVER_WORKERS",
                       "4")
    monkeypatch.setenv("AUTHNZERVER_EMAILSERVER",
                       "smtp.test.org")
    monkeypatch.setenv("AUTHNZERVER_EMAILPORT",
                       "25")
    monkeypatch.setenv("AUTHNZERVER_EMAILUSER",
                       "testuser")
    monkeypatch.setenv("AUTHNZERVER_EMAILPASS",
                       "testpass")

    # load the config items now
    loaded_config = confload.load_config(confvars.CONF,
                                         generated_options,
                                         envfile=generated_options.envfile)

    assert loaded_config.authdb == "sqlite:///test/db/path"
    assert loaded_config.basedir == "/test/base/dir"
    assert loaded_config.cachedir == "/test/authnzerver/cachedir"
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == '127.0.0.1'

    # check if the permission model was loaded correctly
    loaded_permissions = load_permissions_json(loaded_config.permissions)
    assert isinstance(loaded_permissions, dict)
    assert loaded_permissions['roles'] == {'superuser',
                                           'staff',
                                           'authenticated',
                                           'anonymous',
                                           'locked'}

    assert loaded_config.port == 13431
    assert loaded_config.secret == 'super-secret-secret'
    assert loaded_config.piisalt == 'super-secret-salt'

    assert loaded_config.sessionexpiry == 60
    assert loaded_config.workers == 4

    # email setup check
    assert loaded_config.emailserver == 'smtp.test.org'
    assert loaded_config.emailport == 25
    assert loaded_config.emailuser == 'testuser'
    assert loaded_config.emailpass == 'testpass'


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
    monkeypatch.setenv("AUTHNZERVER_PIISALT",
                       'this is a direct text salt')
    monkeypatch.setenv("AUTHNZERVER_SESSIONEXPIRY",
                       "60")
    monkeypatch.setenv("AUTHNZERVER_WORKERS",
                       "4")
    monkeypatch.setenv("AUTHNZERVER_EMAILSERVER",
                       "smtp.test.org")
    monkeypatch.setenv("AUTHNZERVER_EMAILPORT",
                       "25")
    monkeypatch.setenv("AUTHNZERVER_EMAILUSER",
                       "testuser")
    monkeypatch.setenv("AUTHNZERVER_EMAILPASS",
                       "testpass")

    # load the config items now
    loaded_config = confload.load_config(confvars.CONF,
                                         generated_options,
                                         envfile=generated_options.envfile)

    assert loaded_config.authdb == "sqlite:///test/db/path"
    assert loaded_config.basedir == "/test/base/dir"
    assert loaded_config.cachedir == "/test/authnzerver/cachedir"
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == '127.0.0.1'

    # check if the permission model was loaded correctly
    loaded_permissions = load_permissions_json(loaded_config.permissions)
    assert isinstance(loaded_permissions, dict)
    assert loaded_permissions['roles'] == {'superuser',
                                           'staff',
                                           'authenticated',
                                           'anonymous',
                                           'locked'}

    assert loaded_config.port == 13431
    assert loaded_config.secret == 'this is a direct text secret'
    assert loaded_config.piisalt == 'this is a direct text salt'

    assert loaded_config.sessionexpiry == 60
    assert loaded_config.workers == 4

    # email setup check
    assert loaded_config.emailserver == 'smtp.test.org'
    assert loaded_config.emailport == 25
    assert loaded_config.emailuser == 'testuser'
    assert loaded_config.emailpass == 'testpass'


def test_load_config_from_options(monkeypatch, tmpdir):

    # generate the secret files
    secret_file = generate_secret_file(tmpdir)
    salt_file = generate_salt_file(tmpdir)

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    generated_options.authdb = 'sqlite:///path/to/auth-db-opt'
    generated_options.basedir = '/path/to/basedir-opt'
    generated_options.listen = '192.168.1.1'
    generated_options.port = 15000
    generated_options.sessionexpiry = 7
    generated_options.workers = 8

    generated_options.permissions = permissions_json
    generated_options.secret = secret_file
    generated_options.piisalt = salt_file

    generated_options.emailserver = 'smtp.test.org'
    generated_options.emailport = 25
    generated_options.emailuser = 'me'
    generated_options.emailpass = 'them'

    # load the config items now
    loaded_config = confload.load_config(confvars.CONF,
                                         generated_options,
                                         envfile=None)

    assert loaded_config.authdb == 'sqlite:///path/to/auth-db-opt'
    assert loaded_config.basedir == '/path/to/basedir-opt'
    assert loaded_config.cachedir == '/tmp/authnzerver-cache'
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == '192.168.1.1'

    # check if the permission model was loaded correctly
    loaded_permissions = load_permissions_json(loaded_config.permissions)
    assert isinstance(loaded_permissions, dict)
    assert loaded_permissions['roles'] == {'superuser',
                                           'staff',
                                           'authenticated',
                                           'anonymous',
                                           'locked'}

    assert loaded_config.port == 15000
    assert loaded_config.secret == 'super-secret-secret'
    assert loaded_config.piisalt == 'super-secret-salt'

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
        authdb='sqlite:///path/to/authdb-envfile',
        basedir='/path/to/basedir-envfile',
        cachedir='/tmp/authnzerver/cachedir-envfile',
        debugmode=0,
        listen='10.0.0.10',
        permissions=permissions_json,
        port=5005,
        secret=secret_file,
        piisalt=salt_file,
        sessionexpiry=25,
        workers=1,
        emailserver='smtp.test.org',
        emailport=25,
        emailuser='testuser',
        emailpass='testpass'
    )

    # load the config items now
    loaded_config = confload.load_config(confvars.CONF,
                                         generated_options,
                                         envfile=generated_envfile)

    assert loaded_config.authdb == "sqlite:///path/to/authdb-envfile"
    assert loaded_config.basedir == "/path/to/basedir-envfile"
    assert loaded_config.cachedir == "/tmp/authnzerver/cachedir-envfile"
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == '10.0.0.10'

    # check if the permission model was loaded correctly
    loaded_permissions = load_permissions_json(loaded_config.permissions)
    assert isinstance(loaded_permissions, dict)
    assert loaded_permissions['roles'] == {'superuser',
                                           'staff',
                                           'authenticated',
                                           'anonymous',
                                           'locked'}

    assert loaded_config.port == 5005
    assert loaded_config.secret == 'super-secret-secret'
    assert loaded_config.piisalt == 'super-secret-salt'

    assert loaded_config.sessionexpiry == 25
    assert loaded_config.workers == 1

    # email setup check
    assert loaded_config.emailserver == 'smtp.test.org'
    assert loaded_config.emailport == 25
    assert loaded_config.emailuser == 'testuser'
    assert loaded_config.emailpass == 'testpass'


def test_load_config_from_envfile_textsecret(monkeypatch, tmpdir):

    # generate the secrets
    secret = 'this is a direct secret bit'
    piisalt = 'this is a direct secret salt'

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    # generate the envfile
    generated_envfile = generate_envfile(
        tmpdir,
        authdb='sqlite:///path/to/authdb-envfile',
        basedir='/path/to/basedir-envfile',
        cachedir='/tmp/authnzerver/cachedir-envfile',
        debugmode=0,
        listen='10.0.0.10',
        permissions=permissions_json,
        port=5005,
        secret=secret,
        piisalt=piisalt,
        sessionexpiry=25,
        workers=1,
        emailserver='smtp.test.org',
        emailport=25,
        emailuser='testuser',
        emailpass='testpass'
    )

    # load the config items now
    loaded_config = confload.load_config(confvars.CONF,
                                         generated_options,
                                         envfile=generated_envfile)

    assert loaded_config.authdb == "sqlite:///path/to/authdb-envfile"
    assert loaded_config.basedir == "/path/to/basedir-envfile"
    assert loaded_config.cachedir == "/tmp/authnzerver/cachedir-envfile"
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == '10.0.0.10'

    # check if the permission model was loaded correctly
    loaded_permissions = load_permissions_json(loaded_config.permissions)
    assert isinstance(loaded_permissions, dict)
    assert loaded_permissions['roles'] == {'superuser',
                                           'staff',
                                           'authenticated',
                                           'anonymous',
                                           'locked'}

    assert loaded_config.port == 5005
    assert loaded_config.secret == 'this is a direct secret bit'
    assert loaded_config.piisalt == 'this is a direct secret salt'

    assert loaded_config.sessionexpiry == 25
    assert loaded_config.workers == 1

    # email setup check
    assert loaded_config.emailserver == 'smtp.test.org'
    assert loaded_config.emailport == 25
    assert loaded_config.emailuser == 'testuser'
    assert loaded_config.emailpass == 'testpass'


def test_load_config_env_and_defaults(monkeypatch, tmpdir):

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    monkeypatch.setenv("AUTHNZERVER_AUTHDB",
                       "sqlite:///test/db/path")
    monkeypatch.setenv("AUTHNZERVER_DEBUGMODE",
                       "0")
    monkeypatch.setenv("AUTHNZERVER_PERMISSIONS",
                       permissions_json)
    monkeypatch.setenv("AUTHNZERVER_SECRET",
                       'this is a direct text secret')
    monkeypatch.setenv("AUTHNZERVER_PIISALT",
                       'this is a direct text salt')

    # load the config items now
    loaded_config = confload.load_config(confvars.CONF,
                                         generated_options,
                                         envfile=generated_options.envfile)

    assert loaded_config.authdb == "sqlite:///test/db/path"
    assert loaded_config.basedir == os.getcwd()
    assert loaded_config.cachedir == '/tmp/authnzerver-cache'
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == '127.0.0.1'

    # check if the permission model was loaded correctly
    loaded_permissions = load_permissions_json(loaded_config.permissions)
    assert isinstance(loaded_permissions, dict)
    assert loaded_permissions['roles'] == {'superuser',
                                           'staff',
                                           'authenticated',
                                           'anonymous',
                                           'locked'}

    assert loaded_config.port == 13431
    assert loaded_config.secret == 'this is a direct text secret'
    assert loaded_config.piisalt == 'this is a direct text salt'

    assert loaded_config.sessionexpiry == 30
    assert loaded_config.workers == 4

    # email setup check
    assert loaded_config.emailserver == 'localhost'
    assert loaded_config.emailport == 25
    assert loaded_config.emailuser == getpass.getuser()
    assert loaded_config.emailpass == ''


def test_load_config_options_and_defaults(monkeypatch, tmpdir):

    # generate the secret file
    secret_file = generate_secret_file(tmpdir)

    # generate the salt file
    salt_file = generate_salt_file(tmpdir)

    # generate the permissions JSON
    permissions_json = generate_permissions_json(tmpdir)

    # generate the tornado options object
    generated_options = generate_options()

    generated_options.authdb = 'sqlite:///path/to/auth-db-opt'
    generated_options.listen = '192.168.1.1'
    generated_options.port = 4002
    generated_options.permissions = permissions_json
    generated_options.secret = secret_file
    generated_options.piisalt = salt_file

    # load the config items now
    loaded_config = confload.load_config(confvars.CONF,
                                         generated_options,
                                         envfile=None)

    assert loaded_config.authdb == 'sqlite:///path/to/auth-db-opt'
    assert loaded_config.basedir == os.getcwd()
    assert loaded_config.cachedir == '/tmp/authnzerver-cache'
    assert loaded_config.debugmode == 0
    assert loaded_config.listen == '192.168.1.1'

    # check if the permission model was loaded correctly
    loaded_permissions = load_permissions_json(loaded_config.permissions)
    assert isinstance(loaded_permissions, dict)
    assert loaded_permissions['roles'] == {'superuser',
                                           'staff',
                                           'authenticated',
                                           'anonymous',
                                           'locked'}

    assert loaded_config.port == 4002
    assert loaded_config.secret == 'super-secret-secret'
    assert loaded_config.piisalt == 'super-secret-salt'

    assert loaded_config.sessionexpiry == 30
    assert loaded_config.workers == 4

    # email setup check
    assert loaded_config.emailserver == 'localhost'
    assert loaded_config.emailport == 25
    assert loaded_config.emailuser == getpass.getuser()
    assert loaded_config.emailpass == ''
