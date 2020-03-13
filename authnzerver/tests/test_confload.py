'''
This tests loading conf variables from the environment or tornado options.

'''

import json

from tornado.options import OptionParser
from authnzerver import confvars, confload


def generate_secret_file(filepath):

    with open(filepath.join('secret-file.secret'),'w') as outfd:
        outfd.write('super-secret-secret\n')

    return filepath.join('secret-file.secret')


def generate_permissions_json(filepath):

    json_fpath = filepath.join('permissions-model.json')

    model = {'test':'yes',
             'no':1}
    with open(json_fpath,'w') as outfd:
        json.dump(model, outfd)

    return json_fpath


def generate_options():
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
        default=None,
        help=('Path to a file containing environ variables '
              'for testing/development.'),
        type=str
    )

    # whether to make a new authdb if none exists
    generated_options.define(
        'autosetup',
        default=False,
        help=("If this is True, will automatically generate an SQLite "
              "authentication database in the basedir if there isn't one "
              "present and the value of the authdb option is also None."),
        type=bool
    )

    return generated_options


def test_load_config_from_env(monkeypatch, tmpdir):

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
                       "sqlite:///test/authnzerver/cachedir")
    monkeypatch.setenv("AUTHNZERVER_DEBUGMODE",
                       "0")
    monkeypatch.setenv("AUTHNZERVER_LISTEN",
                       "127.0.0.1")
    monkeypatch.setenv("AUTHNZERVER_PERMISSIONS",
                       str(permissions_json))
    monkeypatch.setenv("AUTHNZERVER_PORT",
                       "13431")
    monkeypatch.setenv("AUTHNZERVER_SECRET",
                       str(secret_file))
    monkeypatch.setenv("AUTHNZERVER_SESSIONEXPIRY",
                       "60")
    monkeypatch.setenv("AUTHNZERVER_WORKERS",
                       "4")

    # load the config items now
    loaded_config = confload.load_config(confvars.CONF,
                                         generated_options,
                                         envfile=generated_options.envfile)

    assert loaded_config.authdb == "sqlite:///test/db/path"
