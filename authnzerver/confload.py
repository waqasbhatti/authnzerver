#!/usr/bin/env python
# -*- coding: utf-8 -*-
# confload.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''This contains functions to load config from environ, command line params, or
an envfile.

'''

#############
## LOGGING ##
#############

import logging

# get a logger
LOGGER = logging.getLogger(__name__)


#############
## IMPORTS ##
#############

import os
import os.path
from configparser import ConfigParser
from itertools import chain
import json
from types import SimpleNamespace


###############################
## CONFIG HANDLING FUNCTIONS ##
###############################

def get_conf_item(env_key,
                  environment,
                  options_object,
                  options_key=None,
                  vartype=str,
                  default=None,
                  readable_from_file=False,
                  raiseonfail=True,
                  basedir=None):
    """This loads a config item from the environment or command-line options.

    The order of precedence is:

    1. environment or envfile if that is provided
    2. command-line option

    Parameters
    ----------

    env_key : str
        The environment variable that specifies the item to get.

    environment : environment object or ConfigParser object
        This is an object similar to that obtained from ``os.environ`` or a
        similar ConfigParser object.

    options_object : Tornado options object
        If the environment variable isn't defined, the next place this function
        will try to get the item value from a passed-in `Tornado options
        <http://www.tornadoweb.org/en/stable/options.html>`_ object, which
        parses command-line options.

    vartype : Python type object: float, str, int, etc.
        The type to use to coerce the input variable to a specific Python type.

    default : Any
        The default value of the conf item.

    options_key : str
        This is the attribute to look up in the options object for the value of
        the conf item.

    readable_from_file : {'json','string'} or False
        If this is specified, and the conf item is a valid filename, will open
        it and read it in, cast to the specified variable type, and return the
        item.

    raiseonfail : bool
        If this is set to True, the function will raise a ValueError for any
        missing config items that can't be set from the environment, the envfile
        or the command-line options. If this is set to False, the function won't
        immediately raise an exception, but will return None. This latter
        behavior is useful for indicating which configuration items are missing
        (e.g. when a server is being started for the first time.)

    basedir : str
        The directory where the server will do its work. This is used to fill in
        '{{basedir}}' template values in any conf item. By default, this is the
        current working directory.

    Returns
    -------

    Any
        The value of the secret.

    """

    confitem = None

    # check the options object first
    if options_key is not None:
        confitem = getattr(options_object, options_key)

    # override with the environment value
    if env_key in environment:
        confitem = environment.get(env_key)

    #
    # if we got a confitem or a default sub, process it
    #

    # if the conf item doesn't exist and there's no default, fail.
    if ( (confitem is None or len(str(confitem).strip()) == 0) and
         (default is None) ):

        if raiseonfail:
            raise ValueError(
                'Config item: "%s" is invalid/missing, '
                'no default provided.' % env_key
            )

        else:
            LOGGER.error(
                'Config item: "%s" is invalid/missing, '
                'no default provided.' % env_key
            )
            return None

    # if the conf item doesn't exist, but a default exists, process that.
    elif ( (confitem is None or len(str(confitem).strip()) == 0) and
           (default is not None) ):

        LOGGER.warning(
            'Config item: "%s" is invalid/missing, '
            'using provided default.' % env_key
        )

        confitem = default

        # handle special substitutions
        if isinstance(confitem, str) and '{{basedir}}' in confitem:
            confitem = confitem.replace('{{basedir}}',basedir)

        # if this is a file to read in as a string
        if (isinstance(confitem, str) and
            os.path.exists(confitem) and
            readable_from_file == 'string'):
            with open(confitem,'r') as infd:
                confitem = infd.read().strip('\n')
                confitem = vartype(confitem)

        # if this is a file to read in as JSON
        elif (isinstance(confitem, str) and
              os.path.exists(confitem) and
              readable_from_file == 'json'):
            with open(confitem,'r') as infd:
                confitem = json.load(infd)

        # otherwise, it's not a file or it doesn't exist, return it as is
        # NOTE: no casting done here to preserve whatever type default was
        # NOTE: e.g., this allows us to use a a dict as a default
        return confitem

    #
    # otherwise, if the conf item exists, return its appropriate value
    #
    # handle special substitutions
    if isinstance(confitem, str) and '{{basedir}}' in confitem:
        confitem = confitem.replace('{{basedir}}',basedir)

    # if this is a file to read in as a string
    if (isinstance(confitem, str) and
        os.path.exists(confitem) and
        readable_from_file == 'string'):
        with open(confitem,'r') as infd:
            confitem = infd.read().strip('\n')
            confitem = vartype(confitem)

    # if this is a file to read in as JSON
    elif (isinstance(confitem, str) and
          os.path.exists(confitem) and
          readable_from_file == 'json'):
        with open(confitem,'r') as infd:
            confitem = json.load(infd)

    # otherwise, it's not a file or it doesn't exist, return it and cast to the
    # appropriate type
    else:
        confitem = vartype(confitem)

    return confitem


def load_config(conf_dict,
                options_object,
                envfile=None):
    '''
    This loads all the config items in config_dict.

    '''

    # get the environ from the envfile as priority 1
    if isinstance(envfile, str) and os.path.exists(envfile):

        # inspired by: https://stackoverflow.com/a/26859985
        with open(envfile,'r') as infd:
            envfd = chain(('[DEFAULT]',), infd)
            c = ConfigParser()
            c.read_file(envfd)
            current_environment = c['DEFAULT']

    # if envfile is an instance of ConfigParser, load it
    elif isinstance(envfile, ConfigParser):
        current_environment = envfile['DEFAULT']

    # if neither of the above work, fall back to the actual environment
    else:
        current_environment = os.environ

    #
    # get the basedir from either the environment or the options
    #
    basedir = get_conf_item(
        conf_dict['basedir']['env'],
        current_environment,
        options_object,
        options_key=conf_dict['basedir']['cmdline'],
        vartype=conf_dict['basedir']['type'],
        default=conf_dict['basedir']['default'],
        readable_from_file=conf_dict['basedir']['readable_from_file'],
    )

    loaded_options = SimpleNamespace()

    for key in conf_dict:

        conf_item_value = get_conf_item(
            conf_dict[key]['env'],
            current_environment,
            options_object,
            options_key=conf_dict[key]['cmdline'],
            vartype=conf_dict[key]['type'],
            default=conf_dict[key]['default'],
            readable_from_file=conf_dict[key]['readable_from_file'],
            basedir=basedir
        )
        setattr(loaded_options, key, conf_item_value)

    return loaded_options
