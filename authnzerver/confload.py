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


###############################
## CONFIG HANDLING FUNCTIONS ##
###############################

def get_conf_item(item_key,
                  environment,
                  options_object,
                  vartype=str,
                  default=None,
                  options_object_attr=None,
                  readable_from_file=False,
                  basedir=None):
    """This loads a config item from the environment or command-line options.

    The order of precedence is:

    1. environment or envfile if that is provided
    2. command-line option

    Parameters
    ----------

    item_key : str
        The key that specifies the item to get.

    environment : environment object
        This is an environment object similar to that obtained from::

            os.environ

    options_object : Tornado options object
        If the environment variable isn't defined, the next place this function
        will try to get the item value from a passed-in `Tornado options
        <http://www.tornadoweb.org/en/stable/options.html>`_ object, which
        parses command-line options.

    vartype : Python type object: float, str, int, etc.
        The type to use to coerce the input variable to a specific Python type.

    default : Any
        The default value of the conf item.

    options_object_attr : str
        This is the attribute to look up in the options object for the value of
        the conf item.

    readable_from_file : bool
        If this is True, and the conf item is a valid filename, will open it and
        read it in, cast to the specified variable type, and return the item.

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
    if options_object_attr is not None:
        confitem = getattr(options_object, options_object_attr)

    # override with the environment value
    if item_key in environment:
        confitem = environment.get(item_key)

    #
    # if we got a confitem or a default sub, process it
    #

    # if the conf item doesn't exist and there's no default, fail.
    if ( (confitem is None or len(str(confitem).strip()) == 0) and
         (default is None) ):

        raise ValueError(
            'Config item: "%s" is invalid/missing, '
            'no default provided.' % item_key
        )

    # if the conf item doesn't exist, but a default exists, process that.
    elif ( (confitem is None or len(str(confitem).strip()) == 0) and
           (default is not None) ):

        LOGGER.warning(
            'Config item: "%s" is invalid/missing, '
            'using provided default.' % item_key
        )

        confitem = default

        # handle special substitutions
        if isinstance(confitem, str) and '{{basedir}}' in confitem:
            confitem = confitem.replace('{{basedir}}',basedir)

        # if this is a file to read in as a string
        if os.path.exists(confitem) and readable_from_file == 'string':
            with open(confitem,'r') as infd:
                confitem = infd.read().strip('\n')
                confitem = vartype(confitem)

        # if this is a file to read in as JSON
        elif os.path.exists(confitem) and readable_from_file == 'json':
            with open(confitem,'r') as infd:
                confitem = json.load(infd)

        # otherwise, it's not a file or it doesn't exist, return it as is
        else:
            confitem = vartype(confitem)

        return confitem

    #
    # otherwise, if the conf item exists, return its appropriate value
    #
    # handle special substitutions
    if isinstance(confitem, str) and '{{basedir}}' in confitem:
        confitem = confitem.replace('{{basedir}}',basedir)

    # if this is a file to read in as a string
    if os.path.exists(confitem) and readable_from_file == 'string':
        with open(confitem,'r') as infd:
            confitem = infd.read().strip('\n')
            confitem = vartype(confitem)

    # if this is a file to read in as JSON
    elif os.path.exists(confitem) and readable_from_file == 'json':
        with open(confitem,'r') as infd:
            confitem = json.load(infd)

    # otherwise, it's not a file or it doesn't exist, return it as is
    else:
        confitem = vartype(confitem)

    return confitem


def load_config(conf_dict,
                options_object,
                envfile=None,
                basedir=None):
    '''
    This loads all the config items in config_dict.

    '''

    if not basedir:
        basedir = os.getcwd()

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

    for key in conf_dict:

        conf_item_value = get_conf_item(
            key,
            current_environment,
            options_object,
            vartype=conf_dict[key]['type'],
            default=conf_dict[key]['default'],
            options_object_attr=conf_dict[key]['cmdline'],
            readable_from_file=conf_dict[key]['readable_from_file'],
            basedir=basedir
        )
        options_object[key] = conf_item_value

    return options_object
