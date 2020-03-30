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
from functools import reduce, partial
from operator import getitem
import re

import requests

from .modtools import object_from_string


#####################################
## FILE AND URL HANDLING FUNCTIONS ##
#####################################

ENV_REGEX = re.compile(r'\[\[(\w+)\]\]')


def _dict_get(datadict, keylist):
    '''This gets a requested dict key by walking the dict.

    Parameters
    ----------

    datadict : dict
        The dict to get the specified key from.

    keylist : list of str or str
        This is a list of keys to use to walk the dict and get to the key that
        is provided as the last element in `keylist`. For example::

            keylist = ['key1','key2','key3']

        will walk `datadict` recursively to get to
        `datadict[key1][key2][key3]`. If this is provided as a string, you must
        separate the keys in the path with '.' character, e.g.::

            keylist = 'key1.key2.key3'

        To retrieve a item in the key path with a numeric index, e.g. a
        list item inside a dict, you must specify its address as
        ``'_arr_indexnum'``. For example, to get back "no" from this dict::

            get_response = {
                "secret":"very-yes",
                "testbit":{
                    "available":["maybe","yes","no"]
                }
            }

        Use the following call::

            _dict_get(get_response, "testbit.available._arr_2")

    Returns
    -------

    object
        The dict value of the specified key address.

    '''

    # convert the key list items to a list and handle str -> int conversions
    if isinstance(keylist,str):
        keylist = keylist.split('.')

    use_keylist = keylist[::]

    for ind, item in enumerate(keylist):
        if '_arr_' in item:
            arrind = item.replace('_arr_','')
            arrind = int(arrind)
            use_keylist[ind] = arrind

    return reduce(getitem, use_keylist, datadict)


def item_from_file(file_path,
                   file_spec,
                   basedir=None):
    '''Reads a conf item from a file.

    Parameters
    ----------

    file_path : str
        The file to open. Here you can use the following substitutions as
        necessary:

        - ``[[homedir]]``: points to the home directory of the user running the
          server.

        - ``[[basedir]]``: points to the base directory of the server.

    file_spec : str or tuple
        This specifies how to read the conf item from the file:

        - ``'string'``: read a file and use the resulting string as the value of
          the config item. The trailing ``\\n`` character will be stripped. This
          is useful for simple text secret keys stored in a file on disk, etc.

        - ``'json'``: read the entire file as JSON and return the loaded dict as
          the value of the config item.

        - ``('json','path.to.item.or.listitem._arr_0')``: read the entire file
          as JSON, resolve the JSON object path pointed to by the second tuple
          element, get the value there and return it as the value of the config
          item.

    basedir : str or None
        The base directory of the server. If None, the current working directory
        is used.

    Returns
    -------

    conf_value : Any
        Returns the value of the conf item. The calling function is
        responsible for casting to the correct type.

    '''

    # handle special substitutions
    if '[[basedir]]' in file_path:
        file_to_load = file_path.replace('[[basedir]]',basedir)
    elif '[[homedir]]' in file_path:
        file_to_load = file_path.replace(
            '[[homedir]]',
            os.path.abspath(os.path.expanduser('~'))
        )
    else:
        file_to_load = file_path

    file_to_load = os.path.abspath(file_to_load)

    if not os.path.exists(file_to_load):

        LOGGER.error("Requested conf item cannot be loaded because "
                     "the file path doesn't exist.")
        return None

    #
    # now deal with the spec
    #

    # string load
    if isinstance(file_spec, str) and file_spec == 'string':

        with open(file_to_load,'r') as infd:
            conf_item = infd.read().strip('\n')

        return conf_item

    # JSON load entire file
    elif isinstance(file_spec, str) and file_spec == 'json':

        with open(file_to_load,'r') as infd:
            conf_item = json.load(infd)

        return conf_item

    elif isinstance(file_spec, tuple) and file_spec[0] == 'json':

        item_path = file_spec[-1]
        item_path = item_path.split('.')

        with open(file_to_load,'r') as infd:
            conf_dict = json.load(infd)
            conf_item = _dict_get(conf_dict, item_path)

        return conf_item

    else:

        LOGGER.error("Unknown file_spec provided, can't handle it.")
        return None


def item_from_url(url,
                  url_spec,
                  environment,
                  timeout=5.0):
    '''Reads a conf item from a URL.

    Parameters
    ----------

    url : str
        The URL to fetch.

    url_spec : tuple
        This specifies how to get the conf item from the URL:

        - ``('http',{method dict},'string')``: HTTP GET/POST the URL pointed to
          by the config item key, assume the value returned is plain-text and
          return it as the value of the config item. This can be useful for
          things stored in AWS/GCP metadata servers.

        - ``('http',{method dict},'json')``: HTTP GET/POST the URL pointed to by
          the config item key, load it as JSON, and return the loaded dict as
          the value of the config item.

        - ``('http',{method dict},'json','path.to.item.or.listitem._arr_0')``:
          HTTP GET the URL pointed to by the config key, load it as JSON,
          resolve the JSON object path pointed to by the fourth element of the
          tuple, get the value there and return it as the value of the config
          item.

        The ``{method dict}`` is a dict of the following form::

            {'method':'post' or 'get',
             'headers':dict of header keys and values to send or None,
             'data':data dict to attach to the POST request or param dict to
                    attach to the GET request or None,
             'timeout': time in seconds to wait for a response}

        Using the method dict allows you to add in authentication headers and
        data needed to gain access to the URL indicated by the config item key.

        If an item in the 'headers' or 'data' dicts requires something from an
        environment variable or .env file, indicate this by using ``'[[NAME OF
        ENV VAR]]'`` in the value of that key. For example, to get a bearer
        token to use in the 'Authorization' header::

            method_dict['headers'] = {'Authorization': 'Bearer [[API_KEY]]'}

        This will look up the environment variable 'API_KEY' and substitute
        that value in.

    environment : environment object or ConfigParser object
        This is an object similar to that obtained from ``os.environ`` or a
        similar ConfigParser object.

    timeout : int or float
        The default timeout in seconds to use for the HTTP request if one is not
        provided in the method dict in ``url_spec``.

    Returns
    -------

    conf_value : Any
        Returns the value of the conf item. The calling function is
        responsible for casting to the correct type.

    '''

    if not isinstance(url_spec, tuple):
        LOGGER.error("Invalid URL spec provided for conf item.")
        return None

    if url_spec[0] != 'http':
        LOGGER.error("Invalid URL spec provided for conf item.")
        return None

    if not isinstance(url_spec[1], dict):
        LOGGER.error("No HTTP request parameters provided for conf item.")
        return None

    request_options = url_spec[1]
    item_type = url_spec[2]
    if item_type == 'json' and len(url_spec) == 4:
        item_path = url_spec[3]
    else:
        item_path = None

    for key in ('method', 'headers', 'data'):
        if key not in request_options:
            LOGGER.error("Missing '%s' key in HTTP request parameters.")
            return None

    #
    # handle environment var substitutions in request_options 'headers' or
    # 'data'
    #
    if isinstance(request_options['headers'], dict):
        for key in request_options['headers']:

            val = request_options['headers'][key]
            env_items = ENV_REGEX.findall(val)

            for item in env_items:
                val = val.replace('[[%s]]' % item, environment.get(item, ''))

            request_options['headers'][key] = val

    if isinstance(request_options['data'], dict):
        for key in request_options['data']:

            val = request_options['data'][key]
            env_items = ENV_REGEX.findall(val)

            for item in env_items:
                val = val.replace('[[%s]]' % item, environment.get(item, ''))

            request_options['data'][key] = val

    #
    # now process the request
    #

    req_timeout = request_options.get('timeout', timeout)

    if request_options['method'] == 'post':

        req = requests.post

        # add in the headers and data
        req_func = partial(
            req,
            headers=request_options['headers'],
            data=request_options['data'],
            timeout=req_timeout
        )

    else:

        req = requests.get

        # add in the headers and data
        req_func = partial(
            req,
            headers=request_options['headers'],
            params=request_options['data'],
            timeout=req_timeout,
        )

    #
    # fire the request and deal with the response
    #

    try:

        resp = req_func(url)
        resp.raise_for_status()

        if item_type == 'string':
            conf_item = resp.text.rstrip('\n')

        elif item_type == 'json' and item_path is None:
            conf_item = resp.json()

        elif item_type == 'json' and item_path is not None:

            conf_dict = resp.json()
            conf_item = _dict_get(conf_dict, item_path.split('.'))

        else:
            LOGGER.error("Unknown item type provided.")
            conf_item = None

    except Exception:

        LOGGER.error("Failed to retrieve config "
                     "item value from URL.")
        conf_item = None

    finally:

        try:
            resp.close()
        except UnboundLocalError:
            pass

    return conf_item


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
                  postprocess_value=None,
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

    readable_from_file : {'json','string', others, see below} or False
        If this is specified, and the conf item key (env_key or options_key
        above) is a valid filename or URL, will open it and read it in, cast to
        the specified variable type, and return the item. If this is set to
        False, will treat the config item pointed to by the key as a plaintext
        item and return it directly.

        There are several readable_from_file options. The first two below are
        strings, the rest are tuples.

        - ``'string'``: read a file and use the resulting string as the value of
          the config item. The trailing ``\\n`` character will be stripped. This
          is useful for simple text secret keys stored in a file on disk, etc.

        - ``'json'``: read the entire file as JSON and return the loaded dict as
          the value of the config item.

        - ``('json','path.to.item.or.listitem._arr_0')``: read the entire file
          as JSON, resolve the JSON object path pointed to by the second tuple
          element, get the value there and return it as the value of the config
          item.

        - ``('http',{method dict},'string')``: HTTP GET/POST the URL pointed to
          by the config item key, assume the value returned is plain-text and
          return it as the value of the config item. This can be useful for
          things stored in AWS/GCP metadata servers.

        - ``('http',{method dict},'json')``: HTTP GET/POST the URL pointed to by
          the config item key, load it as JSON, and return the loaded dict as
          the value of the config item.

        - ``('http',{method dict},'json','path.to.item.or.listitem._arr_0')``:
          HTTP GET the URL pointed to by the config key, load it as JSON,
          resolve the JSON object path pointed to by the fourth element of the
          tuple, get the value there and return it as the value of the config
          item.

        The ``{method dict}`` is a dict of the following form::

            {'method':'post' or 'get',
             'headers':dict of header keys and values to send or None,
             'data':data dict to attach to the POST request or param dict to
                    attach to the GET request or None,
             'timeout': time in seconds to wait for a response}

        Using the method dict allows you to add in authentication headers and
        data needed to gain access to the URL indicated by the config item key.

        If an item in the 'headers' or 'data' dicts requires something from an
        environment variable or .env file, indicate this by using ``'[[NAME OF
        ENV VAR]]'`` in the value of that key. For example, to get a bearer
        token to use in the 'Authorization' header::

            method_dict['headers'] = {'Authorization': 'Bearer [[API_KEY]]'}

        This will look up the environment variable 'API_KEY' and substitute
        that value in.

    postprocess_value : str
        This is a string pointing to a Python function to apply to the config
        item that was retrieved. The function must take one argument and return
        one item. The function is specified as either a fully qualified Python
        module name and function name, e.g.::

            'base64.b64decode'

        or a path to a Python module on disk and the function name separated by
        '::' ::

            '~/some/directory/mymodule.py::custom_b64decode'

    raiseonfail : bool
        If this is set to True, the function will raise a ValueError for any
        missing config items that can't be set from the environment, the envfile
        or the command-line options. If this is set to False, the function won't
        immediately raise an exception, but will return None. This latter
        behavior is useful for indicating which configuration items are missing
        (e.g. when a server is being started for the first time.)

    basedir : str
        The directory where the server will do its work. This is used to fill in
        ``'[[basedir]]'`` template values in any conf item. By default, this is
        the current working directory.

    Returns
    -------

    Any
        The value of the configuration item.

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

        #
        # check if the confitem points to a file that exists
        #
        if isinstance(confitem, str):

            if '[[basedir]]' in confitem:
                file_check = confitem.replace('[[basedir]]',basedir)
            elif '[[homedir]]' in confitem:
                file_check = confitem.replace(
                    '[[homedir]]',
                    os.path.abspath(os.path.expanduser('~'))
                )
            else:
                file_check = confitem

            file_check = os.path.exists(os.path.abspath(file_check))

        else:

            file_check = False

        #
        # handle all the cases
        #
        if (file_check and isinstance(readable_from_file, str) and
            readable_from_file == 'string'):

            confitem = item_from_file(confitem,
                                      readable_from_file,
                                      basedir=basedir)

            # check if the confitem isn't None because of a failure
            if confitem is None and raiseonfail:
                raise ValueError(
                    'Config item: "%s" is invalid/missing, '
                    'could not retrieve from default file.' % env_key
                )

            confitem = vartype(confitem)

        elif (file_check and isinstance(readable_from_file, str) and
              readable_from_file == 'json'):

            confitem = item_from_file(confitem,
                                      readable_from_file,
                                      basedir=basedir)

            # check if the confitem isn't None because of a failure
            if confitem is None and raiseonfail:
                raise ValueError(
                    'Config item: "%s" is invalid/missing, '
                    'could not retrieve from default file.' % env_key
                )

        elif (file_check and isinstance(readable_from_file, tuple) and
              readable_from_file[0] == 'json'):

            confitem = item_from_file(confitem,
                                      readable_from_file,
                                      basedir=basedir)

            # check if the confitem isn't None because of a failure
            if confitem is None and raiseonfail:
                raise ValueError(
                    'Config item: "%s" is invalid/missing, '
                    'could not retrieve from default file.' % env_key
                )

        elif (isinstance(confitem, str) and
              confitem.startswith('http') and
              isinstance(readable_from_file, tuple) and
              readable_from_file[0] == 'http'):

            confitem = item_from_url(confitem,
                                     readable_from_file,
                                     environment)

            # check if the confitem isn't None because of a failure
            if confitem is None and raiseonfail:
                raise ValueError(
                    'Config item: "%s" is invalid/missing, '
                    'could not retrieve from default URL.' % env_key
                )

        # otherwise, it's not a file or it doesn't exist, return it as is
        # NOTE: no casting done here to preserve whatever type default was
        # NOTE: e.g., this allows us to use a a dict as a default

        # handle any postprocessing
        if isinstance(postprocess_value,str):
            postproc_func = object_from_string(postprocess_value)
            if postproc_func is not None:
                confitem = postproc_func(confitem)

        return confitem

    #
    # otherwise, if the conf item exists, return its appropriate value
    #

    #
    # check if the confitem points to a file that exists
    #
    if isinstance(confitem, str):

        if '[[basedir]]' in confitem:
            file_check = confitem.replace('[[basedir]]',basedir)
        elif '[[homedir]]' in confitem:
            file_check = confitem.replace(
                '[[homedir]]',
                os.path.abspath(os.path.expanduser('~'))
            )
        else:
            file_check = confitem

        file_check = os.path.exists(os.path.abspath(file_check))

    else:

        file_check = False

    #
    # handle all the cases
    #
    if (file_check and isinstance(readable_from_file, str) and
        readable_from_file == 'string'):

        confitem = item_from_file(confitem,
                                  readable_from_file,
                                  basedir=basedir)

        # check if the confitem isn't None because of a failure
        if confitem is None and raiseonfail:
            raise ValueError(
                'Config item: "%s" is invalid/missing, '
                'could not retrieve from provided file.' % env_key
            )

    elif (file_check and isinstance(readable_from_file, str) and
          readable_from_file == 'json'):

        confitem = item_from_file(confitem,
                                  readable_from_file,
                                  basedir=basedir)

        # check if the confitem isn't None because of a failure
        if confitem is None and raiseonfail:
            raise ValueError(
                'Config item: "%s" is invalid/missing, '
                'could not retrieve from provided file.' % env_key
            )

    elif (file_check and isinstance(readable_from_file, tuple) and
          readable_from_file[0] == 'json'):

        confitem = item_from_file(confitem,
                                  readable_from_file,
                                  basedir=basedir)

        # check if the confitem isn't None because of a failure
        if confitem is None and raiseonfail:
            raise ValueError(
                'Config item: "%s" is invalid/missing, '
                'could not retrieve from provided file.' % env_key
            )

    elif (isinstance(confitem, str) and
          confitem.startswith('http') and
          isinstance(readable_from_file, tuple) and
          readable_from_file[0] == 'http'):

        confitem = item_from_url(confitem,
                                 readable_from_file,
                                 environment)

        # check if the confitem isn't None because of a failure
        if confitem is None and raiseonfail:
            raise ValueError(
                'Config item: "%s" is invalid/missing, '
                'could not retrieve from provided URL.' % env_key
            )

    # otherwise, it's not a file or it doesn't exist, return it and cast to the
    # appropriate type
    else:
        confitem = vartype(confitem)

    # handle any postprocessing
    if isinstance(postprocess_value,str):
        postproc_func = object_from_string(postprocess_value)
        if postproc_func is not None:
            confitem = postproc_func(confitem)

    return confitem


def load_config(conf_dict,
                options_object,
                envfile=None):
    '''Loads all the config items in config_dict.

    Parameters
    ----------

    conf_dict : dict
        This is a dict containing information on each config item to load and
        return. Each key in this dict serves as the name of the config item and
        the value for each key is a dict of the following form::

            'conf_item_name':{
                'env':'The environmental variable to check',
                'cmdline':'The command-line option to check',
                'type':the Python type of the config item,
                'default':a default value for the config item or None,
                'help':'The help string to use for the command-line option',
                'readable_from_file':how to retrieve the item (see below),
                'postprocess_value': 'func to postprocess the item (see below)',
            },

        The ``'readable_from_file'`` key in each config item's dict indicates
        how the value present in either the environment variable or the
        command-line option will be used to retrieve the config item. This is
        one of the following:

        - ``'string'``: read a file and use the resulting string as the value of
          the config item. The trailing ``\\n`` character will be stripped. This
          is useful for simple text secret keys stored in a file on disk, etc.

        - ``'json'``: read the entire file as JSON and return the loaded dict as
          the value of the config item.

        - ``('json','path.to.item.or.listitem._arr_0')``: read the entire file
          as JSON, resolve the JSON object path pointed to by the second tuple
          element, get the value there and return it as the value of the config
          item.

        - ``('http',{method dict},'string')``: HTTP GET/POST the URL pointed to
          by the config item key, assume the value returned is plain-text and
          return it as the value of the config item. This can be useful for
          things stored in AWS/GCP metadata servers.

        - ``('http',{method dict},'json')``: HTTP GET/POST the URL pointed to by
          the config item key, load it as JSON, and return the loaded dict as
          the value of the config item.

        - ``('http',{method dict},'json','path.to.item.or.listitem._arr_0')``:
          HTTP GET the URL pointed to by the config key, load it as JSON,
          resolve the JSON object path pointed to by the fourth element of the
          tuple, get the value there and return it as the value of the config
          item.

        The ``{method dict}`` is a dict of the following form::

            {'method':'post' or 'get',
             'headers':dict of header keys and values to send or None,
             'data':data dict to attach to the POST request or param dict to
                    attach to the GET request or None,
             'timeout': time in seconds to wait for a response}

        Using the method dict allows you to add in authentication headers and
        data needed to gain access to the URL indicated by the config item key.

        If an item in the 'headers' or 'data' dicts requires something from an
        environment variable or .env file, indicate this by using ``'[[NAME OF
        ENV VAR]]'`` in the value of that key. For example, to get a bearer
        token to use in the 'Authorization' header::

            method_dict['headers'] = {'Authorization': 'Bearer [[API_KEY]]'}

        This will look up the environment variable 'API_KEY' and substitute
        that value in.

        The ``'postprocess_value'`` key in each config item's dict is used to
        point to a Python function to post-process the config item after it has
        been retrieved. The function must take one argument and return
        one item. The function is specified as either a fully qualified Python
        module name and function name, e.g.::

            'base64.b64decode'

        or a path to a Python module on disk and the function name separated by
        '::' ::

            '~/some/directory/mymodule.py::custom_b64decode'

    options_object : Tornado options object
        If the environment variable isn't defined for a config item, the next
        place this function will try to get the item value from a passed-in
        `Tornado options <http://www.tornadoweb.org/en/stable/options.html>`_
        object, which parses command-line options.

    envfile : str or None
        The path to a file containing key=value pairs in the same manner as
        environment variables. This serves as an override to any environment
        variables that this function looks up to find config items.

    Returns
    -------

    loaded_config : SimpleNamespace object
        This returns an object with the parsed final values of each of the
        config items as object attributes.

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
            postprocess_value=conf_dict[key]['postprocess_value'],
            basedir=basedir
        )
        setattr(loaded_options, key, conf_item_value)

    return loaded_options
