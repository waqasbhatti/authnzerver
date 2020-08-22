# -*- coding: utf-8 -*-

"""This contains functions to dynamically import modules and get Python objects.

"""

#############
## LOGGING ##
#############

import logging
LOGGER = logging.getLogger(__name__)

LOGDEBUG = LOGGER.debug
LOGINFO = LOGGER.info
LOGWARNING = LOGGER.warning
LOGERROR = LOGGER.error
LOGEXCEPTION = LOGGER.exception


#############
## IMPORTS ##
#############

import sys
import importlib
import os.path


###############
## FUNCTIONS ##
###############

def module_from_string(module, force_reload=False):
    """This imports the module specified.

    Used to dynamically import Python modules.

    Parameters
    ----------

    module : str
        This is either:

        - a Python module import path, e.g. 'concurrent.futures' or
        - a path to a Python file, e.g. '~/authnzerver/authnzerver/main.py'

    force_reload : bool
        If True, will reload a previous imported module even if it's been
        previously imported. This is useful to pick up changes in Python module
        files used as program config files.

    Returns
    -------

    Python module
        This returns a Python module if it's able to successfully import it.

    Notes
    -----

    Hypens are not allowed in module filenames.

    """

    try:

        if os.path.exists(module):

            if '~' in module:
                module = os.path.expanduser(module)

            sys.path.append(os.path.dirname(module))
            module_import_path = os.path.basename(module.replace('.py', ''))

            if '-' in module_import_path or ' ' in module_import_path:
                LOGERROR("Can't import the requested module."
                         "Spaces or the character '-' are not allowed in a "
                         "Python module name. "
                         "Try using the '_' character "
                         "instead if you want spaces.")
                return False

            # check if the module has already been imported
            if module_import_path in sys.modules and force_reload:
                # get the module object
                imported_module = importlib.import_module(
                    module_import_path
                )
                # call reload on the module object
                importedok = importlib.reload(imported_module)
            else:
                importedok = importlib.import_module(
                    module_import_path
                )

        else:
            if module in sys.modules and force_reload:
                importedok = importlib.reload(module)
            else:
                importedok = importlib.import_module(module)

    except Exception:
        LOGEXCEPTION('Could not import the module: %s. '
                     'Check the file path or fully qualified module name?'
                     % (module, ))
        importedok = False

    return importedok


def object_from_string(objectpath, force_reload=False):
    """This returns a Python object pointed to by the given string.

    An object can be any valid Python object. One of the main uses for this
    function is to dynamically load Python functions from a module given its
    file path on disk or a fully qualified module string.

    The string should be in one of the forms below:

    - fully qualified module name and object name, e.g.::

        'authnzerver.confvars.CONF' -> gets the CONF dict
        'sqlalchemy.dialects.postgresql.JSONB' -> gets the JSONB class
        'scipy.ndimage.convolve' -> gets the convolve() function

    - path to a module on disk and the object name separated by '::', e.g.::

        '~/authnzerver/authnzerver/actions/user.py::create_new_user'
        '~/authzerver/authnzerver/authdb.py::Users'

      (This is similar to the format used by pytest.)

    """

    if '::' in objectpath:
        pymod, pyobject = objectpath.split('::')
    else:
        splitstr = objectpath.split('.')
        pymod, pyobject = '.'.join(splitstr[:-1]), splitstr[-1]

    imported_module = module_from_string(pymod, force_reload=force_reload)

    if imported_module is not False:
        return getattr(imported_module, pyobject)
    else:
        return None
