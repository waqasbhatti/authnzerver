.. authnzerver documentation master file, created by
   sphinx-quickstart on Fri Mar 27 11:58:23 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Authnzerver
~~~~~~~~~~~

Authnzerver is a tiny authentication (authn) and authorization (authz) server
implemented in Python and the Tornado web framework.

This documentation is a work in progress.

Installation
============

Requirements
------------

This package requires the following other packages:

- tornado>=5.1
- cryptography>=2.3
- SQLAlchemy>=1.2.11
- argon2-cffi>=18.3.0
- diskcache>=3.0.6
- uvloop>=0.11.0
- confusable_homoglyphs>=3.2.0
- requests>=2.22


Installing with pip
-------------------

Install authnzerver (preferably in a virtualenv)::

  (venv)$ pip install authnzerver


Other installation methods
--------------------------

To install the latest version (may be unstable at times)::

  $ git clone https://github.com/waqasbhatti/authnzerver
  $ cd authnzerver
  $ python setup.py install
  $ # or use pip install . to install requirements automatically
  $ # or use pip install -e . to install in develop mode along with requirements

.. toctree::
   :maxdepth: 3
   :caption: Documentation

   running
   permissions
   api
   Python modules <modules>


Changelog and TODO
==================

Please see `CHANGELOG.md in the Github repository
<https://github.com/waqasbhatti/authnzerver/blob/master/CHANGELOG.md>`_ for the
latest changelog for tagged versions.

Similarly, please see `TODO.md in the Github repository
<https://github.com/waqasbhatti/authnzerver/blob/master/docs/TODO.md>`_ for
items being worked on or in the pipeline for future versions.


License
=======

Authnzerver is provided under the MIT License. See the `LICENSE file
<https://github.com/waqasbhatti/authnzerver/blob/master/LICENSE>`_ for the full
text.


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
