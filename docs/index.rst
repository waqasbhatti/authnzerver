.. authnzerver documentation master file, created by
   sphinx-quickstart on Fri Mar 27 11:58:23 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Authnzerver
~~~~~~~~~~~

`Authnzerver <https://github.com/waqasbhatti/authnzerver>`_ is a tiny
authentication (authn) and authorization (authz) server implemented in Python
and the `Tornado <http://www.tornadoweb.org>`_ web framework.

I wrote it to help with the login/logout/signup flows for the `Light Curve
Collection Server <https://github.com/waqasbhatti/lcc-server>`_ and extracted
much of the code from there. It builds on the auth bits there and is eventually
meant to replace them. It can do the following things:

- Handle user sign-ups, logins, logouts, and locks/unlocks.

- Handle user email verification, password changes, forgotten password
  processes, and editing user properties.

- Handle API key issuance and verification.

- Handle access and rate-limit checks for arbitrary schemes of user roles,
  permissions, and target items. There is a `default scheme
  <https://github.com/waqasbhatti/authnzerver/blob/master/authnzerver/default-permissions-model.json>`_
  of permissions and user roles, originally from the LCC-Server where this code
  was extracted from. A custom permissions policy can be specified as JSON.

Authnzerver talks to a frontend server over HTTP. Communications are secured
with symmetric encryption using the `cryptography <https://cryptography.io>`_
package's `Fernet scheme <https://cryptography.io/en/latest/fernet/>`_, so
you'll need a pre-shared key that both Authnzerver and your frontend server
know.

See :doc:`the HTTP API docs <./api>` for details on how to call Authnzerver from a
frontend service.

Installation
============

Installing with pip
-------------------

Install authnzerver (preferably in a virtualenv)::

  (venv)$ pip install authnzerver


Installing the latest version from Github
-----------------------------------------

To install the latest version (may be unstable at times)::

  $ git clone https://github.com/waqasbhatti/authnzerver
  $ cd authnzerver
  $ python setup.py install
  $ # or use pip install . to install requirements automatically
  $ # or use pip install -e . to install in develop mode along with requirements

Installing the container from Docker Hub
----------------------------------------

Pull the image::

   docker pull waqasbhatti/authnzerver:latest


Using the server
================

See :doc:`the server configuration and usage docs <./running>` on how to configure the
server with environment variables or command-line options, and run it either as
a Docker container or as script executable from the Python package.

Quick start
-----------

If you have authnzerver installed as a Python package in an activated virtualenv::

    authnzrv --autosetup --basedir=$(PWD)

If you're running it as a Docker container::

    docker run -p 13431:13431 -v $(PWD):/home/authnzerver/basedir \
      --rm -it waqasbhatti/authnzerver:latest \
      --autosetup --basedir=/home/authnzerver/basedir


.. toctree::
   :maxdepth: 2
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
