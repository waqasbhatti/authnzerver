# authnzerver v0.1.3 - 2020-03-30

## New stuff

- Email addresses for user sign-up are now checked against a list of disposable
  email provider domains.
- Configuration variables can be now retrieved from a variety of sources: from
  an environment variable, from a file, or from an HTTP request. The method of
  retrieval is now customizable by editing the `confvars.py` file copied to the
  server's base directory after `authnzrv --autosetup` is run.
- The `default-permissions-model.json` file is now copied to the server's base
  directory when `authnzrv --autosetup` is run for easier customization of the
  permissions policy.

## Changes

- The server now checks if the user's password needs to be rehashed when they
  sign-in. This should enable automatic upgrades of the Argon2 parameters as
  required.

## Fixes

- If a configuration variable is None after retrieval from a source, the server
  now halts start-up instead of continuing with that value.


# authnzerver v0.1.2 - 2020-03-27

## New stuff

- Added Sphinx generated autodocs for modules:
  https://authnzerver.readthedocs.io/en/latest/.


# authnzerver v0.1.1 - 2020-03-27

## Fixes

- Various minor documentation fixes.


# authnzerver v0.1.0 - 2020-03-26

This is the initial release.
