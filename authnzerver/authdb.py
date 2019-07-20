#!/usr/bin/env python
# -*- coding: utf-8 -*-
# authdb.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""
This contains SQLAlchemy models for the authnzerver.

"""

import os.path
import os
import stat
from datetime import datetime
import sqlite3
import secrets
import getpass
import uuid

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy import event
from sqlalchemy import (
    Table, Column, Integer, String, Text,
    Boolean, DateTime, ForeignKey, MetaData
)

from argon2 import PasswordHasher


##########################
## JSON type for SQLite ##
##########################

# taken from:
# docs.sqlalchemy.org/en/latest/core/custom_types.html#marshal-json-strings

from sqlalchemy.types import TypeDecorator, TEXT
import json


class JSONEncodedDict(TypeDecorator):
    """Represents an immutable structure as a json-encoded string.

    Usage::

        JSONEncodedDict(255)

    """

    impl = TEXT

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)

        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value


########################
## AUTHNZERVER TABLES ##
########################

AUTHDB_META = MetaData()


# This lists all possible roles in the system
Roles = Table(
    'roles',
    AUTHDB_META,
    Column('name', String(length=100), primary_key=True, nullable=False),
    Column('desc', String(length=280), nullable=False)
)


# This is the sessions table storing client sessions
Sessions = Table(
    'sessions',
    AUTHDB_META,
    Column('session_token',String(), primary_key=True),
    Column('ip_address', String(length=280), nullable=False),
    # some annoying people send zero-length client-headers
    # we won't allow them to initiate a session
    Column('user_agent', String(length=280), nullable=False),
    Column('user_id', Integer, ForeignKey("users.user_id", ondelete="CASCADE"),
           nullable=False),
    Column('created', DateTime(),
           default=datetime.utcnow,
           nullable=False, index=True),
    Column('expires', DateTime(), nullable=False, index=True),
    Column('extra_info_json', JSONEncodedDict()),
)


# This is the main users table
Users = Table(
    'users',
    AUTHDB_META,

    # The primary key of this table. Should NOT be made public, not even to the
    # frontend. Primary use for this is as a foreign key to other tables.
    Column('user_id', Integer(), primary_key=True, nullable=False),

    # This is the system ID to expose to JS frontends, etc and is a UUID4. We
    # try to never expose the user_id pk to avoid user enumeration. The
    # system_id is also used for autocompletes on the frontend to map to
    # full_name if a user indicates their name can be public or is shared in a
    # group.
    Column('system_id', String(length=50), index=True, nullable=False),

    # This is what the user calls themselves, freeform. Never exposed to other
    # users unless we have explicit permission.
    Column('full_name', String(length=280), index=True),

    Column('password', Text(), nullable=False),
    Column('email', String(length=280), nullable=False, unique=True),
    Column('email_verified',Boolean(), default=False,
           nullable=False, index=True),
    Column('is_active', Boolean(), default=False, nullable=False, index=True),

    # these track when we last sent emails to this user
    Column('emailverify_sent_datetime', DateTime()),
    Column('emailforgotpass_sent_datetime', DateTime()),
    Column('emailchangepass_sent_datetime', DateTime()),

    # these two are separated so we can enforce a rate-limit on login tries
    Column('last_login_success', DateTime(), index=True),
    Column('last_login_try', DateTime(), index=True),

    # this is reset everytime a user logs in sucessfully. this is used to check
    # the number of failed tries since the last successful try. FIXME: can we
    # use this for throttling login attempts without leaking info?
    Column('failed_login_tries', Integer(), default=0),

    Column('created_on', DateTime(),
           default=datetime.utcnow,
           nullable=False,index=True),
    Column('last_updated', DateTime(),
           onupdate=datetime.utcnow,
           nullable=False,index=True),
    Column('user_role', String(length=100),
           ForeignKey("roles.name"),
           nullable=False, index=True)
)


# this is the groups table
# groups can only be created by authenticated users and above
Groups = Table(
    'groups', AUTHDB_META,
    Column('group_id', Integer, primary_key=True),
    Column('group_name',String(length=280), nullable=False),
    Column('visibility',String(length=100), nullable=False,
           default='public', index=True),
    Column('created_by', Integer, ForeignKey("users.user_id"),
           nullable=False),
    Column('is_active', Boolean(), default=False,
           nullable=False, index=True),
    Column('created_on', DateTime(),
           default=datetime.utcnow,
           nullable=False,index=True),
    Column('last_updated', DateTime(),
           onupdate=datetime.utcnow,
           nullable=False,index=True),
    Column('user_role', String(length=100),
           ForeignKey("roles.name"),
           nullable=False, index=True)
)


# user preferences - fairly freeform to allow extension
Preferences = Table(
    'preferences', AUTHDB_META,
    Column('pref_id', Integer, primary_key=True),
    Column('user_id', Integer,
           ForeignKey("users.user_id", ondelete="CASCADE"),
           nullable=False),
    Column('pref_name', String(length=100), nullable=False),
    Column('pref_value', String(length=280))
)


# API keys that are in use
# FIXME: should API keys be deleted via CASCADE when the sessions are deleted?
APIKeys = Table(
    'apikeys',
    AUTHDB_META,
    Column('apikey', Text(), primary_key=True, nullable=False),
    Column('issued', DateTime(), nullable=False, default=datetime.utcnow),
    Column('expires', DateTime(), index=True, nullable=False),
    Column('not_valid_before', DateTime(), index=True, nullable=False),
    Column('user_id', Integer(),
           ForeignKey('users.user_id', ondelete="CASCADE"),
           nullable=False),
    Column('user_role', Integer(),
           ForeignKey('roles.name', ondelete="CASCADE"),
           nullable=False),
    Column('session_token', Text(),
           ForeignKey('sessions.session_token', ondelete="CASCADE"),
           nullable=False)
)


#######################
## UTILITY FUNCTIONS ##
#######################

WAL_MODE_SCRIPT = '''\
pragma journal_mode=WAL;
pragma journal_size_limit=5242880;
'''


def create_sqlite_auth_db(
        auth_db_path,
        echo=False,
        returnconn=False
):
    """
    This creates the local SQLite auth DB.

    """

    engine = create_engine('sqlite:///%s' % os.path.abspath(auth_db_path),
                           echo=echo)
    AUTHDB_META.create_all(engine)

    if returnconn:
        return engine, AUTHDB_META
    else:
        engine.dispose()
        del engine

    # at the end, we'll switch the auth DB to WAL mode to make it handle
    # concurrent operations a bit better
    db = sqlite3.connect(auth_db_path)
    cur = db.cursor()
    cur.executescript(WAL_MODE_SCRIPT)
    db.commit()
    db.close()

    # set the permissions on the file appropriately
    os.chmod(auth_db_path, 0o100600)


def create_authdb(authdb_url,
                  echo=False,
                  returnconn=False):
    """
    This creates an authentication database for an arbitrary SQLAlchemy DB URL.

    """

    engine = create_engine(authdb_url, echo=echo)
    AUTHDB_META.create_all(engine)

    if returnconn:
        return engine, AUTHDB_META
    else:
        engine.dispose()
        del engine


def get_auth_db(auth_db_path, echo=False):
    """
    This just gets a connection to the auth DB.

    """

    # if this is an SQLite DB, make sure to check the auth DB permissions before
    # we load it so we can be sure no one else messes with it
    potential_file_path = auth_db_path.replace('sqlite:///','')

    if os.path.exists(potential_file_path):

        fileperm = oct(os.stat(potential_file_path)[stat.ST_MODE])

        if not (fileperm == '0100600' or fileperm == '0o100600'):
            raise IOError('incorrect permissions on auth DB, will not load it')

        @event.listens_for(Engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    engine = create_engine(auth_db_path, echo=echo)
    AUTHDB_META.bind = engine
    conn = engine.connect()

    return engine, conn, AUTHDB_META


def initial_authdb_inserts(auth_db_path,
                           superuser_email=None,
                           superuser_pass=None,
                           echo=False):
    """
    This does initial set up of the auth DB.

    - adds an anonymous user
    - adds a superuser with:
      -  userid = UNIX userid
      - password = random 16 bytes)
    - sets up the initial permissions table

    Returns the superuser userid and password.

    """

    engine, conn, meta = get_auth_db(auth_db_path,
                                     echo=echo)

    # get the roles table and fill it in
    roles = meta.tables['roles']
    res = conn.execute(roles.insert(),[
        {'name': 'superuser',
         'desc': 'Accounts that can do anything.'},
        {'name': 'staff',
         'desc': 'Users with basic admin privileges.'},
        {'name': 'authenticated',
         'desc': 'Logged in regular users.'},
        {'name': 'anonymous',
         'desc': 'The anonymous user role.'},
        {'name': 'locked',
         'desc': 'An account that has been disabled.'},
    ])
    res.close()

    # get the users table
    users = meta.tables['users']

    # make the superuser account
    if not superuser_email:
        try:
            superuser_email = '%s@localhost' % getpass.getuser()
        except Exception:
            superuser_email = 'admin@localhost'

    if not superuser_pass:
        superuser_pass = secrets.token_urlsafe(16)
        superuser_pass_auto = True
    else:
        superuser_pass_auto = False

    hasher = PasswordHasher()

    hashed_password = hasher.hash(superuser_pass)

    result = conn.execute(
        users.insert().values([
            # the superuser
            {'password': hashed_password,
             'email': superuser_email,
             'system_id':str(uuid.uuid4()),
             'email_verified': True,
             'is_active': True,
             'user_role': 'superuser',
             'created_on': datetime.utcnow(),
             'last_updated': datetime.utcnow()},
            # the anonuser
            {'password': hasher.hash(secrets.token_urlsafe(32)),
             'email': 'anonuser@localhost',
             'system_id':str(uuid.uuid4()),
             'email_verified': True,
             'is_active': True,
             'user_role': 'anonymous',
             'created_on': datetime.utcnow(),
             'last_updated': datetime.utcnow()},
            # the dummyuser to fail passwords for nonexistent users against
            {'password': hasher.hash(secrets.token_urlsafe(32)),
             'email': 'dummyuser@localhost',
             'system_id':str(uuid.uuid4()),
             'email_verified': True,
             'is_active': False,
             'user_role': 'locked',
             'created_on': datetime.utcnow(),
             'last_updated': datetime.utcnow()},
        ])
    )
    result.close()

    if superuser_pass_auto:
        return superuser_email, superuser_pass
    else:
        return superuser_email, None
