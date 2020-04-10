'''test_email.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Sep 2018
License: MIT. See the LICENSE file for details.

This contains tests for the emailing functions.

'''

from datetime import datetime, timedelta
from mailbox import Maildir
import ssl
import time
import textwrap

import py.path

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Mailbox
from aiosmtpd.smtp import SMTP

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from cryptography.fernet import Fernet

from authnzerver import authdb, actions
from authnzerver import tokens


# from https://github.com/aio-libs/aiosmtpd/issues/179#issuecomment-570917671
class STARTTLSController(Controller):
    def __init__(self,
                 handler,
                 factory=SMTP,
                 hostname=None,
                 port=0,
                 *,
                 ready_timeout=1.0,
                 enable_SMTPUTF8=True,
                 ssl_context=None):
        super().__init__(handler,
                         hostname=hostname,
                         port=port,
                         ready_timeout=ready_timeout,
                         enable_SMTPUTF8=enable_SMTPUTF8,
                         ssl_context=None)
        self.__factory = factory
        self.__ssl_context = ssl_context

    def factory(self):
        return self.__factory(self.handler,
                              enable_SMTPUTF8=self.enable_SMTPUTF8,
                              hostname=self.hostname,
                              tls_context=self.__ssl_context)


def get_test_authdb(tmpdir):
    '''This just makes a new test auth DB for each test function.

    '''

    if not isinstance(tmpdir, py.path.local):
        tmpdir = py.path.local(tmpdir)

    dbpath = str(tmpdir.join('test-email.authdb.sqlite'))

    authdb.create_sqlite_authdb(dbpath)
    authdb.initial_authdb_inserts('sqlite:///%s' % dbpath)

    return 'sqlite:///%s' % dbpath


def generate_cert_and_key(tmpdir):
    '''
    This generates a temporary TLS certificate for testing.

    Mostly from: https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate

    '''

    if not isinstance(tmpdir, py.path.local):
        tmpdir = py.path.local(tmpdir)

    key_file = str(tmpdir.join('email-server-key.pem'))
    cert_file = str(tmpdir.join('email-server.pem'))

    # make a new key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # write the private key
    with open(key_file, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,
                           "CA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,
                           "International Space Station"),
        x509.NameAttribute(NameOID.LOCALITY_NAME,
                           "Main Truss"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                           "Canadarm2"),
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            "https://www.asc-csa.gc.ca/eng/iss/canadarm2/default.asp"
        ),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.utcnow() + timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False,
        # Sign our certificate with our private key
    ).sign(key, hashes.SHA256(), default_backend())

    # Write our certificate out to disk.
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert_file, key_file


def generate_email_server(tmpdir):
    '''
    This starts an SMTP server in a new thread, which listens on port 2587.

    STARTTLS is enabled using a self-signed certificate.

    '''

    if not isinstance(tmpdir, py.path.local):
        tmpdir = py.path.local(tmpdir)

    cert_file, key_file = generate_cert_and_key(tmpdir)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert_file, keyfile=key_file)

    maildir = str(tmpdir.join('maildir'))

    controller = STARTTLSController(Mailbox(maildir),
                                    hostname='localhost',
                                    port=2587,
                                    ssl_context=ctx)
    return controller, maildir


##################
## ACTUAL TESTS ##
##################

def test_email_works(tmpdir):
    '''
    This is a basic test of the email server working OK.

    '''

    email_server, maildir = generate_email_server(tmpdir)
    email_server.start()
    time.sleep(3.0)

    # send a test email
    email_sent = actions.send_email(
        'test@test.org',
        'Hello',
        'this is a test',
        ['test@test.org'],
        '127.0.0.1',
        None,
        None,
        'salt',
        port=2587
    )

    assert email_sent is True

    # check if it was received
    mailbox = Maildir(maildir)

    for _, message in mailbox.items():

        if message['Subject'] == 'Hello':
            assert message['From'] == 'test@test.org'
            assert message['To'] == 'test@test.org'
            assert 'this is a test' in message.as_string()

    email_server.stop()


def test_create_user_with_email(tmpdir):
    '''
    This creates a user and tries to send a verification code to their email.

    '''

    test_authdb_url = get_test_authdb(tmpdir)

    # 0. start the email server
    email_server, maildir = generate_email_server(tmpdir)
    email_server.start()

    # 1a. create a new session
    session_payload = {
        'user_id':2,
        'user_agent':'Mozzarella Killerwhale',
        'expires':datetime.utcnow()+timedelta(hours=1),
        'ip_address': '1.1.1.1',
        'extra_info_json':{'pref_datasets_always_private':True},
        'pii_salt':'super-secret-salt',
        'reqid':1
    }
    # check creation of session
    session_token_info = actions.auth_session_new(
        session_payload,
        raiseonfail=True,
        override_authdb_path=test_authdb_url
    )

    # 1b. create a new user
    payload = {'full_name': 'Test User',
               'email':'testuser@test.org',
               'password':'aROwQin9L8nNtPTEMLXd',
               'reqid':1,
               'pii_salt':'super-secret-salt'}
    user_created = actions.create_new_user(
        payload,
        raiseonfail=True,
        override_authdb_path=test_authdb_url
    )
    assert user_created['success'] is True
    assert user_created['user_email'] == 'testuser@test.org'
    assert user_created['user_id'] == 4
    assert user_created['send_verification'] is True
    assert ('User account created. Please verify your email address to log in.'
            in user_created['messages'])

    # 2. generate a verification token and send them an email
    email_token = tokens.generate_email_token(
        session_payload['ip_address'],
        session_payload['user_agent'],
        'testuser@test.org',
        session_token_info['session_token'],
        Fernet.generate_key()
    )

    verification_email_info = actions.send_signup_verification_email(
        {'email_address':'testuser@test.org',
         'session_token':session_token_info['session_token'],
         'created_info':user_created,
         'server_name':'Authnzerver',
         'server_baseurl':'https://localhost/auth',
         'account_verify_url':'/users/verify',
         'verification_token':email_token,
         'verification_expiry':900,
         'smtp_user':None,
         'smtp_pass':None,
         'smtp_server':'localhost',
         'smtp_port':2587,
         'smtp_sender':'Authnzerver <authnzerver@test.org>',
         'reqid':1337,
         'pii_salt':'super-secret-salt'},
        raiseonfail=True,
        override_authdb_path=test_authdb_url
    )
    assert verification_email_info['success'] is True
    assert verification_email_info['email_address'] == 'testuser@test.org'

    # 3. check the mailbox to see if the email was received
    mailbox = Maildir(maildir)

    email_found = False

    for _, message in mailbox.items():

        if 'Please verify your account sign up request' in message['Subject']:

            email_found = True
            assert message['From'] == 'Authnzerver <authnzerver@test.org>'
            assert message['To'] == 'testuser@test.org'
            assert (
                '\n'.join(textwrap.wrap(email_token.decode()))
                in message.as_string()
            )

    assert email_found is True

    #
    # clean up
    #

    email_server.stop()
