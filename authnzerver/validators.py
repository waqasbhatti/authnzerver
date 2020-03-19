# -*- coding: utf-8 -*-
"""This module contains validation functions taken from the James Bennett's
excellent `django-registration
<https://github.com/ubernostrum/django-registration>`_ package. I've modified it
a bit so the validators don't need Django to work. The original docstring and
the BSD License for that package are reproduced immediately below.

Copyright (c) 2007-2018, James Bennett
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.
    * Neither the name of the author nor the names of other
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Error messages, data and custom validation code used in
django-registration's various user-registration form classes.

"""

#############
## LOGGING ##
#############

import logging

# get a logger
LOGGER = logging.getLogger(__name__)


#############
## IMPORTS ##
#############

import unicodedata
import re
import os.path

from confusable_homoglyphs import confusables


####################
## RESERVED NAMES ##
####################

# Below we construct a large but non-exhaustive list of names which
# users probably should not be able to register with, due to various
# risks:
#
# * For a site which creates email addresses from username, important
#   common addresses must be reserved.
#
# * For a site which creates subdomains from usernames, important
#   common hostnames/domain names must be reserved.
#
# * For a site which uses the username to generate a URL to the user's
#   profile, common well-known filenames must be reserved.
#
# etc., etc.
#
# Credit for basic idea and most of the list to Geoffrey Thomas's blog
# post about names to reserve:
# https://ldpreload.com/blog/names-to-reserve
SPECIAL_HOSTNAMES = [
    # Hostnames with special/reserved meaning.
    'autoconfig',     # Thunderbird autoconfig
    'autodiscover',   # MS Outlook/Exchange autoconfig
    'broadcasthost',  # Network broadcast hostname
    'isatap',         # IPv6 tunnel autodiscovery
    'localdomain',    # Loopback
    'localhost',      # Loopback
    'wpad',           # Proxy autodiscovery
]


PROTOCOL_HOSTNAMES = [
    # Common protocol hostnames.
    'ftp',
    'imap',
    'mail',
    'news',
    'pop',
    'pop3',
    'smtp',
    'usenet',
    'uucp',
    'webmail',
    'www',
]


CA_ADDRESSES = [
    # Email addresses known used by certificate authorities during
    # verification.
    'admin',
    'administrator',
    'hostmaster',
    'info',
    'is',
    'it',
    'mis',
    'postmaster',
    'root',
    'ssladmin',
    'ssladministrator',
    'sslwebmaster',
    'sysadmin',
    'webmaster',
]


RFC_2142 = [
    # RFC-2142-defined names not already covered.
    'abuse',
    'marketing',
    'noc',
    'sales',
    'security',
    'support',
]


NOREPLY_ADDRESSES = [
    # Common no-reply email addresses.
    'mailer-daemon',
    'nobody',
    'noreply',
    'no-reply',
]


SENSITIVE_FILENAMES = [
    # Sensitive filenames.
    'clientaccesspolicy.xml',  # Silverlight cross-domain policy file.
    'crossdomain.xml',         # Flash cross-domain policy file.
    'favicon.ico',
    'humans.txt',
    'keybase.txt',  # Keybase ownership-verification URL.
    'robots.txt',
    '.htaccess',
    '.htpasswd',
]


OTHER_SENSITIVE_NAMES = [
    # Other names which could be problems depending on URL/subdomain
    # structure.
    'account',
    'accounts',
    'auth',
    'authorize',
    'blog',
    'buy',
    'cart',
    'clients',
    'contact',
    'contactus',
    'contact-us',
    'copyright',
    'dashboard',
    'doc',
    'docs',
    'download',
    'downloads',
    'enquiry',
    'faq',
    'help',
    'inquiry',
    'license',
    'login',
    'logout',
    'me',
    'myaccount',
    'oauth',
    'pay',
    'payment',
    'payments',
    'plans',
    'portfolio',
    'preferences',
    'pricing',
    'privacy',
    'profile',
    'register',
    'secure',
    'settings',
    'signin',
    'signup',
    'ssl',
    'status',
    'store',
    'subscribe',
    'terms',
    'tos',
    'user',
    'users',
    'weblog',
    'work',
]


DEFAULT_RESERVED_NAMES = set(
    SPECIAL_HOSTNAMES + PROTOCOL_HOSTNAMES + CA_ADDRESSES + RFC_2142 +
    NOREPLY_ADDRESSES + SENSITIVE_FILENAMES + OTHER_SENSITIVE_NAMES
)

MOD_DIR = os.path.dirname(__file__)
TENK_PASSWORDS_FILE = os.path.abspath(
    os.path.join(MOD_DIR,
                 'top-10k-passwords.txt')
)
with open(TENK_PASSWORDS_FILE,'r') as infd:
    TOP_10K_PASSWORDS = {x.strip('\n') for x in infd.readlines()}


###############
## FUNCTIONS ##
###############

def validate_reserved_name(value):
    '''
    This validates if the value is not one of the reserved names.

    '''

    if (value in DEFAULT_RESERVED_NAMES or
        '.well-known' in value):

        return False

    else:

        return True


def validate_confusables(value):
    '''
    This validates if the value is not a confusable homoglyph.

    '''

    if confusables.is_dangerous(value):
        return False

    else:
        return True


def validate_email_address(emailaddr):
    '''This validates an email address using the HTML5 specification,
    which is good enough for most purposes.

    The regex is taken from here:

    http://blog.gerv.net/2011/05/html5_email_address_regexp/

    And was transformed to Python using the excellent https://regex101.com.

    '''

    match_regex = (
        r"^[a-zA-Z0-9.!#$%&’*+\/=?^_`{|}~-]+@"
        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,253}[a-zA-Z0-9])"
        r"?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,253}[a-zA-Z0-9])?)*$"
    )
    return re.match(match_regex, emailaddr) is not None


def validate_confusables_email(value):
    """
    Validator which disallows 'dangerous' email addresses likely to
    represent homograph attacks.

    An email address is 'dangerous' if either the local-part or the
    domain, considered on their own, are mixed-script and contain one
    or more characters appearing in the Unicode Visually Confusable
    Characters file.

    """

    # we need a single @ in the email
    at_symbols = re.findall(r'@', value)
    if len(at_symbols) != 1:
        return False

    local_part, domain = value.split('@')
    if confusables.is_dangerous(local_part) or confusables.is_dangerous(domain):
        return False

    if local_part in DEFAULT_RESERVED_NAMES:
        return False

    return True


def validate_unique_value(value, check_list):

    '''This checks if the input value does not already exist in the check_list.

    The check_list comes from the DB and should contain user names, etc. that
    have been already normalized and casefolded.

    '''

    normalized_value = unicodedata.normalize('NFKC', value)

    if hasattr(normalized_value, 'casefold'):
        normalized_value = normalized_value.casefold()

    if normalized_value in set(check_list):
        return False
    else:
        return True


########################
## NORMALIZING VALUES ##
########################

def normalize_value(value):
    '''
    This normalizes a given value and casefolds it.

    Assumes that the value has already passed validation.

    '''

    if '@' in value:
        local_part, domain = value.split('@')

    else:
        local_part = value
        domain = ''

    if len(local_part) > 0:

        local_part = unicodedata.normalize('NFKC',local_part)
        local_part = local_part.casefold()

    if len(domain) > 0:

        domain = unicodedata.normalize('NFKC',domain)
        domain = domain.casefold()

    if '@' in value:
        return '@'.join([local_part, domain])
    else:
        return local_part
