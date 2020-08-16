# -*- coding: utf-8 -*-
# actions_user.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""This contains functions for validating passwords.

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

import socket

from tornado.escape import squeeze
from difflib import SequenceMatcher

from ..permissions import pii_hash

from .. import validators


def validate_input_password(
        full_name,
        email,
        password,
        pii_salt,
        reqid,
        min_pass_length=12,
        max_unsafe_similarity=20,
        config=None
):
    """Validates user input passwords.

    Password rules are:

    1. must be at least min_pass_length characters (we'll truncate the password
       at 1024 characters since we don't want to store entire novels)

    2. must not match within max_unsafe_similarity of their email or full_name

    3. must not match within max_unsafe_similarity of the site's FQDN

    4. must not have a single case-folded character take up more than 20% of the
       length of the password

    5. must not be completely numeric

    6. must not be in the top 10k passwords list

    Parameters
    ----------

    full_name : str
        The full name of the user creating the account.

    email : str
        The email address of the user creating the account.

    password : str
        The password of the user creating the account.

    pii_salt : str
        The PII salt value passed in from a wrapping function. Used to censor
        personally identifying information in the logs emitted from this
        function.

    reqid : int or str
        The request ID associated with this password validation request. Used to
        track and correlate these requests in logs.

    min_pass_length : int
        The minimum required character length of the password. The value
        provided in this kwarg will be overriden by the ``passpolicy`` attribute
        in the config object if that is passed in as well.

    max_unsafe_similarity : int
        The maximum ratio required to fuzzy-match the input password against
        the server's domain name, the user's email, or their name. The value
        provided in this kwarg will be overriden by the ``passpolicy`` attribute
        in the config object if that is passed in as well.

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    bool
        Returns True if the password is OK to use and meets all
        specification. False otherwise.

    """

    # handle kwargs passed via config object
    if config is not None:
        passpolicy = getattr(config, "passpolicy", None)

        if passpolicy:
            try:
                pass_minlen, pass_maxsim = passpolicy.split(';')
                min_pass_length = int(pass_minlen.strip().split(':')[1])
                max_unsafe_similarity = int(pass_maxsim.strip().split(':')[1])
            except Exception:
                LOGGER.error(
                    "[%s] Invalid password policy could not be parsed: '%s'. "
                    "Falling back to kwarg values."
                    % (reqid, passpolicy)
                )
                pass

    messages = []

    # we'll ignore any repeated white space and fail immediately if the password
    # is all white space
    if len(squeeze(password.strip())) < min_pass_length:

        LOGGER.warning('[%s] Password for new account '
                       'with email: %s is too short (%s chars < required %s).' %
                       (reqid,
                        pii_hash(email, pii_salt),
                        len(password),
                        min_pass_length))
        messages.append('Your password is too short. '
                        'It must have at least %s characters.' %
                        min_pass_length)
        passlen_ok = False
    else:
        passlen_ok = True

    # check if the password is straight-up dumb
    if password.casefold() in validators.TOP_10K_PASSWORDS:
        LOGGER.warning('[%s] Password for new account '
                       'with email: %s was found in the '
                       'top 10k passwords list.' %
                       (reqid, pii_hash(email, pii_salt)))
        messages.append('Your password is on the list of the '
                        'most common passwords and is vulnerable to guessing.')
        tenk_ok = False
    else:
        tenk_ok = True

    # FIXME: also add matching to top 10k passwords list to avoid stuff
    # like 'passwordpasswordpassword'

    # check the match against the FQDN, user name, and email address
    fqdn = socket.getfqdn()

    password_to_match = squeeze(password.casefold().strip())

    fqdn_matcher = SequenceMatcher(
        None, password_to_match, fqdn.casefold()
    )
    email_matcher = SequenceMatcher(
        None, password_to_match, email.casefold()
    )
    name_matcher = SequenceMatcher(
        None, password_to_match, full_name.casefold()
    )

    fqdn_match = fqdn_matcher.ratio()*100.0
    email_match = email_matcher.ratio()*100.0
    name_match = name_matcher.ratio()*100.0

    fqdn_ok = fqdn_match < max_unsafe_similarity
    email_ok = email_match < max_unsafe_similarity
    name_ok = name_match < max_unsafe_similarity

    if not fqdn_ok or not email_ok or not name_ok:
        LOGGER.warning('[%s] Password for new account '
                       'with email: %s matches FQDN '
                       '(similarity: %.1f), their name (similarity: %.1f), '
                       ' or their email address '
                       '(similarity: %.1f).' %
                       (reqid,
                        pii_hash(email, pii_salt),
                        fqdn_match,
                        name_match,
                        email_match))
        messages.append('Your password is too similar to either '
                        'the domain name of this server or your '
                        'own name or email address.')

    # next, check if the password is complex enough
    histogram = {}
    for char in password:
        if char.casefold() not in histogram:
            histogram[char.casefold()] = 1
        else:
            histogram[char.casefold()] = histogram[char.casefold()] + 1

    hist_ok = True

    for h in histogram:
        if (histogram[h]/len(password)) > 0.2:
            hist_ok = False
            LOGGER.warning('[%s] Password for new account '
                           'with email: %s does not have enough entropy. '
                           'One character is more than '
                           '0.2 x length of the password.' %
                           (reqid, pii_hash(email, pii_salt)))
            messages.append(
                'Your password is not complex enough. '
                'One or more characters appear appear too frequently.'
            )
            break

    # check if the password is all numeric
    if password.isdigit():
        numeric_ok = False
        LOGGER.warning('[%s] Password for new account '
                       'with email: %s is all numbers.' %
                       (reqid, pii_hash(email, pii_salt)))
        messages.append('Your password cannot be all numbers.')
    else:
        numeric_ok = True

    return (
        (passlen_ok and email_ok and name_ok and
         fqdn_ok and hist_ok and numeric_ok and tenk_ok),
        messages
    )
