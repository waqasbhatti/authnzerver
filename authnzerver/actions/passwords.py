# -*- coding: utf-8 -*-
# actions_user.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""This contains functions for validating passwords.

"""

#############
## LOGGING ##
#############

import logging
from types import SimpleNamespace

# get a logger
LOGGER = logging.getLogger(__name__)


#############
## IMPORTS ##
#############

import socket
from hashlib import sha1
import random
import time

from tornado.escape import squeeze
import requests
from requests.exceptions import HTTPError, Timeout

from difflib import SequenceMatcher

from ..permissions import pii_hash

from .. import validators


###############
## functions ##
###############


def check_password_pwned(
    password: str,
    email: str,
    reqid: str,
    pii_salt: str,
    min_matches: int = 25,
) -> tuple:
    """
    Checks the password against the haveibeenpwned.com API.

    https://haveibeenpwned.com/API/v3#PwnedPasswords

    Parameters
    ----------

    password : str
        The password to check against the haveibeenpwned.com API.

    email : str
        The email address of the user creating the account.

    reqid : int or str
        The request ID associated with this password validation request. Used to
        track and correlate these requests in logs.

    pii_salt : str
        The PII salt value passed in from a wrapping function. Used to censor
        personally identifying information in the logs emitted from this
        function.

    min_matches : int
        The minimum number of matches required in the matching set returned by
        the API to consider a password as compromised.

    Returns
    -------

    (status, msg, sha1_suffix, all_matches) : tuple
        If the password is considered to be compromised, returns "bad", msg
        for the first two elements in the tuple. Otherwise, returns "ok", "". If
        the API does not respond or there's an error, returns "unknown", "".

    """

    # SHA1 hash the password
    hashed_password = sha1(password.encode("utf-8")).hexdigest()
    hashed_password_prefix = hashed_password[:5]
    hashed_password_suffix = hashed_password[5:]

    # send the request
    try:

        # need to stagger calls to the haveibeenpwned API
        time.sleep(0.1 + abs(random.random() - 0.4))

        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{hashed_password_prefix}",
            timeout=5.0,
        )
        resp.raise_for_status()

    except HTTPError as e:

        if e.response and e.response.status_code != 200:
            LOGGER.warning(
                f"[{reqid}] The haveibeenpwned.com API did not "
                f"respond with a 200 OK."
                f"HTTP response code was: {e.response.status_code}."
            )
        return "unknown", "", hashed_password_suffix, None

    except Timeout:

        LOGGER.warning(
            f"[{reqid}] The haveibeenpwned.com API did not "
            f"respond within the requested timeout."
        )
        return "unknown", "", hashed_password_suffix, None

    except Exception:

        LOGGER.exception(f"[{reqid}] The haveibeenpwned.com API call failed.")
        return "unknown", "", hashed_password_suffix, None

    # load the resp body
    respbody = resp.text
    resp_lines = respbody.split("\n")
    resp_lines = [tuple(x.strip().split(":")) for x in resp_lines]
    resp_check = {x[0].casefold(): int(x[1]) for x in resp_lines}

    if (
        hashed_password_suffix in resp_check
        and resp_check[hashed_password_suffix] >= min_matches
    ):

        err_msg = (
            f"Your password was found with "
            f"{resp_check[hashed_password_suffix]} matches in "
            f"the database of recently "
            f"compromised Web account passwords from "
            f"https://haveibeenpwned.com/Passwords and "
            f"is not secure."
        )
        LOGGER.warning(
            f"[{reqid}] Password for account with "
            f"email: {pii_hash(email, pii_salt)} was found in "
            f"haveibeenpwned.com data with "
            f"{resp_check[hashed_password_suffix]} matches."
        )

        return "bad", err_msg, hashed_password_suffix, resp_check

    return "ok", "", hashed_password_suffix, resp_check


def validate_input_password(
    full_name: str,
    email: str,
    password: str,
    pii_salt: str,
    reqid: str,
    min_pass_length: int = 12,
    max_unsafe_similarity: int = 33,
    max_character_frequency: float = 0.3,
    min_pwned_matches: int = 25,
    config: SimpleNamespace = None,
) -> tuple:
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

    If all of the above pass, one last check is done:

    7. must not be in the https://haveibeenpwned.com/Passwords database with at
       least *min_pwned_matches* matches

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

    max_character_frequency : float
        The maximum number of times a character can appear in the password as a
        fraction of the total number of characters in the password. Upper and
        lower case characters are counted separately.

    min_pwned_matches : int
        The minimum number of matches required in the matching set returned by
        the haveibeenpwned.com password compromise database API to consider a
        password as compromised.

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    (password_ok, messages) : tuple
        *password_ok* is True if the password is OK to use and meets all
        specification, False otherwise. *messages* is a list of strings
        containing helpful messages on why the password was rejected (if it was)
        that can be passed to an end-user.

    """

    server_fqdn = socket.getfqdn()

    # handle kwargs passed via config object
    if config is not None:
        passpolicy = getattr(config, "passpolicy", None)
        config_fqdn = getattr(config, "fqdn", None)
        if config_fqdn is not None:
            server_fqdn = config_fqdn

        if passpolicy:
            try:
                (
                    pass_minlen,
                    pass_maxsim,
                    pass_charfreq,
                    min_pwned,
                ) = passpolicy.split(";")
                min_pass_length = int(
                    pass_minlen.strip().replace(" ", "").split(":")[1]
                )
                max_unsafe_similarity = int(
                    pass_maxsim.strip().replace(" ", "").split(":")[1]
                )
                max_character_frequency = float(
                    pass_charfreq.strip().replace(" ", "").split(":")[1]
                )
                min_pwned_matches = int(
                    min_pwned.strip().replace(" ", "").split(":")[1]
                )
            except Exception:
                LOGGER.exception(
                    "[%s] Invalid password policy could not be parsed: '%s'. "
                    "Falling back to kwarg values." % (reqid, passpolicy)
                )
                pass

    messages = []

    # we'll ignore any repeated white space and fail immediately if the password
    # is all white space
    if len(squeeze(password.strip())) < min_pass_length:

        LOGGER.warning(
            "[%s] Password for account "
            "with email: %s is too short (%s chars < required %s)."
            % (
                reqid,
                pii_hash(email, pii_salt),
                len(password),
                min_pass_length,
            )
        )
        messages.append(
            "Your password is too short. "
            "It must have at least %s characters." % min_pass_length
        )
        passlen_ok = False
    else:
        passlen_ok = True

    # check if the password is straight-up dumb
    if password.casefold() in validators.TOP_10K_PASSWORDS:
        LOGGER.warning(
            "[%s] Password for account "
            "with email: %s was found in the "
            "top 10k passwords list." % (reqid, pii_hash(email, pii_salt))
        )
        messages.append(
            "Your password is on the list of the "
            "most common passwords and is vulnerable to guessing."
        )
        tenk_ok = False
    else:
        tenk_ok = True

    # FIXME: also add matching to top 10k passwords list to avoid stuff
    # like 'passwordpasswordpassword'

    # check the match against the FQDN, user name, and email address
    password_to_match = squeeze(password.casefold().strip())

    fqdn_matcher = SequenceMatcher(
        None, password_to_match, server_fqdn.casefold()
    )
    email_matcher = SequenceMatcher(None, password_to_match, email.casefold())
    name_matcher = SequenceMatcher(
        None, password_to_match, full_name.casefold()
    )

    fqdn_match = fqdn_matcher.ratio() * 100.0
    email_match = email_matcher.ratio() * 100.0
    name_match = name_matcher.ratio() * 100.0

    fqdn_ok = fqdn_match < max_unsafe_similarity
    email_ok = email_match < max_unsafe_similarity
    name_ok = name_match < max_unsafe_similarity

    if not fqdn_ok or not email_ok or not name_ok:
        LOGGER.warning(
            "[%s] Password for account "
            "with email: %s matches FQDN "
            "(similarity: %.1f), their name (similarity: %.1f), "
            " or their email address "
            "(similarity: %.1f)."
            % (
                reqid,
                pii_hash(email, pii_salt),
                fqdn_match,
                name_match,
                email_match,
            )
        )
        messages.append(
            "Your password is too similar to either "
            "the domain name of this server or your "
            "own name or email address."
        )

    # next, check if the password is complex enough
    histogram = {}
    for char in password:
        if char not in histogram:
            histogram[char] = 1
        else:
            histogram[char] = histogram[char] + 1

    hist_ok = True

    for h in histogram:
        if (histogram[h] / len(password)) > max_character_frequency:
            hist_ok = False
            LOGGER.warning(
                "[%s] Password for account "
                "with email: %s does not have enough entropy. "
                "One character is more than "
                "%s x length of the password."
                % (reqid, pii_hash(email, pii_salt), max_character_frequency)
            )
            messages.append(
                "Your password is not complex enough. "
                "One or more characters appear appear too frequently."
            )
            break

    # check if the password is all numeric
    if password.isdigit():
        numeric_ok = False
        LOGGER.warning(
            "[%s] Password for account "
            "with email: %s is all numbers."
            % (reqid, pii_hash(email, pii_salt))
        )
        messages.append("Your password cannot be all numbers.")
    else:
        numeric_ok = True

    # check the password against haveibeenbeenpwned.com. only do this check if
    # all the other ones pass, since this is an external HTTP API call
    if (
        passlen_ok
        and email_ok
        and name_ok
        and fqdn_ok
        and hist_ok
        and numeric_ok
        and tenk_ok
    ):
        pwned_status, pwned_msg, _, _ = check_password_pwned(
            password, email, reqid, pii_salt, min_matches=min_pwned_matches
        )
        is_pwned = pwned_status == "bad"
        if is_pwned:
            messages.append(pwned_msg)
    else:
        is_pwned = False

    return (
        (
            passlen_ok
            and email_ok
            and name_ok
            and fqdn_ok
            and hist_ok
            and numeric_ok
            and tenk_ok
            and not is_pwned
        ),
        messages,
    )


def validate_password(
    payload: dict,
    raiseonfail: bool = False,
    override_authdb_path: str = None,
    config: SimpleNamespace = None,
) -> dict:
    """External interface to password validation.

    Use this in a frontend server or client to validate any passwords sent by
    the end-user.

    Parameters
    ----------

    payload : dict
        This is a dict with the following required keys:

        - password: str
        - email: str
        - full_name: str

        The following keys are optional:

        - min_pass_length: int, default = 12
        - max_unsafe_similarity: int, default = 33
        - max_character_frequency: float, default = 0.3
        - min_pwned_matches: int, default = 25

        The *email* and *full_name* are required to check if the password is too
        similar to either of these items.

        *min_pass_length* is the minimum number of characters required for the
        password. All passwords are capped at 256 characters. This value will be
        overriden by a value in the *config* object's *min_pass_length*
        attribute.

        *max_unsafe_similarity* is the maximum ratio required to fuzzy-match the
        input password against the server's domain name, the user's email, or
        their name. This value will be overriden by a value in the *config*
        object's *max_unsafe_similarity* attribute.

        *max_character_frequency* is the maximum ratio required to fuzzy-match
        the input password against the server's domain name, the user's email,
        or their name. The value provided in this kwarg will be overriden by the
        ``passpolicy`` attribute in the config object if that is passed in as
        well.

        *min_pwned_matches* is the minimum number of matches required in the
        matching set returned by the haveibeenpwned.com password compromise
        database API to consider a password as compromised.

        In addition to these items received from an authnzerver client, the
        payload must also include the following keys (usually added in by a
        wrapping function):

        - reqid: int or str
        - pii_salt: str

    raiseonfail : bool
        If True, will raise an Exception if something goes wrong.

    override_authdb_path : str or None
        If given as a str, is the alternative path to the auth DB.

    config : SimpleNamespace object or None
        An object containing systemwide config variables as attributes. This is
        useful when the wrapping function needs to pass in some settings
        directly from environment variables.

    Returns
    -------

    dict
        Returns a dict containing a *success* key indicating if the user's
        password is valid and can be used. If the password is invalid, the
        *messages* key will contain messages that inform the user why their
        password was rejected.

    """

    for key in ("reqid", "pii_salt"):
        if key not in payload:
            LOGGER.error(
                "Missing %s in payload dict. Can't process this request." % key
            )
            return {
                "success": False,
                "failure_reason": (
                    "invalid request: missing '%s' in request" % key
                ),
                "messages": ["Invalid password validation request."],
            }

    for key in {"password", "email", "full_name"}:

        if key not in payload:

            LOGGER.error(
                "[%s] Invalid password validation request, missing %s."
                % (payload["reqid"], key)
            )

            return {
                "success": False,
                "failure_reason": (
                    "invalid request: missing '%s' in request" % key
                ),
                "messages": [
                    "Invalid password validation request. "
                    "Some required parameters are missing."
                ],
            }

    password, email, full_name = (
        payload["password"],
        payload["email"],
        payload["full_name"],
    )

    try:
        min_pass_length = int(payload.get("min_pass_length", 12))
        if min_pass_length < 0:
            min_pass_length = 12
    except Exception:
        min_pass_length = 12

    try:
        max_unsafe_similarity = int(payload.get("max_unsafe_similarity", 33))
        if max_unsafe_similarity < 0:
            max_unsafe_similarity = 33
    except Exception:
        max_unsafe_similarity = 33

    try:
        max_character_frequency = float(
            payload.get("max_character_frequency", 0.3)
        )
        if max_character_frequency < 0:
            max_character_frequency = 0.3
    except Exception:
        max_character_frequency = 0.3

    try:
        min_pwned_matches = int(payload.get("min_pwned_matches", 25))
        if min_pwned_matches < 0:
            min_pwned_matches = 25
    except Exception:
        min_pwned_matches = 25

    password_ok, messages = validate_input_password(
        full_name,
        email,
        password,
        payload["pii_salt"],
        payload["reqid"],
        min_pass_length=min_pass_length,
        max_unsafe_similarity=max_unsafe_similarity,
        max_character_frequency=max_character_frequency,
        min_pwned_matches=min_pwned_matches,
        config=config,
    )

    retdict = {"success": password_ok, "messages": messages}

    if not password_ok:
        retdict["failure_reason"] = "password is insecure or invalid"

    return retdict
