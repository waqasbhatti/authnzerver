# -*- coding: utf-8 -*-
# cache.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

"""This contains functions to drive the cache.

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

import os.path
import time
from datetime import datetime

from diskcache import FanoutCache


##############################
## CACHE HANDLING FUNCTIONS ##
##############################

def cache_add(key, value,
              cacheobj=None,
              timeout_seconds=0.3,
              expires_seconds=None,
              cache_dirname='/tmp/authnzerver-cache'):
    """
    This sets a key to the value specified in the cache.

    """

    if not cacheobj:
        cachedir = os.path.abspath(cache_dirname)
        cache = FanoutCache(cachedir, timeout=timeout_seconds)
    else:
        cache = cacheobj

    added = cache.add(key, value, expire=expires_seconds)

    cache.close()
    return added


def cache_get(key,
              cacheobj=None,
              timeout_seconds=0.3,
              cache_dirname='/tmp/authnzerver-cache'):
    """
    This sets a key to the value specified in the cache.

    """

    if not cacheobj:
        cachedir = os.path.abspath(cache_dirname)
        cache = FanoutCache(cachedir, timeout=timeout_seconds)
    else:
        cache = cacheobj

    val = cache.get(key)

    cache.close()
    return val


def cache_pop(key,
              cacheobj=None,
              timeout_seconds=0.3,
              cache_dirname='/tmp/authnzerver-cache'):
    """
    This sets a key to the value specified in the cache.

    """

    if not cacheobj:
        cachedir = os.path.abspath(cache_dirname)
        cache = FanoutCache(cachedir, timeout=timeout_seconds)
    else:
        cache = cacheobj

    val = cache.pop(key)

    cache.close()
    return val


def cache_delete(key,
                 cacheobj=None,
                 timeout_seconds=0.3,
                 cache_dirname='/tmp/authnzerver-cache'):
    """
    This sets a key to the value specified in the cache.

    """

    if not cacheobj:
        cachedir = os.path.abspath(cache_dirname)
        cache = FanoutCache(cachedir, timeout=timeout_seconds)
    else:
        cache = cacheobj

    deleted = cache.delete(key)

    cache.close()
    return deleted


def cache_increment(key,
                    cacheobj=None,
                    timeout_seconds=0.3,
                    cache_dirname='/tmp/authnzerver-cache'):
    """
    This sets up a counter for the key in the cache.

    Sets the key -> time of initial insertion
    Then increments 'key-counter'.

    """

    if not cacheobj:
        cachedir = os.path.abspath(cache_dirname)
        cache = FanoutCache(cachedir, timeout=timeout_seconds)
    else:
        cache = cacheobj

    # add the key if not already present
    key_added = cache.add(key, time.time())

    # increment the counter in either case
    if key_added:
        key_count = cache.incr('%s-counter' % key)
    else:
        key_count = cache.incr('%s-counter' % key)

    cache.close()
    return key_count


def cache_decrement(key,
                    cacheobj=None,
                    timeout_seconds=0.3,
                    cache_dirname='/tmp/authnzerver-cache'):
    """
    This decrements the counter for key.

    """

    if not cacheobj:
        cachedir = os.path.abspath(cache_dirname)
        cache = FanoutCache(cachedir, timeout=timeout_seconds)
    else:
        cache = cacheobj

    decremented_val = cache.decr('%s-counter' % key)

    # if the counter hits zero, delete the key entirely from the cache
    if decremented_val == 0:
        cache.delete(key)
        cache.delete('%s-counter' % key)
        decremented_val = 0

    cache.close()
    return decremented_val


def cache_getrate(key,
                  cacheobj=None,
                  timeout_seconds=0.3,
                  cache_dirname='/tmp/authnzerver-cache'):
    """This gets the rate of increment for the key by looking at the time of
    insertion inserted at key and the number of times it was incremented in
    key-counter. The rate is then:

        key-counter_val/((time_now - time_insertion)/60.0)

    """

    if not cacheobj:
        cachedir = os.path.abspath(cache_dirname)
        cache = FanoutCache(cachedir, timeout=timeout_seconds)
    else:
        cache = cacheobj

    # get the counter value
    counter_val = cache.get('%s-counter' % key, default=0)

    # get the time of insertion that we stored at the key itself
    time_of_insertion = cache.get(key, default=None)

    if time_of_insertion is not None:

        rate = (counter_val/(time.time() - time_of_insertion))*60.0
    else:
        rate = 0.0

    cache.close()
    return (
        rate,
        counter_val,
        datetime.fromtimestamp(time_of_insertion).isoformat()
    )


def cache_flush(cacheobj=None,
                timeout_seconds=0.3,
                cache_dirname='/tmp/authnzerver-cache'):
    """
    This removes all keys from the cache.

    """

    if not cacheobj:
        cachedir = os.path.abspath(cache_dirname)
        cache = FanoutCache(cachedir, timeout=timeout_seconds)
    else:
        cache = cacheobj

    items_removed = cache.clear()

    cache.close()
    return items_removed
