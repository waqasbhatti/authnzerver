# -*- coding: utf-8 -*-
# dictcache.py - Waqas Bhatti (waqas.afzal.bhatti@gmail.com) - Jul 2020
# License: MIT - see the LICENSE file for the full text.
"""This contains a simple dict-based in-memory cache.

"""

#############
## IMPORTS ##
#############

import logging

# normally we'd use monotonic(), but we use time() because
# we want to be able to preserve the cache expiries across
# saves/loads of the cache to/from disk
from time import time
import pickle
from collections import namedtuple
from hashlib import blake2b
from hmac import compare_digest

from sortedcontainers import SortedSet

# get a logger
LOGGER = logging.getLogger(__name__)


#######################
## sorted key object ##
#######################

KeyWithTime = namedtuple('KeyWithTime', ['keytime', 'key'])


##################
## CACHE OBJECT ##
##################

class DictCache:

    def __init__(self, capacity=20000):
        """
        Initializes a cache with the given capacity.

        """

        self.container = {}
        self.capacity = capacity
        self.sortedkeys = SortedSet()

        # this stores keys that can expire and have a TTL
        self.expireable_key_ttls = SortedSet()

    #
    # internal operations
    #

    def _trim(self):
        """
        Removes the oldest key in the cache.

        """

        if len(self.container) > self.capacity:

            # index 0 is the oldest key in the sortest set (meaning smallest
            # time value)
            oldest_key = self.sortedkeys.pop(index=0)
            oldest_item = self.container.pop(oldest_key.key)

            if oldest_item is not None and oldest_item['ttl'] is not None:
                oldest_item_ttlkey = KeyWithTime(
                    oldest_item['keytime'] + oldest_item['ttl'],
                    oldest_key
                )
                self.expireable_key_ttls.discard(oldest_item_ttlkey)

    def _expire(self):
        """
        This expires all keys that are older than the current time.

        """

        self._trim()

        current_time = time()
        comparison_ttlkey = KeyWithTime(current_time, "")
        exp_indices_now = self.expireable_key_ttls.bisect_left(
            comparison_ttlkey
        )
        expireable_keys_now = self.expireable_key_ttls[:exp_indices_now]
        for sk in expireable_keys_now:
            self.sortedkeys.discard(sk)
            self.container.pop(sk.key)

        del self.expireable_key_ttls[:exp_indices_now]

    def _add_ttl(self, key, origin_time, ttl):
        """
        Adds a TTL key to self.expireable_key_ttls.

        If a key with the same value of key and TTL exists, does nothing.

        """

        self._trim()
        self._expire()

        if ttl is not None and ttl < 0:
            raise ValueError("Can't set ttl < 0")

        if ttl is not None:
            ttlkey = KeyWithTime(origin_time + ttl, key)
            self.expireable_key_ttls.add(ttlkey)

    def _set_ttl(self, key, existing_origin_time, existing_ttl, new_ttl):
        """
        Sets a TTL key in self.expireable_key_ttls to a new TTL.

        """

        self._trim()
        self._expire()

        if new_ttl is not None and new_ttl < 0:
            raise ValueError("Can't set ttl < 0")

        # handle an expireable key's TTL update
        if existing_ttl is not None:
            ttlkey = KeyWithTime(existing_origin_time + existing_ttl, key)

            # remove the existing ttl item
            self.expireable_key_ttls.discard(ttlkey)

            # if we're going to update it with a new item, generate the new item
            # and add it back to the SortedSet
            # otherwise, this falls through to the case of new_ttl = None,
            # which we've already handled above
            if new_ttl is not None:
                new_ttlkey = KeyWithTime(existing_origin_time + new_ttl, key)
                self.expireable_key_ttls.add(new_ttlkey)

        # handle setting a persistent key to be expireable
        else:
            self._add_ttl(key, existing_origin_time, new_ttl)

    #
    # cache info operations
    #

    def time(self):
        """
        Returns the cache's current time time counter.

        """

        self._expire()
        self._trim()

        return time()

    def size(self):
        """
        Returns the number of items in the cache.

        """

        self._trim()
        self._expire()

        return len(self.container)

    def info(self):
        """Returns the capacity of the cache, and
        number of normal and TTL items.

        """

        self._trim()
        self._expire()

        infodict = {
            "size":self.size(),
            "ttlkeys":len(self.expireable_key_ttl),
            "capacity":self.capacity,
            "time":self.time(),
        }
        return infodict

    #
    # normal key operations
    #

    def add(self, key, value, ttl=None, extras=None):
        """Adds a key and sets it to the value.

        If the key already exists, does nothing.

        If value is None, does not add the key to the cache because this would
        be pointless.

        if extras is provided, it must be a dict with key:val pairs. These will
        be added to the stored item in the container in a dict key called
        'extras'.

        """

        self._trim()
        self._expire()

        if ttl is not None and ttl < 0:
            raise ValueError("Can't set ttl < 0")

        if key not in self.container and value is not None:

            insert_time = time()

            sortedkey = KeyWithTime(insert_time, key)
            self.container[key] = {'value':value,
                                   'keytime':insert_time,
                                   'ttl':ttl}
            if extras is not None:
                self.container[key]['extras'] = extras

            self.sortedkeys.add(sortedkey)
            self._add_ttl(key, insert_time, ttl)

            return value

        else:
            return value

    def get(self, key, time_and_ttl=False, extras=False):
        """
        Gets the value of key from the cache.

        """

        self._trim()
        self._expire()

        item = self.container.get(key, None)
        if item and time_and_ttl and extras:
            return (item['value'],
                    item['keytime'],
                    item['ttl'],
                    item.get('extras'))
        if item and time_and_ttl:
            return item['value'], item['keytime'], item['ttl']
        elif item:
            return item['value']
        else:
            return None

    def set(self,
            key,
            value,
            ttl=None,
            extras=None,
            add_ifnotexists=True):
        """This sets the value of key to value and returns the new value.

        If the key doesn't exist and add_ifnotexists is False, returns None. If
        add_ifnotexists is True, adds the key to the cache and returns the
        value.

        ttl = None implies that the TTL no longer applies, in which it will be
        removed from the key, meaning the key becomes persistent.

        extras is a dict with key:val pairs that will update the existing extras
        dict for item in the container using the dict.update() method.

        """

        self._trim()
        self._expire()

        if ttl is not None and ttl < 0:
            raise ValueError("Can't set ttl < 0")

        if key not in self.container and add_ifnotexists:
            return self.add(key, value, ttl=ttl, extras=extras)

        elif key in self.container:
            self.container[key]['value'] = value
            self._set_ttl(key,
                          self.container[key]['keytime'],
                          self.container[key]['ttl'],
                          ttl)
            self.container[key]['ttl'] = ttl
            if extras is not None:
                self.container[key]['extras'].update(extras)

            return self.container[key]['value']

        else:
            return None

    def pop(self, key):
        """
        Pops the key from the cache.

        """

        self._trim()
        self._expire()

        item = self.container.pop(key, None)
        if item:

            sortedkey = KeyWithTime(item['keytime'], key)
            self.sortedkeys.discard(sortedkey)

            if item.get('ttl', None) is not None:
                ttlkey = KeyWithTime(item['keytime'] + item['ttl'], key)
                self.expireable_key_ttls.discard(ttlkey)

            return item['value']
        else:
            return None

    def delete(self, key):
        """Deletes the key from the cache.

        """

        self._trim()
        self._expire()

        removed_item = self.pop(key)
        if removed_item:
            return True
        else:
            return False

    def flush(self):
        """
        This removes all items in the cache.

        """

        self.container = {}
        self.sortedkeys = SortedSet()
        self.expireable_key_ttls = SortedSet()

    #
    # counter key operations
    #

    def counter_get(self, key):
        """This gets the current count for a counter key.

        """

        self._trim()
        self._expire()

        counter_key = f"{key}-dictcache-counterkey"

        if counter_key in self.container:
            count = self.get(counter_key)
            return count

        else:
            return 0

    def counter_add(self, key, initial_value, ttl=None):
        """
        Adds a new counter key to the cache with the specified initial value.

        """

        self._trim()
        self._expire()

        counter_key = f"{key}-dictcache-counterkey"

        int_initial_value = int(initial_value)
        if int_initial_value != initial_value or int_initial_value < 0:
            raise ValueError("counter value must be an integer >= 0")

        if counter_key not in self.container:
            return self.add(counter_key,
                            int_initial_value,
                            ttl=ttl,
                            extras={'initval':initial_value})
        else:
            return self.counter_get(key)

    def counter_set(self, key, value, ttl=None):
        """
        Sets the counter key to the specified value.

        """

        self._trim()
        self._expire()

        counter_key = f"{key}-dictcache-counterkey"

        int_value = int(value)
        if int_value != value or int_value < 0:
            raise ValueError("counter value must be an integer >= 0")

        if counter_key not in self.container:
            return self.counter_add(key,
                                    int_value,
                                    ttl=ttl)
        else:
            return self.set(counter_key, int_value, ttl=ttl)

    def counter_increment(self, key, ttl=None):
        """This increments a counter key by 1 every time it's called
        and returns the new count.

        If the key doesn't exist, adds it to the cache with an initial count of
        1.

        """

        self._trim()
        self._expire()

        counter_key = f"{key}-dictcache-counterkey"

        if counter_key in self.container:

            count = self.counter_get(key)
            updated_count = self.counter_set(key, count+1, ttl=ttl)
            return updated_count

        else:
            return self.counter_add(key, 1, ttl=ttl)

    def counter_decrement(self, key, ttl=None):
        """Decrements a counter key by 1 every time it's called.

        This will pop the key when its count reaches zero either after the
        current decrement or if the count has already reached zero before the
        decrement operation will be performed.

        Returns the new count after decrement or None if the key doesn't exist
        in the cache.

        """

        self._trim()
        self._expire()

        counter_key = f"{key}-dictcache-counterkey"

        if counter_key in self.container:

            count = self.counter_get(key)

            if count == 0:
                self.pop(counter_key)
                return 0

            else:
                new_count = self.counter_set(key, count-1, ttl=ttl)
                if new_count == 0:
                    self.pop(counter_key)
                    return 0
                else:
                    return new_count

        else:
            return None

    def counter_rate(self,
                     key,
                     period_seconds,
                     return_allinfo=False,
                     absolute_rate=True):
        """This gets the rate of increment/decrement over period (in seconds)
        for a counter key that was incremented in the past.

        If the counter key does not exist, returns None.

        If return_allinfo = True, returns a tuple with the current rate, the
        current value, the initial value, the current time, and the insertion
        time. Otherwise, returns only the rate as a float.

        If absolute_rate is True, returns the absolute value of the rate.

        """

        self._trim()
        self._expire()

        counter_key = f"{key}-dictcache-counterkey"

        if counter_key in self.container:
            key_item = self.container[counter_key]
            tnow = time()
            rate = ( (key_item['value'] - key_item['extras']['initval']) /
                     ((tnow - key_item['keytime'])/period_seconds) )

            if absolute_rate is True:
                rate = abs(rate)

            if return_allinfo:
                return (rate,
                        key_item['value'],
                        key_item['extras']['initval'],
                        tnow,
                        key_item['keytime'])
            else:
                return rate

        else:
            return None

    #
    # saving/loading to/from disk
    #

    def save(self, outfile, protocol=4, hmac_key=None):
        """This saves the current contents of the cache to disk.

        The items stored must be pickleable.

        If hmac_key is not None, the pickle will be signed before saving it to
        disk.

        """

        self._trim()
        self._expire()

        serialized = {
            "sortedkeys":self.sortedkeys,
            "keyttls":self.expireable_key_ttls,
            "container":self.container,
            "capacity":self.capacity
        }

        if hmac_key is not None:
            pickle_bytes = pickle.dumps(serialized, protocol=protocol)
            hasher = blake2b(key=hmac_key.encode('utf-8'),
                             digest_size=16,
                             person=b'authnzrv-hmac')
            hasher.update(pickle_bytes)
            hmac_sig = hasher.hexdigest()
            with open(outfile, 'wb') as outfd:
                outfd.write(hmac_sig.encode('utf-8') + pickle_bytes)
        else:
            with open(outfile,'wb') as outfd:
                pickle.dump(serialized, outfd, protocol=protocol)

    def load(self, infile, hmac_key=None):
        """This loads contents of the cache from a pickle file on disk.

        If hmac_key is not None, this function will assume it has to load a
        signed pickle. If hmac_key is None but the saved pickle was signed,
        loading will throw an exception.

        """

        if not hmac_key:

            with open(infile, 'rb') as infd:
                deserialized = pickle.load(infd)

        else:

            with open(infile, 'rb') as infd:
                intermediate = infd.read()

            hasher = blake2b(key=hmac_key.encode('utf-8'),
                             digest_size=16,
                             person=b'authnzrv-hmac')
            signature, deserialized_bytes = intermediate[:32], intermediate[32:]
            hasher.update(deserialized_bytes)
            hmac_sig = hasher.hexdigest()
            sig_ok = compare_digest(signature,
                                    hmac_sig.encode('utf-8'))
            if not sig_ok:
                raise ValueError("Incorrect signature for loaded pickle.")
            else:
                deserialized = pickle.loads(deserialized_bytes)

        self.sortedkeys = deserialized['sortedkeys']
        self.expireable_key_ttls = deserialized['keyttls']
        self.container = deserialized['container']
        self.capacity = deserialized['capacity']

        self._trim()
        self._expire()
