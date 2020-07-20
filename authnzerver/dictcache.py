# -*- coding: utf-8 -*-
# cache.py - Waqas Bhatti (waqas.afzal.bhatti@gmail.com) - Jul 2020
# License: MIT - see the LICENSE file for the full text.
"""This contains a simple dict-based in-memory cache.

"""

#############
## IMPORTS ##
#############

import logging
from time import monotonic
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

SortedKey = namedtuple('SortedKey', ['inserted', 'key'])


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

    def _trim(self):
        """
        Removes the oldest key in the cache.

        """
        if len(self.container) > self.capacity:
            oldest_key = self.sortedkeys.pop()
            self.container.pop(oldest_key.key)

    def size(self):
        """
        Returns the number of items in the cache.

        """

        return len(self.container)

    def add(self, key, value):
        """
        Adds a key and sets it to the value.

        If the key already exists, does nothing.

        """

        self._trim()

        if key not in self.container:

            insert_time = monotonic()

            sortedkey = SortedKey(insert_time, key)
            self.sortedkeys.add(sortedkey)
            self.container[key] = {'value':value, 'inserted':insert_time}
            return value

        else:
            return value

    def get(self, key):
        """
        Gets the value of key from the cache.

        """

        item = self.container.get(key, None)
        if item:
            return item['value']
        else:
            return None

    def set(self, key, value,
            add_ifnotexists=True):
        """This sets the value of key to value and returns the new value.

        If the key doesn't exist and add_ifnotexists is False, returns None. If
        add_ifnotexists is True, adds the key to the cache and returns the
        value.

        """

        if key not in self.container and add_ifnotexists:
            return self.add(key, value)

        elif key in self.container:
            self.container[key]['value'] = value
            return self.container[key]['value']

        else:
            return None

    def pop(self, key):
        """
        Pops the key from the cache.

        """

        item = self.container.pop(key, None)
        if item:
            sortedkey = SortedKey(item['inserted'], key)
            self.sortedkeys.remove(sortedkey)
            return item['value']
        else:
            return None

    def delete(self, key):
        """Deletes the key from the cache.

        """

        removed_item = self.pop(key)
        if removed_item:
            return True
        else:
            return False

    def count(self, key):
        """This gets the current count for a key that was previously
        incremented/decremented.

        """

        counter_key = f"{key}-cachecounterkey"

        if counter_key in self.container:
            count = self.get(counter_key)
            return count

        else:
            return 0

    def increment(self, key):
        """This increments a key by 1 every time it's called
        and returns the new count.

        If the key doesn't exist, adds it to the cache with an initial count of
        1.

        """

        counter_key = f"{key}-cachecounterkey"

        if counter_key in self.container:

            count = self.get(counter_key)
            updated_count = self.set(counter_key, count+1)
            return updated_count

        else:
            return self.add(counter_key, 1)

    def decrement(self, key, pop_whenzero=True):
        """Decrements a key by 1 every time it's called.

        If pop_whenzero is True, will pop the key when its count reaches zero
        either after the current decrement or if the count has already reached
        zero before the decrement operation will be performed.

        Returns the new count after decrement or None if the key doesn't exist
        in the cache.

        """

        counter_key = f"{key}-cachecounterkey"

        if counter_key in self.container:

            count = self.get(counter_key)

            if count is not None and count == 0 and pop_whenzero:
                self.pop(counter_key)
                return 0

            elif count is not None and count == 0:
                return 0

            elif count is not None:
                new_count = self.set(counter_key, count-1)
                if new_count == 0 and pop_whenzero:
                    self.pop(counter_key)
                    return 0
                else:
                    return new_count

        else:
            return None

    def getrate(self, key, period_seconds):
        """This gets the rate of increment over period (in seconds) for
        a counter key that was incremented in the past.

        If the counter key does not exist, returns None.

        """

        counter_key = f"{key}-cachecounterkey"

        if counter_key in self.container:
            key_item = self.container[counter_key]
            tnow = monotonic()
            rate = ( key_item['value'] /
                     ((tnow - key_item['inserted'])/period_seconds) )

            return rate, key_item['value'], key_item['inserted'], tnow

        else:
            return None

    def flush(self):
        """
        This removes all items in the cache.

        """

        self.container = {}
        self.sortedkeys = SortedSet()

    def save(self, outfile, protocol=4, hmac_key=None):
        """This saves the current contents of the cache to disk.

        The items stored must be pickleable.

        If hmac_key is not None, the pickle will be signed before saving it to
        disk.

        """

        serialized = {
            "sortedkeys":self.sortedkeys,
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
        self.container = deserialized['container']
        self.capacity = deserialized['capacity']
