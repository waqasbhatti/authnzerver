"""
This includes tests for the dictcache in-memory store.

"""

import time

import pytest

from authnzerver.dictcache import DictCache


@pytest.fixture(scope="function")
def dictcache_obj():
    """
    This is a fixture that returns a DictCache object.

    """

    return DictCache(capacity=1000)


#
# basic tests
#


def test_add_key(dictcache_obj):
    """
    Tests simple add.

    """

    retval = dictcache_obj.add("test_key", 123)
    assert retval == 123
    assert dictcache_obj.get("test_key") == 123


def test_add_same_key(dictcache_obj):
    """
    Tests if adding the same key with a new value doesn't do anything.

    """

    retval = dictcache_obj.add("test_key", 123)
    assert retval == 123
    dictcache_obj.add("test_key", 456)
    assert dictcache_obj.get("test_key") == 123
    assert dictcache_obj.size() == 1


def test_cache_capacity(dictcache_obj):
    """
    Tests if the cache maintains the set capacity.

    """

    # overfill the cache
    for x in range(1100):
        dictcache_obj.add(f"key_{x}", f"value_{x}")

    # check if the size was maintained
    assert dictcache_obj.size() == 1000
    assert len(dictcache_obj.container) == 1000
    assert len(dictcache_obj.sortedkeys) == 1000

    # check if the first 100 keys were removed as expected
    for x in range(100):
        assert dictcache_obj.get(f"key_{x}") is None

    # check if the next 1000 keys are as expected
    for x in range(100, 1100):
        assert dictcache_obj.get(f"key_{x}") == f"value_{x}"


def test_cache_delete(dictcache_obj):
    """
    Tests if the cache deletes things correctly.

    """

    for x in range(1000):
        dictcache_obj.add(f"key_{x}", f"value_{x}", ttl=10.0)

    for x in range(1000):
        dictcache_obj.delete(f"key_{x}")

    assert dictcache_obj.size() == 0
    assert len(dictcache_obj.container) == 0
    assert len(dictcache_obj.sortedkeys) == 0
    assert len(dictcache_obj.expireable_key_ttls) == 0


def test_cache_flush(dictcache_obj):
    """
    Tests if the cache flushes correctly.

    """

    for x in range(1100):
        dictcache_obj.add(f"key_{x}", f"value_{x}", ttl=10.0)

    # check if the size was maintained
    assert dictcache_obj.size() == 1000
    assert len(dictcache_obj.container) == 1000
    assert len(dictcache_obj.sortedkeys) == 1000

    dictcache_obj.flush()
    assert dictcache_obj.size() == 0
    assert len(dictcache_obj.container) == 0
    assert len(dictcache_obj.sortedkeys) == 0


#
# TTL tests
#


def test_add_key_with_ttl(dictcache_obj):
    """
    Tests add with key TTL.

    """

    add_time = time.time()
    retval = dictcache_obj.add("test_key", 123, ttl=1.0)
    assert retval == 123

    keyval, keytime, keyttl = dictcache_obj.get("test_key", time_and_ttl=True)
    assert keyval == 123
    assert keyttl == 1.0
    assert keytime == pytest.approx(add_time, rel=1.0e-3)

    time.sleep(1.5)
    assert dictcache_obj.get("test_key") is None
    assert dictcache_obj.size() == 0


def test_set_key(dictcache_obj):
    """
    Tests setting a key to a new value.

    Tests setting a non-existent key with add_ifnotexists=True adds the key.

    Tests setting a non-existent key with add_ifnotexists=False does nothing.

    """

    retval = dictcache_obj.add("test_key", 123)
    assert retval == 123

    dictcache_obj.set("test_key", "hello-world!")
    assert dictcache_obj.get("test_key") == "hello-world!"

    dictcache_obj.set("another_test_key", "hello-world-this-is-new")
    assert dictcache_obj.get("another_test_key") == "hello-world-this-is-new"

    dictcache_obj.set(
        "one_more_test_key",
        "hello-world-this-should-fail",
        add_ifnotexists=False,
    )
    assert dictcache_obj.get("one_more_test_key") is None


def test_set_key_ttl(dictcache_obj):
    """
    Tests if setting a key's TTL works.

    """

    add_time = time.time()
    retval = dictcache_obj.add("test_key", 123, ttl=2.0)
    assert retval == 123

    # test if setting a key TTL to a new value works
    dictcache_obj.set("test_key", 456, ttl=5.0)
    keyval, keytime, keyttl = dictcache_obj.get("test_key", time_and_ttl=True)
    assert keyval == 456
    assert keyttl == 5.0
    assert keytime == pytest.approx(add_time, rel=1.0e-3)

    time.sleep(4.0)
    assert dictcache_obj.get("test_key") == 456

    time.sleep(2.0)
    assert dictcache_obj.get("test_key") is None

    # check if we can set ttl < 0
    with pytest.raises(ValueError, match="Can't set ttl < 0"):
        dictcache_obj.add("test_key_bad_ttl", 123, ttl=-10)


def test_set_key_persistent(dictcache_obj):
    """
    Tests if setting a key's TTL to None makes it persistent.

    """

    add_time = time.time()
    retval = dictcache_obj.add("test_key", 123, ttl=2.0)
    assert retval == 123

    # test if setting an expireable key's TTL to None makes it persistent
    dictcache_obj.set("test_key", 456, ttl=None)
    keyval, keytime, keyttl = dictcache_obj.get("test_key", time_and_ttl=True)
    assert keyval == 456
    assert keyttl is None
    assert keytime == pytest.approx(add_time, rel=1.0e-3)

    time.sleep(3.0)
    assert dictcache_obj.get("test_key") == 456


def test_set_key_expireable(dictcache_obj):
    """
    Tests if setting a key's TTL from None to a time val makes it expireable.

    """

    add_time = time.time()
    retval = dictcache_obj.add("test_key", 123, ttl=None)
    assert retval == 123

    # test if setting an expireable key's TTL to None makes it expireable
    dictcache_obj.set("test_key", 456, ttl=2.0)
    keyval, keytime, keyttl = dictcache_obj.get("test_key", time_and_ttl=True)
    assert keyval == 456
    assert keyttl == 2.0
    assert keytime == pytest.approx(add_time, rel=1.0e-3)

    time.sleep(3.0)
    assert dictcache_obj.get("test_key") is None


#
# counter key
#


def test_counterkey_increment(dictcache_obj):
    """
    Tests if a counter key is incremented correctly.

    """

    count = dictcache_obj.counter_increment("test_key")

    assert count == 1

    for _ in range(99):
        dictcache_obj.counter_increment("test_key")

    assert dictcache_obj.counter_get("test_key") == 100


def test_counterkey_decrement(dictcache_obj):
    """
    Tests if a counter key is decremented correctly.

    """

    count = dictcache_obj.counter_increment("test_key")

    assert count == 1

    for _ in range(99):
        dictcache_obj.counter_increment("test_key")

    assert dictcache_obj.counter_get("test_key") == 100

    for _ in range(99):
        dictcache_obj.counter_decrement("test_key")

    assert dictcache_obj.counter_get("test_key") == 1

    # test that the key is deleted when the last decrement brings the counter to
    # zero
    lastval = dictcache_obj.counter_decrement("test_key")
    assert lastval == 0
    assert dictcache_obj.counter_get("test_key") == 0
    assert dictcache_obj.get("test_key-dictcache-counterkey") is None


def test_counterkey_addset(dictcache_obj):
    """
    Tests if a counter key can be added/set at a specific values.

    """

    count = dictcache_obj.counter_add("test_key", 100)

    assert count == 100
    assert dictcache_obj.counter_get("test_key") == 100
    assert dictcache_obj.get("test_key-dictcache-counterkey") == 100

    count = dictcache_obj.counter_set("test_key", 50)
    assert count == 50
    assert dictcache_obj.counter_get("test_key") == 50
    assert dictcache_obj.get("test_key-dictcache-counterkey") == 50


def test_counterkey_rate(dictcache_obj):
    """
    Tests if a counter key rate is calculated correctly.

    """

    total_time = 0.0
    time_step = 0.01

    start_time = time.time()
    for _ in range(100):
        dictcache_obj.counter_increment("test_key")
        time.sleep(time_step)
        total_time = total_time + time_step
    end_time = time.time()

    (rate, currval, initval, currtime, inittime) = dictcache_obj.counter_rate(
        "test_key", 1.0, return_allinfo=True
    )
    assert rate == pytest.approx(
        (100 - 1) / ((end_time - start_time) / 1.0), rel=1.0e-3
    )

    # now check decreasing rates
    dictcache_obj.counter_add("test_key_two", 101)

    total_time = 0.0

    start_time = time.time()
    for _ in range(100):
        dictcache_obj.counter_decrement("test_key_two")
        time.sleep(time_step)
        total_time = total_time + time_step
    end_time = time.time()

    (rate, currval, initval, currtime, inittime) = dictcache_obj.counter_rate(
        "test_key_two", 1.0, return_allinfo=True
    )
    expected_rate = abs((1 - 101) / ((end_time - start_time) / 1.0))
    assert rate == pytest.approx(expected_rate, rel=1.0e-3)
