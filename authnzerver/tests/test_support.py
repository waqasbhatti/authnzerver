import os.path
import os
import multiprocessing as mp
import time

from authnzerver.validators import public_suffix_list


def get_public_suffix_list():
    """
    Gets the public suffix list and caches it for tests.

    """

    # check if this exists already
    list_file = os.path.join(
        os.path.expanduser("~"), ".cache", "authnzerver", "public-suffixes.txt"
    )

    suff_list = None

    if os.path.exists(list_file):

        out_of_date = (time.time() - os.stat(list_file).st_ctime) > 604800.0

        if not out_of_date:
            with open(list_file, "r") as infd:
                suff_list = [x.strip("\n") for x in infd.readlines()]

    if not suff_list:
        suff_list = public_suffix_list()
        if not os.path.exists(os.path.dirname(list_file)):
            os.makedirs(os.path.dirname(list_file))

        with open(list_file, "w") as outfd:
            for suff in suff_list:
                outfd.write(f"{suff}\n")

    # also set this in the current process's namespace so we can test that
    currproc = mp.current_process()
    currproc.public_suffix_list = suff_list

    return suff_list
