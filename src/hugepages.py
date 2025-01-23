#!/usr/bin/env python

"""
Show huge pages
"""

from __future__ import print_function

import os

hpdir = "/sys/kernel/mm/hugepages"

def file_int(fn):
    return int(open(fn).read().strip())

for d in os.listdir(hpdir):
    dp = os.path.join(hpdir, d)
    print("  %20s  %5u  " % (d, file_int(dp + "/nr_hugepages")))
