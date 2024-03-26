#!/usr/bin/env python
#
# SPDX-FileCopyrightText: Copyright (C) 2024 Arm Limited and/or its affiliates
# SPDX-FileCopyrightText: <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Get the system topology on the host.

The system topology includes the list of CPUs and their vendor and model.

This module is designed to deal with heterogeneous systems such as Arm's
big.LITTLE, where CPUs will be of different types and may even be from
different vendors, although all conforming to a common architecture,
with threads able to migrate between cores. Much of the apparent
complexity of this module is due to the need to track more than one
CPU type.

The CPU vendor (implementer) is needed by clients who wish to look up
implementation-defined behavior such as hardware performance events.

This module works by building an object representing the CPU list,
together with the list of CPU types.
Clients can then query the object.

It assumes that the instruction-set architecture (x86_64, armv8 etc.)
is a system-wide property.

Possible sources for this information:
  /proc/cpuinfo
    As the format of /proc/cpuinfo is not standardized
    this module has to do its best.
  /sys/bus/cpu/devices
  /sys/devices/system/cpu
    may be more complete than /proc/cpuinfo
    shows CPU topology
    'online' shows CPUs online (others are not reported by /proc/cpuinfo)
  Python stdlib
    no module specifically for topology
    multiprocessing: cpu_count() reports the number of CPUs
    platform: knows the architecture type

You can use this to discover the specification of a remote system:

  ssh me@system 'python -s' < cpulist.py

"""

from __future__ import print_function

import platform, sys, os, itertools

o_verbose = 0


try:
    from pyperf.perf_util import *
    check_cpusetstr = True
except ImportError:
    def file_word(fn):
        return open(fn).read().strip()
    def file_int(fn):
        return int(file_word(fn))
    def file_hex(fn):
        return int(file_word(fn).replace(',',''),16)
    def str_memsize(s):
        u = "BKMGT".find(s[-1])
        if u > -1:
            s = s[:-1]
        return float(s) * (1 << (u*10))
    def memsize_str(n, unit=None):
        for u in range(4, 0, -1):
            if unit == "BKMGT"[u] or n >= (1 << (u*10)):
                return "%.3g%s" % ((float(n)/(1<<(u*10))), "BKMGT"[u])
        return str(n)
    def intlist_mask(x):
        m = 0
        for n in x:
            m |= (1 << n)
        return m
    def intmask_list(n):
        return [p for (p, d) in enumerate(bin(n)[-1:1:-1]) if d != '0']
    def cpusetstr_mask(s):
        m = 0
        for r in s.split(','):
            if '-' in r:
                (lo,hi) = r.split('-')
                m |= ((1 << (int(hi)+1)) - (1 << int(lo)))
            else:
                m |= (1 << int(r))
        return m
    def mask_cpusetstr(m):
        # TBD: doesn't compact ranges: 0xF should be "0-3" not "0,1,2,3"
        return str(intmask_list(m))[1:-1]
    check_cpusetstr = False


class CPUspec:
    """
    Specification of a CPU type (any architecture).
    Heterogeneous systems might have multiple CPU types.
    When we read /proc/cpuinfo we discover one or more
    CPU types (usually one) and we also discover the
    mapping of CPU number to CPU type (usually trivial).
    """
    def __init__(self, implementer=None, implementer_code=None, model=None, model_code=None, sku=None, stepping=None, features=None):
        self.implementer = implementer                # implementer company name e.g. "Intel", "Arm"
        self.implementer_code = implementer_code      # e.g. ARM 8-bit implementer code, 0x41 for Arm
        self.model_name = model                       # e.g. "Model 94"
        assert model_code is None or isinstance(model_code, int)
        self.model_code = model_code                  # for Intel this is e.g. 94 for Skylake
        self.model_sku = sku                          # e.g. "Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz"
        self.stepping = stepping                      # for Intel it's a number, for Arm it's a (rx, px) tuple
        self.features = features if features is not None else []
        # self.arch is added by whoever creates this

    def str_compact(self):
        s = "%s " % (self.implementer)
        if self.arch == "x86_64":
            s += "%u" % self.model_code
        else:
            s += "0x%x" % self.model_code
        if self.arch == "aarch64":
            s += " %s" % self.str_stepping()
        return s

    def str_stepping(self):
        if self.arch == "aarch64":
            return "r%up%u" % self.stepping
        else:
            return "stepping %s" % self.stepping

    def str_full(self, features=False):
        s = "%s %s" % (self.implementer, self.model_name)
        if self.model_sku is not None:
            s += " (%s)" % self.model_sku
        if self.stepping is not None:
            s += " %s" % self.str_stepping()
        if features and self.features:
            s += " features [%s]" % (' '.join(self.features))
        return s

    def has_feature(self, feature):
        return feature in self.features

    def __str__(self):
        return self.str_full()

    def __eq__(self, other):
        return self.__repr__() == other.__repr__()

    def __hash__(self):
        return hash(str(self))

    def __repr__(self):
        """
        Generate a string that fully describes the CPU specification.
        This is used to detect whether CPUs are the same or different,
        and build a set of distinct CPU specifications for the whole system
        (normally 1, except for heterogeneous systems like Arm big.LITTLE).
        See the __eq__ and __hash__ methods below. So it's essential
        this string fully describes the CPU implementation.
        """
        a = []
        if self.implementer is not None:
            a.append("imp:%s" % self.implementer)
        if self.implementer_code is not None:
            a.append("impcode:0x%x" % self.implementer_code)
        if self.model_name is not None:
            a.append("model:%s" % self.model_name)
        if self.model_code is not None:
            a.append("code:0x%x" % self.model_code)
        if self.stepping is not None:
            a.append("stepping:%s" % self.str_stepping())
        if self.features:
            a.append("features:[%s]" % (' '.join(self.features)))
        return ' '.join(a)


def read_proc_cpuinfo():
    """
    Read /proc/cpuinfo, returning a series of (CPU number, description) pairs.
    We cope with two basic styles of /proc/cpuinfo:

      style A:
         processor : 0
         key1      : ...
         key2      : ...

         processor : 1
         key1      : ...
         key2      : ...

      style B:
         processor : 0
         processor : 1
         key1      : ...
         key2      : ...

    This routine is architecture-neutral. See System.spec_from_keys for how
    this is translated into a processor code for Intel or Arm.
    """
    f = open("/proc/cpuinfo")
    cpus = []
    keys = {}
    last_cpu_number = None
    for r in f:
        cix = r.find(':')
        if cix < 0:
            for c in cpus:
                yield (c, keys)
            cpus = []
            keys = {}
        if r.startswith("processor"):
            # the CPU number on this system, as seen by Linux
            cpuno = int(r[cix+2:-1])
            if last_cpu_number is not None:
                assert cpuno > last_cpu_number
                if cpuno != last_cpu_number + 1:
                    print("** /proc/cpuinfo is missing CPU(s) %u..%u" % (last_cpu_number+1, cpuno-1), file=sys.stderr)
            last_cpu_number = cpuno
            cpus.append(cpuno)
        elif cpus:
            # only start collecting keys when we've got at least one CPU
            key = r[:cix].strip()
            keys[key] = r[cix+2:-1]
    f.close()
    for c in cpus:
        yield (c, keys)


"""
Cache information. Some caches may be shared, and in our system
representation we have one node per cache. So we aim for a
unique identifier per cache.
sysfs appears to create one instance
pf each cache level per CPU, with no sharing of inodes.
So we can't use inode as a unique identifier.
Instead, we use (cpumask, level, type) as identifier.
"""

def cache_type_letter(ts):
    assert ts in ["Instruction", "Data", "Unified"]
    return ts[0]

def cache_key(path):
    assert os.path.isdir(path)
    cpumask = file_hex(path + "/shared_cpu_map")
    level = file_int(path + "/level")
    ts = file_word(path + "/type")
    return (cpumask, level, cache_type_letter(ts))


class Cache:
    """
    Information about a cache, at any level.
    This object corresponds to a specific cache, e.g. there will be one for each L1.
    """
    def __init__(self, path=None, system=None):
        self.system = system
        self.size = None
        self.line_size = None
        self.ways = None
        self.sets = None
        self.type = None
        self.write_policy = None
        self.level = None
        self.cpus = None     # Set of CPUs using (upstream of) this cache
        # We don't yet know the downstream cache, and won't until
        # we sort out the cache topology after discovery.
        # We assume there is one downstream cache - i.e. we don't
        # have a unified L2 with split L3 downstream of it.
        self.parent = None
        if path is not None:
            self.discover(path)

    def cpu_list(self):
        return self.cpus

    def cpu_mask(self):
        return intlist_mask(self.cpus)

    def __lt__(self, c):
        if min(self.cpus) != min(c.cpus):
            return min(self.cpus) < min(c.cpus)
        if self.level != c.level:
            return self.level > c.level
        return self.type < c.type

    def for_cpu(self, cpuno):
        # Return True if the specified CPU uses this cache
        return cpuno in self.cpus

    def is_unified(self):
        return self.type == "U"

    def contains(self, type):
        assert type in "ID"
        return self.is_unified() or self.type == type

    def discover(self, path):
        """
        Retrieve cache information from sysfs. Suitable paths:
          /sys/bus/cpu/devices/cpu0/cache/index0
          /sys/devices/system/cpu/cpu0/cache/index0
        """
        assert os.path.isdir(path)
        # size might report as zero if CPU offline?
        if os.path.isfile(path + "/size"):
            self.size = str_memsize(file_word(path + "/size"))
        if os.path.isfile(path + "/ways_of_associativity"):
            self.ways = file_int(path + "/ways_of_associativity")
        # if we have one out of number_of_sets or coherency_line_size we could find out the other,
        # but sometimes we have neither
        if os.path.isfile(path + "/number_of_sets"):
            self.sets = file_int(path + "/number_of_sets")
        if os.path.isfile(path + "/coherency_line_size"):
            self.line_size = file_int(path + "/coherency_line_size")
        ts = file_word(path + "/type")
        self.type = cache_type_letter(ts)
        if self.type != "I" and os.path.isfile(path + "/write_policy"):
            self.write_policy = file_word(path + "/write_policy")
        # is level really an inherent property of a cache?
        # possibly a cache could be L3 for some cores and L4 for others.
        self.level = file_int(path + "/level")
        # there's also physical_line_partition, power and uevent
        cpumap = file_hex(path + "/shared_cpu_map")
        self.cpus = intmask_list(cpumap)
        # check the other representation is equivalent
        # (and that our utils stringify the set in the canonical way)
        cpuliststr = file_word(path + "/shared_cpu_list")
        assert cpumap == cpusetstr_mask(cpuliststr), "mismatch: 0x%x %s" % (cpumap, cpuliststr)
        if check_cpusetstr:
            assert cpuliststr == mask_cpusetstr(cpumap), "mismatch: %s 0x%x" % (cpuliststr, cpumap)

    def is_private(self):
        # Test if the cache is exclusive to a processing element.
        # On a multithreaded core with L1 shared between threads, there are
        # no private caches.
        return len(self.cpus) == 1

    def is_LLC(self):
        # Return true if the cache is a last-level cache. Note that a LLC
        # is not necessarily shared between all CPUs.
        return self.parent is None

    def is_package(self):
        # Check if this is a package-level cache.
        # This will be a last-level cache unless there is an off-chip cache shared
        # between packages.
        # Small systems might have higher levels of cache shared between all CPUs;
        # in a single-CPU system, even the L1 is shared between "all CPUs".
        # In that case we only return the outermost cache. That is, there is
        # at most one package cache per CPU.
        p = self.system.cpu(self.cpus[0]).package_id
        is_all_package = (self.system.package_cpulist(p) == self.cpus)
        if is_all_package != self.is_LLC():
            print("unexpected: %s, is_package=%s, parent=%s" % (self, is_all_package, self.parent))
            print("  package:   %s" % list_cpusetstr(CPUlist_to_cpulist(self.system.cpus_by_package[p])))
            print("  self.cpus: %s" % list_cpusetstr(self.cpus))
        return is_all_package

    def type_str(self):
        return "L%u%s" % (self.level, self.type)

    def geometry_str(self):
        if self.size is not None:
            geom = memsize_str(self.size)
            if self.ways is not None:
                geom += " %u-way" % self.ways
        else:
            geom = "unknown geometry"
        if self.line_size is not None:
            geom += " %ub-line" % self.line_size
        return geom

    def __str__(self):
        s = "%s %s" % (self.type_str(), self.geometry_str())
        s += " " + ["shared","private"][self.is_private()]
        s += " for CPU %s" % mask_cpusetstr(self.cpu_mask())
        return s


def read_sys_cpus():
    """
    Read /sys/devices, returning a list of CPUs.
    """
    # /sys/bus/cpu/devices contains just the CPU nodes
    devdir = "/sys/bus/cpu/devices"
    if not os.path.exists(devdir):
        # /sys/devices/system/cpu contains the CPU nodes plus other stuff
        devdir = "/sys/devices/system/cpu"
        assert os.path.exists(devdir)
    for d in os.listdir(devdir):
        if not (d.startswith("cpu") and len(d) >= 4 and d[3].isdigit()):
            continue
        cpuno = int(d[3:])
        cd = devdir + "/" + d
        yield (cpuno, cd)


# TBD this doesn't really belong here

ARM_ARM_cpuid_map = {
    0xc07: "Cortex-A7",
    0xc0f: "Cortex-A15",
    0xd03: "Cortex-A53",
    0xd07: "Cortex-A57",
    0xd08: "Cortex-A72",
    0xd0c: "Neoverse N1",
    0xd40: "Neoverse V1",
    0xd49: "Neoverse N2",
    0xd4f: "Neoverse V2",
}

ARM_experimental_cpuid_map = {
    0x412: "Rainier",
}

#
# Arm architecture implementer codes.
#
# Generally these are ASCII characters inspired by the
# manufacturer name.
#
# These are tabulated in the ARM ARM under the specification
# the Main ID Register (MIDR).
#
ARM_implementer = {
    0x3f: ("Arm-int",   ARM_experimental_cpuid_map),
    0x41: ("Arm",       ARM_ARM_cpuid_map),
    0x42: ("Broadcom",  {}),
    0x43: ("Cavium",    {0x0a1: "ThunderX"}),
    0x44: ("DEC",       {}),
    0x46: ("Fujitsu",   {}),
    0x48: ("Huawei",    {}),
    0x49: ("Infineon",  {}),
    0x4d: ("Motorola/Freescale",  {}),
    0x4e: ("NVIDIA",    {0x003: "Denver"}),
    0x50: ("APM",       {}),
    0x51: ("Qualcomm",  {}),
    0x56: ("Marvell",   {}),
    0x69: ("Intel",     {})
}


class CPU:
    """
    Describe a single architectural CPU - i.e. a CPU as seen by the OS.
    In Arm terminology a CPU is a Processing Element (PE).
    On normal SMT systems (e.g. Intel and Arm) where threads have their
    own architectural and MMU context, a thread is regarded as a CPU.
    Thus, on SMT systems, CPUs may share first-level caches.
    """
    def __init__(self, n, system=None):
        self.system = system  # back pointer to the complete (possibly multi-socket) system
        self.cpuno = int(n)   # CPU number as understood by the OS
        self.found_in_cpuinfo = False
        self.spec = None      # will be a CPUspec
        self.L1I = None       # first-level I-cache - may be shared if SMT
        self.L1D = None       # first-level D-cache - may be shared if SMT
        self.core_id = None   # core id in sysfs topology - not necessarily unique
        self.numa_node = None # NUMA node number
        self.package = None   # package number (not NUMA node number)
        self.freq_min = None
        self.freq_max = None

    def __str__(self):
        return "CPU#%u" % self.cpuno

    def cpu_mask(self):
        """
        The singleton mask for this CPU.
        """
        return 1 << self.cpuno

    def sysfs(self):
        s = "/sys/devices/system/cpu/cpu" + int(self.cpuno)
        assert os.path.isdir(s)
        return s

    def is_online(self):
        return self.found_in_cpuinfo

    def cache(self, level, type):
        """
        Return the CPU's affiliated cache for a given type at the given level.
        The cache may be unified, e.g. if we ask for I$ at level 3 we will likely
        get a unified L3 cache rather than an instruction-only cache.
        The result will be a Cache object, or None.
        """
        assert type in "IDU"
        res = None
        for c in self.caches():
            if c.level == level and c.contains(type):
                assert res is None, "cache overlap: %s vs. %s" % (res, c)
                res = c
        return res

    def cache_path(self, cache_type):
        for i in range(1, 10):
            c = self.cache(i, cache_type)
            assert not (i == 0 and c is None), "missing cache L%u%s for %s" % (i, cache_type, str(self))
            if c is None:
                break
            yield c

    def LLC(self):
        """
        Return the last-level cache for this CPU. The LLC is not necessarily shared
        between all CPUs (e.g. on multi-socket), and is not necessarily the
        same size or at the same level as other CPUs' LLC.
        """
        for c in self.caches():
            if c.is_LLC():
                return c
        return None

    def caches(self):
        """
        Return all caches seen by this CPU, in arbitrary order
        """
        for c in self.system.caches():
            if c.for_cpu(self.cpuno):
                yield c


def freq_range(x):
    def freq(n):
        return "%.1fGHz" % (n/1e9)
    s = freq(x.freq_min)
    if x.freq_min != x.freq_max:
        s += "-" + freq(x.freq_max)
    return s


def CPUlist_to_cpulist(cl):
    return [c.cpuno for c in cl]


def physical_memory():
    """
    Return physical memory size in bytes
    """
    m1 = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    with open("/proc/meminfo") as f:
        for ln in f:
            if ln.startswith("MemTotal:"):
                x = ln.split()
                m2 = int(x[1])
                if x[2] == "kB":
                    m2 *= 1024
                else:
                    assert False
    assert m1 == m2, "physical memory mismatch: %u vs. %u " % (m1, m2)
    return m1


class Group:
    """
    A group of system components, e.g. a node, cluster, core etc.
    Within a group are:
      - subgroups
      - system components (e.g. caches) that don't belong to a subgroup
    A group is uniquely keyed by its CPU mask.
    There will be one top-level group.
    The top-level group need not contain any components,
    but other groups will.
    """
    def __init__(self, mask, system=None):
        self.cpumask = mask
        self.system = system
        self.parent = None
        self.subgroups = []
        self.caches = []     # Caches at this level (no deeper)

    def cpu_mask(self):
        return self.cpumask


class System:
    """
    Description of a system.
    Briefly, a system consists of
      - a set of CPUs
      - a set of CPU descriptions (usually 1)
      - a set of Caches
      - topological relationship between all the above
    """
    def __init__(self):
        self.discover()

    def discover(self):
        if o_verbose:
            print("discovering system topology...", file=sys.stderr)
        self.arch = platform.machine()
        self.phys_mem = physical_memory()
        self.cpus_by_number = {}      # map CPU number to CPUspec
        self.caches_by_key = {}
        self.spec_to_cpulist = {}     # map CPU spec to list of CPUs
        self.max_cpuno = 0
        self.n_cpus_online = 0
        self.cpus_by_core = {}        # map 'core_id' -> CPU
        self.cpus_by_node = {}        # map NUMA node number -> CPU
        self.cpus_by_package = {}
        self.groups_by_cpumask = {}
        allcpu_mask = 0
        # First, gather information from /proc/cpuinfo.
        # This can be problematic given the looseness of the format.
        # But it does tell us things like CPU identifier and features.
        for (cpuno, keys) in read_proc_cpuinfo():
            if o_verbose:
                print("CPU %u: %s" % (cpuno, keys), file=sys.stderr)
            allcpu_mask |= (1 << cpuno)
            if self.max_cpuno < cpuno:
                self.max_cpuno = cpuno
            cpu = CPU(cpuno, system=self)
            self.cpus_by_number[cpuno] = cpu
            cpu.found_in_cpuinfo = True
            self.n_cpus_online += 1
            spec = self.spec_from_keys(keys)
            assert spec is not None, "could not get spec: %s" % (keys)
            cpu.spec = spec
            if spec not in self.spec_to_cpulist:
                self.spec_to_cpulist[spec] = []
            self.spec_to_cpulist[spec].append(cpuno)
        # Now iterate through the CPU nodes in the device graph
        for (cpuno, cd) in read_sys_cpus():
            allcpu_mask |= (1 << cpuno)
            if self.max_cpuno < cpuno:
                self.max_cpuno = cpuno
            if cpuno in self.cpus_by_number:
                cpu = self.cpus_by_number[cpuno]
            else:
                # This wasn't listed in /proc/cpuinfo. Maybe offline?
                cpu = CPU(cpuno, system=self)
                self.cpus_by_number[cpuno] = cpu
            if os.path.isdir(cd + "/topology"):
                # The topology ids are quite arbitrary and probably not useful.
                # They might be a component of the MPIDR (and hence not system-wide unique)
                # or they might be the offset of the CPU or other level's entry in the ACPI PPTT.
                cpu.core_id = file_int(cd + "/topology/core_id")
                if cpu.core_id not in self.cpus_by_core:
                    self.cpus_by_core[cpu.core_id] = []
                self.cpus_by_core[cpu.core_id].append(cpu)
                cpu.package_id = file_int(cd + "/topology/physical_package_id")
                if cpu.package_id not in self.cpus_by_package:
                    self.cpus_by_package[cpu.package_id] = []
                self.cpus_by_package[cpu.package_id].append(cpu)
                # The CPU node should have had a link to the relevant package
                # We are assuming "physical package id" and "node id" are the same (TBD)
                # not populated on Arm
                #assert os.path.isdir(cd + ("/node%u" % cpu.package))
            if os.path.isdir(cd + "/cpufreq"):
                try:
                    cpu.freq_min = file_int(cd + "/cpufreq/cpuinfo_min_freq") * 1e3
                    cpu.freq_max = file_int(cd + "/cpufreq/cpuinfo_max_freq") * 1e3
                except Exception:
                    pass
            caches = cd + "/cache"
            if not os.path.exists(caches):
                # No cache information available
                continue
            # List all caches for this CPU
            # We scan the 'index*' subdirectories of the cpu<n>/cache/ directory.
            # listdir yields them in random order. Typically 'index0' and 'index1'
            # are L1D and L1I while 'index2' is L2.
            caches_for_this_cpu = []
            for c in os.listdir(caches):
                if not c.startswith("index"):
                    continue
                cpath = caches + "/" + c
                ckey = cache_key(cpath)
                if ckey not in self.caches_by_key:
                    cache = Cache(cpath, system=self)
                    self.caches_by_key[ckey] = cache
                    cache_group = self.group(cache.cpu_mask())
                    cache_group.caches.append(cache)
                else:
                    # shared cache - already seen
                    cache = self.caches_by_key[ckey]
                if cache.level == 1:
                    if cache.contains("I"):
                        cpu.L1I = cache
                    if cache.contains("D"):
                        cpu.L1D = cache
                caches_for_this_cpu.append(cache)
            # Fix up cache parent pointers
            for c in caches_for_this_cpu:
                for cp in caches_for_this_cpu:
                    if cp.level == c.level + 1 and (c.type == "U" or cp.contains(c.type)):
                        assert c.parent is None or c.parent == cp
                        c.parent = cp
        assert self.cpus_by_number
        assert self.spec_to_cpulist
        # add NUMA structure
        for n in itertools.count():
            node = "/sys/devices/system/node/node%u" % n
            if not os.path.exists(node):
                # Maybe built with CONFIG_NUMA=n
                break
            node_cpus = intmask_list(cpusetstr_mask(file_word(node + "/cpulist")))
            self.cpus_by_node[n] = node_cpus
            for i in node_cpus:
                c = self.cpus_by_number[i]
                c.numa_node = n
        self.top = self.group(allcpu_mask)
        # all the groups have been created, but the parent/subgroup links need to be be fixed up
        def is_subset(a, b):
            return (a & b) == a
        for (gk, g) in self.groups_by_cpumask.items():
            if gk == allcpu_mask:
                continue
            best_parent = self.top
            for (gpk, gp) in self.groups_by_cpumask.items():
                if gpk == gk:
                    continue
                if is_subset(g.cpu_mask(), gp.cpu_mask()) and is_subset(gp.cpu_mask(), best_parent.cpu_mask()):
                    best_parent = gp
            g.parent = best_parent
            best_parent.subgroups.append(g)
        for g in self.groups_by_cpumask.values():
            for gs in g.subgroups:
                assert gs.parent == g

    def group(self, mask):
        """
        Create a group for a given mask. This isn't yet inserted into the hierarchy.
        """
        if mask not in self.groups_by_cpumask:
            self.groups_by_cpumask[mask] = Group(mask, system=self)
        return self.groups_by_cpumask[mask]

    def cpu(self, n):
        # Return a CPU object, by number
        return self.cpus_by_number[n]

    def cpu_mask(self):
        return self.top.cpu_mask()

    def cpus(self, online_only=True):
        # Yield a list of CPU objects
        for i in range(0, self.n_cpus()):
            cpu = self.cpu(i)
            if (not online_only) or cpu.is_online():
                yield cpu

    def spec_from_keys(self, keys):
        """
        Given a set of keys from /proc/cpuinfo, return a CPU type specification.
        """
        spec = None
        arch = self.arch    # platform.machine()
        if arch == "x86_64":
            family = int(keys["cpu family"])      # always 6, on any modern Intel system; e.g. 25 for AMD
            model = int(keys["model"])
            model_sku = keys["model name"]
            model_code = (family << 8) + model
            model_name = "Family %u model %u" % (family, model)
            imp = keys["vendor_id"]
            if imp == "GenuineIntel":
                imp = "Intel"
                if family == 6:
                    model_name = "Model %u" % model
            elif imp == "AuthenticAMD":
                imp = "AMD"
            stepping = int(keys["stepping"])
            features = keys["flags"].split()
            spec = CPUspec(implementer=imp, model=model_name, model_code=model_code, sku=model_sku, stepping=stepping, features=features)
        elif arch == "aarch64" or arch in ["armv7l","armv8l"]:
            impcode = int(keys["CPU implementer"], 16)
            part = int(keys["CPU part"], 16)
            part_name = "Part 0x%03x" % part
            # /proc/cpuinfo doesn't give the product name, but we might be able to look it up
            if impcode in ARM_implementer:
                imp = ARM_implementer[impcode]
                imp_name = imp[0]
                if part in imp[1]:
                    part_name = imp[1][part]
            else:
                imp_name = "Implementer 0x%02x" % impcode
            cpu_variant = int(keys["CPU variant"], 16)
            cpu_revision = int(keys["CPU revision"])
            stepping = (cpu_variant, cpu_revision)
            features = keys["Features"].split()
            spec = CPUspec(implementer=imp_name, implementer_code=impcode, model=part_name, model_code=part, stepping=stepping, features=features)
        else:
            print("** could not get CPU specification (arch=%s)" % arch)
        if spec is not None:
            spec.arch = arch
        return spec

    def n_cpus(self, online_only=False):
        """
        This returns the number of CPUs we know about.
        Depending on how we discovered the CPUs there may be
        gaps in the CPU numbering.
        This number should match multiprocessing.cpu_count().
        """
        if not online_only:
            return len(self.cpus_by_number)
        else:
            return self.n_cpus_online

    def n_specs(self):
        """
        Number of distinct CPU types. This will generally be 1, except on
        heterogeneous (e.g. Arm big.LITTLE) systems.
        """
        return len(self.spec_to_cpulist)

    def n_nodes(self):
        """
        Number of NUMA nodes. Sometimes corresponds to packages, but not always.
        If the kernel has been built with CONFIG_NUMA=n, this will return 0.
        """
        return len(self.cpus_by_node)

    def n_packages(self):
        """
        Number of physical packages (loosely: sockets).
        """
        return len(self.cpus_by_package)

    def package_cpulist(self, p):
        return sorted(CPUlist_to_cpulist(self.cpus_by_package[p]))

    def cpu_specs(self):
        return self.spec_to_cpulist.keys()

    def has_cpu_feature(self, feature):
        for cs in self.cpu_specs():
            if not cs.has_feature(feature):
                return False
        return True

    def is_heterogeneous(self):
        assert self.spec_to_cpulist
        if len(self.spec_to_cpulist) > 1:
            return True
        if len(self.spec_to_cpulist) == 1:
            # if some CPUs are missing, we can't really tell
            assert not self.is_missing_cpus()
            return False

    def is_missing_cpus(self):
        return self.n_cpus() < self.max_cpuno

    def caches(self):
        return sorted(self.caches_by_key.values())

    def cache_level_max(self):
        return max([c.level for c in self.caches_by_key.values()])

    def show(self, show_features=False):
        print("System specification:")
        print("  Architecture: %s" % self.arch)
        print("  Total cores: %u" % self.n_cpus())
        print("  NUMA nodes: %u" % self.n_nodes())   # 0 indicates CONFIG_NUMA=n
        print("  Packages: %u" % self.n_packages())
        # for each CPU, print its information
        print("  CPU specifications:")
        for (spec, cpus) in self.spec_to_cpulist.items():
            # CPUs must be homogeneous in architecture at least
            assert spec.arch == self.arch
            print("    Specification:", spec.str_full())
            if show_features:
                print("    Features:", ' '.join(spec.features))
            print("      CPUs:", mask_cpusetstr(intlist_mask(cpus)))
            cpurep = self.cpu(cpus[0])
            if cpurep.freq_min is not None:
                print("      Frequency: %s" % freq_range(cpurep))
        if self.is_heterogeneous():
            print("  System is heterogeneous")
        elif self.is_missing_cpus():
            print("  Some CPUs missing information")
        else:
            print("  System is homogeneous")
        print("  Physical memory: %s" % memsize_str(self.phys_mem))

    def show_caches(self):
        print("  Caches:")
        mc = self.cache_level_max()
        for cache in self.caches():
            print("    %s%s" % (("  "*(mc-cache.level)), cache))

    def show_cpus(self):
        print("  CPUs:")
        for cpu in self.cpus():
            print("    %s" % cpu, end="")
            if self.is_heterogeneous():
                print(": %s" % (cpu.spec), end="")
            if self.n_nodes() > 1:
                print(" (NUMA node %s)" % cpu.numa_node, end="")
            print()
            for cache in cpu.caches():
                print("      %s" % cache)


g_system = None


def system():
    """
    Return the system configuration for this system,
    discovering it if not already discovered.
    """
    global g_system
    if g_system is None:
        g_system = System()
    return g_system


def lstopo(s):
    """
    Emulate lstopo from the hwloc package
    To check we're discovering the same things
    """
    print("Machine (%s)" % memsize_str(s.phys_mem, "B"))
    def cache_short(c):
        s = "L%u" % c.level
        if not c.is_unified():
            s += c.type.lower()
        if c.size is not None:
            s += " (%s)" % memsize_str(c.size, "B")
        return s
    def list_group(g, level=0):
        assert s.groups_by_cpumask[g.cpu_mask()] == g
        print("  %sGroup" % ("  "*level), end=" ")
        if o_verbose:
            print("[group level %u]" % level, end=" ")
        for c in g.caches:
            print(cache_short(c), end=" ")
        print()
        if not g.subgroups:
            for cpuno in intmask_list(g.cpu_mask()):
                print("    %sPU P#%u" % ("  "*level, cpuno))
        for sg in g.subgroups:
            assert sg.cpu_mask() != g.cpu_mask()
            assert (sg.cpu_mask() & ~g.cpu_mask()) == 0
            list_group(sg, level+1)
    list_group(s.top)
    if False:
        def cache_path_str(cp):
            return " -> ".join([str(c) for c in cp])
        print("CPUs:")
        for c in s.cpus():
            print("  %s: %s; %s" % (str(c), cache_path_str(c.cache_path('I')), cache_path_str(c.cache_path('D'))))


def lstopo_check():
    print("lstopo:")
    os.system("lstopo --no-io -p --of console")
    print("our discovery:")
    lstopo(system())


def system_summary(S):
    """
    Generate a one-line summary of the system
    """
    s = "Sockets: %u  CPUs: %4u  Memory: %10s" % (S.n_packages(), S.n_cpus(), memsize_str(physical_memory(), unit="G"))
    for sp in S.spec_to_cpulist:
        cpus = S.spec_to_cpulist[sp]
        s += "  %s x %u" % (sp.str_compact(), len(cpus))
    return s


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CPU discovery")
    parser.add_argument("--compact", action="store_true", help="compact output")
    parser.add_argument("--cache", action="store_true", help="show cache details")
    parser.add_argument("--cpus", action="store_true", help="list CPUs")
    parser.add_argument("--features", action="store_true", help="show features")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_compact = opts.compact
    o_show_features = opts.features
    o_list_cpus = opts.cpus
    o_list_cache = opts.cache
    o_check = opts.check
    o_verbose = opts.verbose
    S = system()
    if o_compact:
        print(system_summary(S))
        for c in S.caches():
            if c.is_package():
                print("  LLC: %10s  %s" % (memsize_str(c.size), mask_cpusetstr(c.cpu_mask())))
    else:
        S.show(show_features=o_show_features)
        if o_list_cpus:
            S.show_cpus()
        if o_list_cache:
            S.show_caches()
    if o_check:
        lstopo_check()
