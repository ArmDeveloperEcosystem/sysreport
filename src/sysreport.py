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
General system information, beyond what the platform module does.
E.g. cache sizes.

Some of this information might require sudo powers.

Similar to lscpu, but

 - prints more information about software configuration, particularly perf features

 - gives advice on what to change to enable more perf features

 - (TBD) better reporting of heterogeneous/asymmetric systems
"""

from __future__ import print_function

import os, sys, platform, subprocess, multiprocessing, json, datetime, struct
# import gzip for reading /proc/config.gz
try:
    import gzip
except ImportError:
    pass

import cpulist

import strcolor
from strcolor import colorize

_is_arm = (platform.machine() in ["armv8l", "aarch64"])

o_verbose = 0


def file_data(fn):
    s = None
    if os.path.isfile(fn):
        with open(fn) as f:
            s = f.read().strip()
    return s


def file_int(fn):
    d = file_data(fn)
    return int(d) if d is not None else None


def colorize_redzero(s):
    return colorize(s, "red" if s == 0 else "green")


def colorize_greenred(s):
    return colorize(s, "red" if s is None else "green")


def colorize_abled(s):
    if s is not None:
        return colorize(["disabled", "enabled"][s], ["red", "green"][s])
    else:
        return "n/a"


def is_superuser():
    return os.geteuid() == 0


def kernel_config_file():
    """
    Return the filename of the (compressed or uncompressed) kernel config file, or None.
    """
    if os.path.exists("/proc/config.gz"):
        return "/proc/config.gz"
    bconf = "/boot/config-" + platform.release()
    if os.path.exists(bconf):
        return bconf
    return None


def kernel_config():
    """
    Return a map containing the current kernel configuration variables:
      { "CONFIG_XYZ": "y", ... }
    """
    fn = kernel_config_file()
    if fn is None:
        return None
    try:
        if fn.endswith(".gz"):
            f = gzip.open(fn, mode="r")
        else:
            f = open(fn)
    except Exception:
        return None
    ck = {}
    s = f.read()
    try:
        s = s.decode()
    except Exception:
        pass
    for ln in s.split("\n"):
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        ix = ln.index('=')
        ck[ln[:ix]] = ln[ix+1:]
    f.close()
    return ck


def run_cmd(cmd):
    if o_verbose:
        print(">>> %s" % (cmd), file=sys.stderr)
    args = cmd.split()
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = p.communicate()
    return (out, err)


def backtick(cmd):
    """
    Return the result of executing a command, e.g. backtick("uname -r") == "5.4.0".
    """
    (out, err) = run_cmd(cmd)
    return out


def file_data_keys(fn):
    """
    Create a Python map from a file of the form
      a=b
      c=d
    """
    s = file_data(fn)
    if s is None:
        return None
    lr = s.split("\n")
    data = {}
    for ln in lr:
        ix = ln.find('=')
        if ix > 0:
            name = ln[:ix]
            value = ln[ix+1:].strip()
            if value.startswith('"'):
                value = value[1:-1]
            data[name] = value
    return data


def file_data_key(fn, k):
    m = file_data_keys(fn)
    if m is not None and k in m:
        return m[k]
    else:
        return None


def find_file_in_tree(d, fn):
    """
    If a file is found anywhere in a directory tree, return the first one found.
    Otherwise, return None. To avoid recursion, don't follow links.
    """
    for (dp, dirs, files) in os.walk(d):
        if fn in files:
            return os.path.join(dp, fn)
    return None


def iomem_areas(toplevel=False):
    """
    Return the names of areas described in /proc/iomem. As non-root, we don't see the addresses.
    """
    areas = {}
    with open("/proc/iomem") as f:
        for ln in f:
            if toplevel and ln.startswith(' '):
                continue
            area = ln.strip().split(' : ')[1]
            areas[area] = True
    return areas.keys()


def acpi_irqs():
    """
    Get the IRQ numbers for PMU, SPE and TRBE from the APIC table.
    Not applicable to non-Arm, or to DT systems.
    """
    if not _is_arm:
        return None
    if not is_superuser():
        return None
    try:
        irqs = {}
        with open("/sys/firmware/acpi/tables/APIC", "rb") as f:
            f.read(4)          # signature (b"APIC")
            hdr = f.read(32)   # general ACPI header
            f.read(8)          # APIC
            while True:
                ih = f.read(2)
                if not ih:
                    break
                (itype, ilen) = struct.unpack("<BB", ih)
                id = ih + f.read(ilen-2)
                if itype == 0xB:
                    (_, _, _, _, _, pmu_irq, _, _, _, _, _, _, _, _, _, spe_irq) = struct.unpack("<IIIIIIQQQQIQQBBH", id[:80])
                    if pmu_irq:
                        irqs["PMU"] = pmu_irq
                    if spe_irq:
                        irqs["SPE"] = spe_irq
                    if len(id) >= 82:
                        trbe_irq = struct.unpack("<H", id[80:82])[0]
                        if trbe_irq:
                            irqs["TRBE"] = trbe_irq
                    break     # stop at first GICC
    except Exception:
        return None
    return irqs


_arm_cpu_arch = {
    (0x41, 0xd03): (8, 0),   # Cortex-A53
    (0x41, 0xd07): (8, 0),   # Cortex-A57
    (0x41, 0xd08): (8, 0),   # Cortex-A72
    (0x41, 0xd0c): (8, 2),   # Neoverse N1
    (0x41, 0xd40): (8, 4),   # Neoverse V1
    (0x41, 0xd49): (9, 0),   # Neoverse N2
    (0x41, 0xd4f): (9, 0),   # Neoverse V2
}

def arm_arch(s):
    """
    Arm: Try to deduce Arm architecture (v8.4, v9.2 etc.) from CPU types.
    """
    arch = None
    for spec in s.cpu_types():
        key = (spec.implementer_code, spec.model_code)
        if key in _arm_cpu_arch:
            narch = _arm_cpu_arch[key]
            assert not (arch is not None and arch != narch), "mismatch: %s vs. %s" % (str(arch), str(narch))
            arch = narch
    return arch


class System:
    """
    Miscellaneous information about a complete system.
    """
    def __init__(self):
        self.system = cpulist.system()
        if _is_arm:
            self.arm_arch = arm_arch(self)
        self.kernel_config = kernel_config()
        self.cached_vulnerabilities = None
        self.cached_irqs = None
        self._perf_max_counters = None

    def cpu_types(self):
        """
        Return a list of CPU types. This will only contain more than one
        entry for heterogeneous (big.LITTLE) systems.
        It is not indexed by CPU number.
        """
        return self.system.spec_to_cpulist.keys()

    def architecture(self):
        if _is_arm and self.arm_arch is not None:
            (ma, mi) = self.arm_arch
            return "ARMv%u.%u" % (ma, mi)
        else:
            return platform.machine()

    def is_arm_architecture(self, ma, mi=0):
        return _is_arm and self.arm_arch is not None and self.arm_arch >= (ma, mi)

    def get_distribution(self):
        """
        Return a free-format string describing the distribution.
        """
        s = file_data("/etc/redhat-release")
        if s is not None:
            s = s.replace("Red Hat Enterprise Linux", "RHEL")
            s = s.replace(" release", "")
            if s.endswith(")"):
                s = s[:s.index(" (")]
            return s
        s = file_data_key("/etc/lsb-release", "DISTRIB_DESCRIPTION")
        if s is not None:
            return s
        s = file_data_key("/etc/os-release", "NAME")
        if s is not None:
            return s
        try:
            dist = platform.linux_distribution()      # removed in Python 3.7
            s = "%s %s" % (dist[0].strip(), dist[1])
        except Exception:
            s = "<unknown>"
        return s

    def get_kernel_version(self):
        """
        Get kernel version, as a string, e.g. "6.5.1-rc7" returns "6.5.1"
        """
        s = platform.release()
        ix = s.find('-')
        if ix >= 0:
            s = s[:ix]
        return s

    def get_kernel_maj_min(self):
        """
        Get kernel version as a tuple, e.g. (6, 5)
        """
        v = self.get_kernel_version().split('.')
        return (int(v[0]), int(v[1]))

    def is_kernel_at_least(self, v):
        return self.get_kernel_maj_min() >= v

    def get_kernel_config(self, var, default=None):
        assert var.startswith("CONFIG_")
        if self.kernel_config is not None:
            if var in self.kernel_config:
                return self.kernel_config[var]
        return default

    def kernel_config_enabled(self, var):
        return self.get_kernel_config(var) in ["y", "m"]

    def has_loadable_kernel_module(self, ko):
        """
        Check if a loadable kernel module is present in /lib/modules.
        Caller must know the full path (starting with "kernel").
        """
        assert ko.endswith(".ko")
        mdir = "/lib/modules/" + platform.release()
        return find_file_in_tree(mdir, ko)

    def get_cache_line_size(self):
        """
        Even if cache info isn't available under /sys/bus/cpu, we ought to be
        able to get cache line size.
        """
        try:
            r = backtick("getconf LEVEL1_DCACHE_LINESIZE")
        except FileNotFoundError:
            # minimal busybox system might lack getconf
            return None
        return int(r)

    def get_libc_version(self):
        lv = platform.libc_ver()
        return "%s %s" % (lv[0], lv[1])

    def get_cpu_count(self, online_only=True):
        # Get the number of online CPUs
        n1 = self.system.n_cpus(online_only=online_only)
        if online_only:
            n2 = multiprocessing.cpu_count()
            assert n1 == n2, "mismatch on number of CPUs: %s vs %s" % (n1, n2)
        return n1

    def irqs(self):
        """
        Arm: get the IRQ numbers for performance features. This tells us whether
        the features are exposed by firmware (or hypervisor, in the case of a guest).
        """
        if self.cached_irqs is None:
            irqs = acpi_irqs()
            if irqs is None:
                irqs = {}        # distinguish not yet obtained from n/a
            self.cached_irqs = irqs
        return self.cached_irqs

    def has_irq(self, s):
        """
        Check if an IRQ is registered, for PMU, SPE or TRBE
        """
        return s in self.irqs()

    def perf_max_counters(self):
        if self._perf_max_counters is None:
            self._perf_max_counters = perf_max_counters()
        return self._perf_max_counters

    def vulnerabilities(self):
        if self.cached_vulnerabilities is None:
            self.cached_vulnerabilities = {}
            vd = "/sys/devices/system/cpu/vulnerabilities"
            if os.path.isdir(vd):
                for rd in os.listdir(vd):
                    d = os.path.join(vd, rd)
                    try:
                        vul = file_data(d)
                    except IOError:
                        vul = None
                    self.cached_vulnerabilities[rd] = vul
        return self.cached_vulnerabilities

    def is_KPTI_enabled(self):
        for vm in self.vulnerabilities().values():
            if vm is None:
                return None
            if vm == "Mitigation: PTI":
                return True
        return False

    def get_lockdown(self):
        ld = self.get_kernel_config("CONFIG_LSM")
        if ld is not None:
            if ld[0] == '"':
                ld = ld[1:-1]
            ld = ld.split(',')
        return ld

    def system_interconnect(self):
        """
        Check if this system has an Arm CMN interconnect, by looking at /proc/iomem.
        There seems to be no better way than looking for specific ACPI ids.
        We'll assume that if a system does have CMN, it will be homogeneous.
        """
        itype = None
        n = 1
        for a in iomem_areas(toplevel=True):
            a = a.split(':')[0]
            if a in ["ARMHC600", "ARMHC650", "ARMHC700"]:
                t = "CMN-" + a[5:]
                if itype is None:
                    itype = t
                elif t == itype:
                    n += 1
                else:
                    itype = "<mixed?>"
                    n += 1
        return (itype, n)

    def has_CMN_interconnect(self):
        """
        Return true if the system has an Arm CMN interconnect of any kind.
        """
        if has_event_source("arm_cmn_0"):
            # If the arm-cmn PMU driver is enabled, there must be a CMN.
            return True
        # Otherwise, scan for interconnects.
        (ic, n) = self.system_interconnect()
        return ic is not None and ic.startswith("CMN-")

    def has_MPAM(self):
        return self.get_kernel_config("CONFIG_MPAM") == "y"

    def has_resctrl(self):
        return os.path.exists("/sys/fs/resctrl")

    def cpu_has_SPE(self):
        """
        Report if the system has Arm's SPE (Statistical Profiling Extension).
        This is not exposed as a HWCAP and we can't infer it from architecture level,
        because mobile cores tend not to have it. We have to do it by model name/number.
        Also report (by returning -1) if the implementation is known to be biased.
        """
        spe_type = 0       # not present
        for ct in self.cpu_types():
            if ct.str_full().startswith("Arm Neoverse"):
                if spe_type == 0:
                    spe_type = 1
                if ct.implementer_code == 0x41:
                    if ct.model_code == 0xd0c and ct.stepping < (4, 1):
                        spe_type = -1    # erratum 1694299
                    elif ct.model_code == 0xd40 and ct.stepping < (1, 1):
                        spe_type = -1    # erratum 1694300
        return spe_type


def kernel_build_dir(check=True):
    dir = "/lib/modules/" + platform.release() + "/build"
    if check and not os.path.isdir(dir):
        return None
    return dir


def pyperf_installed():
    """
    Check if we can use perf events, using the pyperf module.
    """
    try:
        sys.path.append(os.path.join(os.path.dirname(__file__), "pyperf"))
        import perf_enum, perf_attr, perf_events
    except ImportError:
        return None   # unknown
    try:
        e = perf_events.Event(perf_attr.PerfEventAttr(type=perf_enum.PERF_TYPE_HARDWARE, config=perf_enum.PERF_COUNT_HW_INSTRUCTIONS).bytes())
        ok = e is not None
        del e
        return ok
    except Exception:
        return False


g_perf_installed = None


def perf_binary():
    """
    Get the canonical location of the perf binary. This might not exist.
    """
    return "/usr/lib/linux-tools/" + platform.release() + "/perf"


def perf_binary_imports(lib):
    p = subprocess.Popen(["ldd", perf_binary()], stdout=subprocess.PIPE)
    (out, err) = p.communicate()
    return lib in out.decode()


def perf_binary_has_opencsd():
    return perf_binary_imports("libopencsd.so")


def perf_installed():
    """
    Check whether perf command-line tools are installed.
    """
    global g_perf_installed
    if g_perf_installed is not None:
        return g_perf_installed
    rc = os.system("perf stat -- true >/dev/null 2>/dev/null")
    g_perf_installed = (rc == 0)
    return rc == 0


def perf_max_counters():
    """
    Find out how many hardware PMU counters are available, by creating successively larger groups.
    As non-weak groups (not marked with 'W'), these should not fall back to ungrouped.
    But perf won't report failure to create a group via the return code,
    so we have to process the output.

    Note: this may under-report if there is other perf activity on the system,
    e.g. a privileged user running a perf command that pins system-wide counters.

    Currently this depends on perf tools being installed.
    We could make it more robust by using perf_event_open (via ctypes).

    We use instructions as a proxy for general-purpose counters.
    The dedicated cycle counter is not included.
    """
    if not perf_installed():
        return None
    for i in range(1, 31):
        # Use braces to ensure that counters are scheduled as a group.
        events = "{" + ",".join(["instructions:u"]*i) + "}"
        cmd = "perf stat -x, -e " + events + " -- true"
        (out, err) = run_cmd(cmd)
        if err.decode().startswith("<not"):
            return i - 1
    return None


def perf_event_paranoid():
    return file_int("/proc/sys/kernel/perf_event_paranoid")


def kptr_restrict():
    try:
        return file_int("/proc/sys/kernel/kptr_restrict")
    except Exception:
        return None


def has_event_source(s):
    # /sys/bus/event_source/devices contains links to /sys/devices,
    # for those devices which provide events
    return os.path.exists("/sys/bus/event_source/devices/" + s)


def perf_precise_sampling(s):
    if platform.machine() == "x86_64":
        if s.system.has_cpu_feature("pebs"):
            return "PEBS"
    return None


def perf_noninvasive_sampling(s):
    if _is_arm:
        if has_event_source("arm_spe_0"):
            return "SPE"
        # It might be disabled because kpti is enabled
    return None


def perf_hardware_trace(s):
    """
    Return true if the platform supports non-invasive program flow tracing,
    e.g. Arm ETM/ETE, or Intel PT.
    """
    if platform.machine() == "x86_64":
        if s.system.has_cpu_feature("intel_pt"):
            return "PT"
    elif _is_arm:
        if os.path.exists("/sys/bus/event_source/devices/cs_etm"):
            # Sometimes we see cs_etm PMU but no trace sources.
            if list(os.listdir("/sys/bus/coresight/devices")):
                return "ETM"
    return None


def perf_user_access(s):
    return file_int("/proc/sys/kernel/perf_user_access")


def perf_interconnect(s):
    """
    Return true if interconnect performance metrics are available, None if unknown.
    """
    if _is_arm:
        if s.has_CMN_interconnect():
            return has_event_source("arm_cmn_0")
        else:
            return None    # other interconnect - don't know
    else:
        return None


def boot_info_type():
    s = None
    # Either /sys/firmware/acpi or /proc/acpi seems to work as a test for ACPI.
    # /proc/acpi is often empty though.
    if os.path.isdir("/sys/firmware/acpi"):
        s = "ACPI"
    if os.path.isdir("/proc/device-tree"):
        assert s is None
        s = "DT"
    return s


def cache_info():
    """
    Report what kind of information is available about cache geometry.
    """
    # sc = "/sys/bus/cpu/devices/cpu0/cache"
    sc = "/sys/devices/system/cpu/cpu0/cache"
    if os.path.isdir(sc):
        s0 = sc + "/index0"
        cl = []
        if os.path.isfile(s0 + "/size"):
            cl.append("size")
        if os.path.isfile(s0 + "/ways_of_associativity"):
            cl.append("associativity")
        if os.path.isfile(s0 + "/shared_cpu_list"):
            cl.append("sharing")
        if not cl:
            return None
        return ", ".join(cl)
    else:
        return None


def has_atomics(s):
    """
    Report whether the platform has atomic opertations such as atomic add.
    Load-exclusive/store-exclusive are not considered here.
    """
    if platform.machine() == "x86_64":
        return True
    else:
        return s.has_cpu_feature("atomics")


def kernel_uses_atomics(s):
    if not has_atomics(s.system):
        return False
    if platform.machine() == "aarch64":
        if s.kernel_config is not None:
            return s.kernel_config_enabled("CONFIG_ARM64_LSE_ATOMICS")
        else:
            return None
    else:
        return None


def kernel_hugepages(s, skip_zero=False):
    """
    Return a list of (page size, nr_hugepages) configured to the kernel.
    It's tempting to read /proc/sys/vm/nr_hugepages, but this only reports
    pages of a specific size.
    """
    # return file_int("/proc/sys/vm/nr_hugepages")
    hpdir = "/sys/kernel/mm/hugepages"
    for d in os.listdir(hpdir):
        if not d.startswith("hugepages-"):
            continue
        dp = os.path.join(hpdir, d)
        nr = file_int(dp + "/nr_hugepages")
        if nr > 0 or (not skip_zero):
            yield (d[10:], nr)


def kernel_hugepages_str(s, skip_zero=False):
    return ", ".join(["%s: %u" % (sz, nr) for (sz, nr) in kernel_hugepages(s, skip_zero=skip_zero)])


def kernel_thp(s):
    """
    Return the enablement state of transparent huge pages.
    If the kernel has been built with CONFIG_TRANSPARENT_HUGEPAGE=n the file
    below will not exist.
    """
    if not s.kernel_config_enabled("CONFIG_TRANSPARENT_HUGEPAGE"):
        return None
    hps = file_data("/sys/kernel/mm/transparent_hugepage/enabled")
    if hps is None:
        return None
    for h in hps.split():
        if h.startswith('['):
            return h[1:-1]
    return None


def lockdown_str(ld):
    if ld is not None:
        return ", ".join([str(s) for s in ld])
    else:
        return ld


def kernel_supports_bpf(s):
    """
    Check the kernel config for CONFIG_BPF - There might be other BPF config options we might want to check
    """
    return s.kernel_config_enabled("CONFIG_BPF")


def bpftool_installed(s):
    """
    Check whether the bpftool is installed and what it supports.
    On some systems it might exist as a script informing users how to install.
    """
    cmd = "/usr/sbin/bpftool"
    if os.path.exists(cmd):
        (out, err) = run_cmd(cmd + " -V")
        if err.decode().startswith("WARNING: bpftool not found"):
            # The bpftool exists as a script, essentially it's not installed.
            # Running it simply informs the user to install the tool
            return None
        else:
            # Strip the 'b' and replace the newline with a space so it's displayed on a single line
            return out.decode().replace('\n', ' ')
    else:
        return None


def bpftrace_installed(s):
    """
    Check whether the bpftrace tool is installed
    """
    cmd = "/usr/bin/bpftrace"
    if os.path.exists(cmd):
        (out, err) = run_cmd(cmd + " -V")
        return out.decode()
    else:
        return None


def vulnerabilities_str(vl):
    sl = []
    for (k, v) in vl.items():
        if v is None:
            # e.g. permission denied when we tried to read it
            sl.append("%s" % (k))
        elif v.startswith("Mitigation:"):
            sl.append("%s:%s" % (k, v[12:]))
        elif v == "Not affected":
            pass
        else:
            sl.append("%s:%s" % (k, v))
    return "; ".join(sl)


def advice(s):
    """
    Give some advice about system changes that would improve observability.

    Advice may make assumptions about the user's intended use case,
    and their level of privilege. E.g. it may say things like
      "to enable performance analysis of the kernel, rebuild with CONFIG..."
    For some users this might not be either appropriate or actionable.
    """
    if False:
        if len(list(kernel_hugepages(s, skip_zero=True))) == 0:
            yield ("huge pages not enabled", [])
    if not s.is_kernel_at_least((5, 0)):
        yield ("kernel version %s may lack support for new perf features" % s.get_kernel_version(), ["update kernel"])
    if not perf_installed():
        # TBD: we could advise on how to install perf, e.g.
        #   Ubuntu: "sudo apt-get install linux-tools-`uname -r`"
        #   Amazon Linux: "yum install perf"
        yield ("perf tools not installed", ["install perf package (see https://learn.arm.com/install-guides/perf)", "or build from kernel sources"])
    else:
        if _is_arm and not perf_binary_has_opencsd():
            yield ("perf tools cannot decode hardware trace", ["build with CORESIGHT=1"])
    if perf_event_paranoid() > 0:
        yield ("System-level events can only be monitored by privileged users", ["sysctl kernel.perf_event_paranoid=0"])
    if not s.perf_max_counters():
        corrs = []
        if _is_arm and not s.has_irq("PMU"):
            corrs.append("ensure APIC table describes PMU interrupt")
        yield ("Hardware perf events are not available", corrs)
    if not os.path.exists("/proc/kcore"):
        yield ("/proc/kcore not enabled, kernel profiling degraded", ["rebuild kernel with CONFIG_PROC_KCORE"])
    if not perf_interconnect(s) and s.has_CMN_interconnect():
        ck = s.get_kernel_config("CONFIG_ARM_CMN")
        problem = "CMN interconnect perf events not enabled"
        if ck in ["m", "y"]:
            yield (problem, ["check boot log for CMN driver problems"])
        else:
            yield (problem, ["rebuild kernel with CONFIG_ARM_CMN enabled"])
    if _is_arm:
        spe = s.cpu_has_SPE()
        if spe:
            corrs = []
            if not perf_noninvasive_sampling(s):
                # CPU has SPE, but apparently not available in perf
                if not s.has_irq("SPE"):
                    corrs.append("ensure APIC table describes SPE interrupt")
                ck = s.get_kernel_config("CONFIG_ARM_SPE_PMU")
                if ck == 'n':
                    corrs.append("ensure kernel is built with SPE support (CONFIG_ARM_SPE_PMU)")
                elif ck == 'm' and not s.has_loadable_kernel_module("arm_spe_pmu.ko"):
                    corrs.append("kernel module arm_spe_pmu.ko must be built")
                yield ("non-invasive sampling (SPE) not enabled", corrs)
            if spe == -1:
                yield ("SPE sampling on %s is biased (hardware erratum)" % list(s.cpu_types())[0], ["allow for bias"])
    if _is_arm and not perf_hardware_trace(s):
        corrs = []
        # advice for v8:
        #  - CoreSight system description in device tree / ACPI DSDT
        #  - rebuild with CONFIG_CORESIGHT
        # advice for v9:
        #  - describe TRBE interrupt in ACPI APIC (or DT equivalent)
        #  - rebuild with CONFIG_CORESIGHT
        # for both: ensure perf is built with OpenCSD
        if not s.kernel_config_enabled("CONFIG_CORESIGHT"):
            corrs.append("rebuild kernel with CONFIG_CORESIGHT")
        if s.is_arm_architecture(9):
            if not s.has_irq("TRBE"):
                corrs.append("ensure APIC table describes TRBE interrupt")
        else:
            corrs.append("ensure ACPI describes CoreSight trace fabric")
        yield ("hardware trace not enabled", corrs)


def show(s):
    """
    Show system characteristics:
     - hardware
     - kernel
     - perf features available
    """
    print("System feature report:")
    print("  Collected:           %s" % (datetime.datetime.now().isoformat(' ')))
    print("  Script version:      %s" % (datetime.datetime.fromtimestamp(os.path.getmtime(__file__)).isoformat(' ')))
    print("  Running as root:     %s" % (colorize(is_superuser())))
    # Hardware features
    print("System hardware:")
    print("  Architecture:        %s" % (s.architecture()))
    print("  CPUs:                %s" % (s.get_cpu_count()))
    print("  CPU types:           %s" % (", ".join(["%u x %s" % (len(cl), ct.str_full()) for (ct, cl) in s.system.spec_to_cpulist.items()])))
    # Show a summary of all the caches.
    print("  cache info:          %s" % (colorize(cache_info())))
    print("  cache line size:     %s" % (colorize_redzero(s.get_cache_line_size())))
    caches = {}
    for c in s.system.caches():
        ct = "%s %s" % (c.type_str(), c.geometry_str())
        if ct not in caches:
            caches[ct] = 0
        caches[ct] += 1
    print("  Caches:")
    for ct in sorted(caches.keys()):
        print("    %u x %s" % (caches[ct], ct))
    print("  System memory:       %s" % (cpulist.memsize_str(s.system.phys_mem)))
    print("  Atomic operations:   %s" % (colorize(has_atomics(s.system))))
    (itype, n) = s.system_interconnect()
    print("  interconnect:        %s x %u" % (colorize(itype), n))
    print("  NUMA nodes:          %u" % (s.system.n_nodes()), end="")
    if not s.kernel_config_enabled("CONFIG_NUMA"):
        print(" (CONFIG_NUMA=n)", end="")
    print()
    print("  Sockets:             %u" % (s.system.n_packages()))
    # Kernel features
    print("OS configuration:")
    print("  Kernel:              %s" % (s.get_kernel_version()))
    print("  config:              %s" % (colorize(kernel_config_file())))
    print("  32-bit support:      %s" % (colorize(s.kernel_config_enabled("CONFIG_COMPAT"))))
    print("  build dir:           %s" % (colorize(kernel_build_dir())))
    print("  uses atomics:        %s" % (colorize(kernel_uses_atomics(s))))
    print("  huge pages:          %s" % (kernel_hugepages_str(s)))
    print("  transparent HP:      %s" % (kernel_thp(s) or "disabled"))
    if _is_arm:
        print("  MPAM configured:     %s" % (colorize(s.has_MPAM())))
    print("  resctrl:             %s" % (colorize(s.has_resctrl())))
    print("  Distribution:        %s" % (s.get_distribution()))
    print("  libc version:        %s" % (s.get_libc_version()))
    print("  boot info:           %s" % (colorize(boot_info_type())))
    print("  KPTI enabled:        %s" % (colorize(s.is_KPTI_enabled(), invert=True)))
    print("  Lockdown:            %s" % (lockdown_str(s.get_lockdown())))
    print("  Mitigations:         %s" % (vulnerabilities_str(s.vulnerabilities())))
    # Perf features
    print("Performance features:")
    print("  perf tools:          %s" % (colorize(perf_installed())))
    print("  perf installed at:   %s" % (perf_binary()), end="")
    if not os.path.exists(perf_binary()):
        print(colorize(" (does not exist)", "red"), end="")
    print()
    print("  perf with OpenCSD:   %s" % (colorize_greenred(perf_binary_has_opencsd())))
    print("  perf counters:       %s" % (s.perf_max_counters()))
    print("  perf sampling:       %s" % (colorize_greenred(perf_noninvasive_sampling(s))))
    print("  perf HW trace:       %s" % (colorize_greenred(perf_hardware_trace(s))))
    print("  perf paranoid:       %s" % (perf_event_paranoid()))   # 0 is not bad, it's good
    print("  kptr_restrict:       %s" % (kptr_restrict()))
    print("  perf in userspace:   %s" % (colorize_abled(perf_user_access(s))))
    print("  interconnect perf:   %s" % (colorize_greenred(perf_interconnect(s))))
    print("  /proc/kcore:         %s" % (colorize(os.path.exists("/proc/kcore"))))
    print("  /dev/mem:            %s" % (colorize(os.path.exists("/dev/mem"))))
    print("  eBPF:")
    print("    kernel configured for BPF: %s" % (colorize_greenred(kernel_supports_bpf(s))))
    bpftool = bpftool_installed(s)
    print("    bpftool installed:         %s" % (colorize(bpftool is not None)))
    if bpftool is not None:
        print("      %s" % colorize(bpftool))
    print("    bpftrace installed:        %s" % (bpftrace_installed(s)))


def print_advice(s):
    """
    Print helpful advice about changes that could improve performance observability.
    """
    printed = False
    for (obs, acts) in advice(s):
        if not printed:
            # Always start with a blank line before any actions / recommendations are printed
            print("\nActions that can be taken to improve performance tools experience:")
            printed = True
        print("  %s" % (obs))
        for act in acts:
            print("    %s" % (act))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Check system configuration")
    parser.add_argument("--config", action="store_true", help="list kernel build-time configuration")
    parser.add_argument("--advice", action="store_true", default=True, help="show configuration advice")
    parser.add_argument("--no-advice", action="store_false", dest="advice", help="don't show configuration advice")
    parser.add_argument("--color", action="store_true", help="use ANSI color escape codes in output")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color escape codes in output")
    parser.add_argument("--vulnerabilities", action="store_true")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    strcolor.enable = opts.color or ((not opts.no_color) and os.isatty(sys.stdout.fileno()))
    S = System()
    show(S)
    if opts.advice:
        print_advice(S)
    if opts.config:
        for (k, d) in kernel_config().items():
            print("  %-30s = %s" % (k, d))
    if opts.vulnerabilities:
        for (k, d) in S.vulnerabilities().items():
            print("  %-20s %s" % (k, d))
