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
Colorize text output using ANSI escape codes.
"""

from __future__ import print_function

import os

enable = True


def colorize(s, c=None, invert=False):
    """
    Add ANSI color escape codes around a string, e.g. to put it into a different color.
    """
    if not enable:
        return s
    if os.environ.get("NO_COLOR", ""):
        # http://no-color.org
        return s
    if c is None:
        if s is None:
            s = "<unknown>"
            c = "cyan"
        elif isinstance(s, bool):
            if (s != invert):
                c = "green"
            else:
                c = "red"
        else:
            c = "white"
    if c != "white":
        cc = {"red":31, "green":32, "yellow":33, "blue":34, "magenta":35, "cyan":36}
        s = ("\x1b[%um" % cc[c]) + str(s) + "\x1b[0m"
    return s


if __name__ == "__main__":
    print(colorize(True))
    print(colorize(False))
    print(colorize(None))
    print(colorize(0))
    print(colorize(1))
    print(colorize(100))
