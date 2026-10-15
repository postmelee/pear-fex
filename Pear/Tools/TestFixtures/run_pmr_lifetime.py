#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prepare the original PMR control against explicit baseline/current sources.

Success means source preparation only. The historical runner's patch application,
implicit tool discovery and native execution are not invoked. The source recipe
preserves its exact fixture and baseline/candidate expected outcomes.
"""
from .prepare import main as prepare_main


def main(argv=None):
    return prepare_main(argv, fixed_case='pmr-lifetime')


if __name__ == '__main__':
    main()
