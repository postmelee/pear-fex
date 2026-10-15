#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Prepare the original NX emitter control with explicit source/tool bindings.

The original fixture, allocator declarations and expected normal/refusal exits are
retained in the source recipe. This adapter never compiles or executes the plan.
"""
from .prepare import main as prepare_main


def main(argv=None):
    return prepare_main(argv, fixed_case='emitter-labels')


if __name__ == '__main__':
    main()
