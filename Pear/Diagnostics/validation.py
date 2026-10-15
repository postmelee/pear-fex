# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Local validation boundary for the imported diagnostic readers."""

def need(condition, code):
    if not condition:
        raise ValueError(code)
