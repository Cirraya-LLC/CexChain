# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""python3 -m kanhe_verify BUNDLE [options], or contract FILE [options]"""

import sys

from .cli import main

sys.exit(main())
