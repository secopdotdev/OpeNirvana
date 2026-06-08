#!/usr/bin/env python3
"""validate.py -- entrypoint for the risk-tiered validation framework.

Run from anywhere:  python unified-stack/scripts/validate.py [--changed-only] [--ci]
See docs/superpowers/specs/2026-06-06-validation-framework-design.md.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # make `validation` importable

from validation.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
