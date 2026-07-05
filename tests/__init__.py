"""Test package for MeSocks.

Puts src/ on sys.path so the tests run against the working tree with
plain `python3 -m unittest` - no install or pytest required.
"""

import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src')
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
