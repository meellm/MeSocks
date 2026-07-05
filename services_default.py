"""Compatibility shim: the built-in profiles now live in mesocks.profiles.

Older setups imported SERVICES from this module as the fallback when no
services_config.py exists. Keep that import working.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

from mesocks.profiles import BUILTIN_PROFILES as SERVICES  # noqa: F401
