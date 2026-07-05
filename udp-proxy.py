#!/usr/bin/env python3
"""Compatibility launcher for the MeSocks UDP media proxy.

The implementation lives in src/mesocks/udp_proxy.py. This wrapper
keeps existing invocations working (systemd units, docs, muscle memory):

    ./udp-proxy.py                 # Auto mode - reads from DNS tracker
    ./udp-proxy.py 203.0.113.7     # Manual mode - fixed IP
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

from mesocks.udp_proxy import main

if __name__ == '__main__':
    main()
