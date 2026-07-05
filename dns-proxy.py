#!/usr/bin/env python3
"""Compatibility launcher for the MeSocks DNS server.

The implementation lives in src/mesocks/dns_server.py. This wrapper
keeps existing invocations working (systemd units, docs, muscle memory):

    sudo python3 dns-proxy.py [PI_IP]

Running from the repo root also puts services_config.py / config_local.py
on the import path, so local overrides keep working unchanged.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

from mesocks.dns_server import main

if __name__ == '__main__':
    main()
