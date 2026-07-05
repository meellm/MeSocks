# Changelog

All notable changes to MeSocks are documented here.

## Unreleased

- Reorganized the Python services into the `mesocks` package under `src/`.
- Added modular service profiles so Discord is the built-in default and custom
  services can be enabled through `services_config.py`.
- Kept top-level compatibility launchers for existing systemd units:
  `dns-proxy.py` and `udp-proxy.py`.
- Added packaging metadata, contribution/security docs, and GitHub templates.
- Improved DNS/UDP reliability and security around Discord text and voice
  routing.
