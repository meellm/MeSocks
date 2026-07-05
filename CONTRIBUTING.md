# Contributing to MeSocks

Thanks for helping improve MeSocks. This guide covers local setup, tests, and
the shape of changes that fit the project.

## Quick Start

```bash
git clone https://github.com/meellm/MeSocks.git
cd MeSocks

python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

pytest
```

The runtime services use only the Python standard library. `pytest` is only for
development.

## Project Layout

```text
src/mesocks/
|-- settings.py    # runtime tunables and config_local.py overrides
|-- profiles.py    # built-in and user service profile loading
|-- dnspacket.py   # raw DNS packet parsing/building
|-- cache.py       # DNS forward cache and media IP tracker
|-- ratelimit.py   # private-network gate and per-IP rate limit
|-- dns_server.py  # mesocks-dns daemon
|-- udp_proxy.py   # mesocks-udp daemon
`-- setupinfo.py   # setup-services.sh helper

tests/             # unit tests for packet parsing, caches, profiles, UDP routing
docs/              # operational and profile documentation
```

The top-level `dns-proxy.py` and `udp-proxy.py` files are compatibility
launchers. Keep them working because existing systemd units and manual deploys
may still call them.

## Running Checks

```bash
pytest
bash -n setup.sh setup-services.sh
PYTHONPYCACHEPREFIX=/tmp/mesocks-pycache \
  python -m py_compile dns-proxy.py udp-proxy.py services_default.py \
  services_config.example.py src/mesocks/*.py tests/*.py
```

## Adding a Service Profile

Service profiles are plain dictionaries with:

- `domains`: base domains to hijack. Subdomains match automatically.
- `enabled`: optional boolean, defaults to `True`.
- `udp_proxy`: optional block for media/voice services.

Add built-in profiles in `src/mesocks/profiles.py` only for broadly useful
services. For personal or network-specific routing, copy
`services_config.example.py` to `services_config.py` and keep that local file
untracked.

## Pull Request Checklist

- [ ] Tests pass locally.
- [ ] New behavior has tests or a clear note explaining why not.
- [ ] Backward-compatible launchers still work.
- [ ] No secrets, tokens, local paths, or personal config in the diff.
- [ ] Documentation matches any changed setup or profile behavior.
