# Security Policy

## Supported Versions

Only the latest code on `main` receives security fixes.

## Reporting a Vulnerability

Please do not open a public issue for security reports. Use GitHub's private
security advisory flow for this repository.

Include:

- A short description of the issue.
- Steps to reproduce.
- The affected MeSocks version or commit.
- Network exposure details, especially whether the Pi is reachable outside a
  trusted LAN.

## Scope

In scope:

- Open resolver or open UDP relay behavior.
- DNS cache poisoning or spoofed upstream responses.
- Resource exhaustion that can crash the daemons from the network.
- Unsafe service setup that exposes unauthenticated proxy access unexpectedly.
- Routing bugs that leak configured service traffic outside the intended VPN
  path.

Out of scope:

- General bypasses for services that hardcode IP literals or use domains not
  configured in MeSocks.
- Bugs in third-party components such as `sniproxy`, `microsocks`, or a VPN
  provider.
- Physical-access or already-root scenarios on the Pi.
