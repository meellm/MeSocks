"""Setup-time queries against the active services config.

Used by setup-services.sh so the profile-flattening logic lives in one
place instead of inline python snippets in the shell script.

Usage:
    python3 -m mesocks.setupinfo summary        # "1 service(s): discord (26 domains)"
    python3 -m mesocks.setupinfo forward-rules  # sniproxy --forward-rule lines
    python3 -m mesocks.setupinfo has-udp        # "True" / "False"
    python3 -m mesocks.setupinfo udp-port       # UDP listen port
"""

import sys

from .profiles import load_services, udp_configs, udp_listen_port


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    commands = ('summary', 'forward-rules', 'has-udp', 'udp-port')
    if len(argv) != 1 or argv[0] not in commands:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    services = load_services()
    command = argv[0]

    if command == 'summary':
        total = sum(len(s.get('domains', [])) for s in services.values())
        names = ', '.join(services.keys())
        print(f'{len(services)} service(s): {names} ({total} domains)')
    elif command == 'forward-rules':
        rules = []
        for cfg in services.values():
            for domain in cfg.get('domains', []):
                rules.append(f'  --forward-rule={domain} --forward-rule=*.{domain}')
        print(' \\\n'.join(rules))
    elif command == 'has-udp':
        print(bool(udp_configs(services)))
    elif command == 'udp-port':
        print(udp_listen_port(services))
    return 0


if __name__ == '__main__':
    sys.exit(main())
