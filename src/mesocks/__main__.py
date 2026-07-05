"""Small command dispatcher for `python -m mesocks`."""

import sys

from . import setupinfo


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ('-h', '--help'):
        print("Usage: python -m mesocks setupinfo <summary|forward-rules|has-udp>")
        return 0
    command, rest = argv[0], argv[1:]
    if command == 'setupinfo':
        return setupinfo.main(rest)
    print(f"Unknown command: {command}", file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
