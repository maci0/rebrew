"""Thin wrapper to launch the recoverage dev server as a console script."""

import sys
from pathlib import Path


def main() -> int:
    # Add the recoverage directory to sys.path so dev_server can be imported
    recoverage_dir = Path(__file__).resolve().parents[2] / "recoverage"
    sys.path.insert(0, str(recoverage_dir))
    from dev_server import main as _main  # type: ignore

    return _main()


if __name__ == "__main__":
    raise SystemExit(main())
