"""render_skills.py – render the packaged agent-skills into a target tree.

``src/rebrew/agent-skills/`` is the canonical tree; ``rebrew init`` copies it
into a project with ``<target>`` replaced by the target name.  This repo's own
``.agents/skills/`` is such a rendered copy, and ``tests/test_skills_sync.py``
pins the two apart.  Regenerating it with a ``cp -r`` + ``sed -i`` pipeline
depends on GNU-only ``sed``, on ``find`` visiting files in a stable order, and
on nothing failing between the copy and the substitution.

Walking the tree here instead makes the render deterministic (sorted, UTF-8,
LF) and lets a failure name the file.  The substitution mirrors
``rebrew.init.agent_skill_files``.

Usage::

    python tools/render_skills.py            # (re)write .agents/skills/
    python tools/render_skills.py --check    # verify it matches, no write
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "rebrew" / "agent-skills"
DEST = ROOT / ".agents" / "skills"

#: Target name this repo's .agents/skills/ copy is rendered with.  Must match
#: ``tests/test_skills_sync.py``'s RENDER_TARGET.
RENDER_TARGET = "bench"

#: Only these carry the ``<target>`` placeholder; binary skill assets are
#: copied byte for byte.
_TEXT_SUFFIXES = frozenset({".md"})

PLACEHOLDER = "<target>"


def render(relative: Path, data: bytes) -> bytes:
    """Return *data* with the target placeholder substituted, or unchanged.

    Substitution is text-only and restricted to the suffixes that can hold
    prose, so a binary asset is never decoded and re-encoded.
    """
    if relative.suffix not in _TEXT_SUFFIXES:
        return data
    return data.decode("utf-8").replace(PLACEHOLDER, RENDER_TARGET).encode("utf-8")


def rendered_tree() -> dict[str, bytes]:
    """Map every file under the packaged tree to its rendered bytes."""
    if not SRC.is_dir():
        raise SystemExit(f"packaged skill tree missing: {SRC}")
    files: dict[str, bytes] = {}
    for path in sorted(SRC.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(SRC)
        files[relative.as_posix()] = render(relative, path.read_bytes())
    if not files:
        raise SystemExit(f"packaged skill tree is empty: {SRC}")
    return files


def _current_tree() -> dict[str, bytes]:
    if not DEST.is_dir():
        return {}
    return {
        path.relative_to(DEST).as_posix(): path.read_bytes()
        for path in sorted(DEST.rglob("*"))
        if path.is_file()
    }


def main() -> int:
    """Write (or check) the rendered tree; return 0 when it matches."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify .agents/skills matches the packaged tree (exit 1 on drift) without writing",
    )
    args = parser.parse_args()

    wanted = rendered_tree()
    if args.check:
        current = _current_tree()
        stale = sorted(
            name for name, data in wanted.items() if name not in current or current[name] != data
        )
        extra = sorted(set(current) - set(wanted))
        if stale or extra:
            for name in stale:
                print(f"stale or missing: .agents/skills/{name}", file=sys.stderr)
            for name in extra:
                print(f"not in the packaged tree: .agents/skills/{name}", file=sys.stderr)
            print("run: make gen-skills", file=sys.stderr)
            return 1
        print(f"{len(wanted)} rendered skill files up to date")
        return 0

    # Replace the tree wholesale: a leftover file from a renamed skill would
    # otherwise survive and drift from the packaged source.
    if DEST.exists():
        for path in sorted(DEST.rglob("*"), reverse=True):
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
    for name, data in sorted(wanted.items()):
        out = DEST / name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
    print(f"wrote {len(wanted)} files under {DEST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
