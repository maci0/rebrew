"""Audit every rebrew-* project: config validation, toolchain resolution,
metadata syntax, functions.txt, and annotation parseability."""

from __future__ import annotations

import logging
import re
import sys
import tomllib
import warnings
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rebrew.annotation import parse_c_file_multi
from rebrew.catalog.loaders import parse_function_list
from rebrew.compile import resolve_cl_command
from rebrew.config import _KNOWN_PROFILES, load_config
from rebrew.data_metadata import load_data_metadata
from rebrew.metadata import KNOWN_STATUSES, load_metadata

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else "/home/maci/Desktop/Projects/relumea")

_VA_RE = re.compile(r"^0x[0-9a-fA-F]+$")


def check_functions_txt(ft: Path) -> list[str]:
    """Use the same parser rebrew itself uses — header lines (radare2/rizin
    exports) and non-matching lines are legitimately skipped, so only a
    warning or a completely empty result counts as a problem."""
    import warnings

    with warnings.catch_warnings(record=True) as wlist:
        warnings.simplefilter("always")
        funcs = parse_function_list(ft)
    out = [f"warning: {w.message}" for w in wlist if issubclass(w.category, UserWarning)]
    nonempty = any(
        line.strip() and not line.strip().startswith("#")
        for line in ft.read_text(encoding="utf-8", errors="replace").splitlines()
    )
    if nonempty and not funcs:
        out.append("no functions parsed from a non-empty file")
    return out


def check_metadata(meta: Path) -> list[str]:
    issues = []
    try:
        entries = load_metadata(meta.parent)
    except Exception as e:  # toml syntax / schema
        return [f"load_metadata failed: {e}"]
    for key, v in entries.items():
        if not isinstance(v, dict):
            issues.append(f"{key}: not a table")
            continue
        status = v.get("status")
        if status is not None and status not in KNOWN_STATUSES:
            issues.append(f"{key}: unknown status {status!r}")
        for field, typ in (("size", int), ("va", int)):
            if field in v and not isinstance(v[field], typ):
                issues.append(f"{key}.{field}: {type(v[field]).__name__}")
    return issues


def check_data_metadata(meta: Path) -> list[str]:
    issues: list[str] = []
    try:
        entries = load_data_metadata(meta.parent)
    except Exception as e:
        return [f"load_data_metadata failed: {e}"]
    for key, v in entries.items():
        if not isinstance(v, dict):
            issues.append(f"{key}: not a table")
    return issues


def main() -> int:
    total_issues: Counter[str] = Counter()
    logger = logging.getLogger("rebrew")
    logger.setLevel(logging.WARNING)
    buf: list[str] = []

    class _Buf(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            buf.append(f"log: {record.getMessage()}")

    handler = _Buf()
    logger.addHandler(handler)
    try:
        tomls = sorted(ROOT.glob("*/rebrew-project.toml"))
        print(f"Auditing {len(tomls)} projects\n")
        for toml in tomls:
            proj = toml.parent
            if proj.name == "rebrew":
                continue
            issues: list[str] = []
            try:
                raw = tomllib.loads(toml.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"== {proj.name}: TOML PARSE FAILED: {e}")
                total_issues["toml_parse"] += 1
                continue
            targets = list(raw.get("targets", {}).keys())
            if not targets:
                issues.append("no [targets] section")

            for t in targets:
                buf.clear()
                with warnings.catch_warnings(record=True) as wlist:
                    warnings.simplefilter("always")
                    try:
                        cfg = load_config(proj, target=t)
                    except Exception as e:
                        issues.append(f"[{t}] config load failed: {e}")
                        continue
                for w in wlist:
                    if issubclass(w.category, UserWarning):
                        issues.append(f"[{t}] config warn: {w.message}")
                issues.extend(buf)
                # Toolchain resolution
                try:
                    cmd = resolve_cl_command(cfg)
                    if not Path(cmd[-1]).exists():
                        issues.append(f"[{t}] CL not found: {cmd[-1]}")
                except Exception as e:
                    issues.append(f"[{t}] resolve_cl_command: {e}")
                inc = getattr(cfg, "compiler_includes", Path())
                if inc and not inc.exists():
                    issues.append(f"[{t}] includes missing: {inc}")
                # functions.txt
                ft = getattr(cfg, "function_list", Path())
                if ft.exists():
                    for b in check_functions_txt(ft):
                        issues.append(f"[{t}] functions.txt: {b}")
                # Metadata
                meta_root = cfg.metadata_dir
                fn_meta = meta_root / "rebrew-function.toml"
                if fn_meta.exists():
                    for b in check_metadata(fn_meta):
                        issues.append(f"[{t}] metadata: {b}")
                data_meta = meta_root / "rebrew-data.toml"
                if data_meta.exists():
                    for b in check_data_metadata(data_meta):
                        issues.append(f"[{t}] data-metadata: {b}")
                # Annotations parseability
                rdir = cfg.reversed_dir
                if rdir.exists():
                    bad_files = 0
                    total_files = 0
                    for c in sorted(rdir.rglob("*")):
                        if c.suffix.lower() not in (".c", ".cpp"):
                            continue
                        total_files += 1
                        try:
                            parse_c_file_multi(
                                c, target_name=cfg.marker or None, metadata_dir=meta_root
                            )
                        except Exception as e:
                            bad_files += 1
                            if bad_files <= 2:
                                issues.append(f"[{t}] annotation parse fail: {c.name}: {e}")
                    if bad_files:
                        issues.append(f"[{t}] {bad_files}/{total_files} sources fail to parse")
                # Compiler profile sanity
                prof = getattr(cfg, "compiler_profile", "")
                if prof not in _KNOWN_PROFILES:
                    issues.append(f"[{t}] unknown profile {prof!r}")

            status = "OK " if not issues else "ISSUES"
            for _iss in issues:
                total_issues["issues"] += 1
            print(f"{status} {proj.name} ({len(targets)} targets)")
            for iss in issues:
                print(f"     - {iss}")
    finally:
        logger.removeHandler(handler)
    print(f"\nTotal issue lines: {total_issues['issues']}")
    return 0 if not total_issues["issues"] else 1


if __name__ == "__main__":
    sys.exit(main())
