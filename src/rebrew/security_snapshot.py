"""Rule-based security scan over a verified retained snapshot."""

from __future__ import annotations

from typing import Any


def scan_retained(config: Any, req: Any) -> dict[str, Any]:
    from rebrew import ops
    from rebrew.named_snapshot import retained_snapshot
    from rebrew.security_scan import SEVERITY_ORDER, filter_by_severity, scan_paths
    from rebrew.sources import _EXCLUDE_DIRS, iter_sources

    if req.min_severity not in SEVERITY_ORDER:
        raise ops._invalid(f"min_severity must be one of {', '.join(SEVERITY_ORDER)}")
    with retained_snapshot(config, req) as (root, cfg, retained, verify_files):
        directory = cfg.reversed_dir.resolve()
        if not directory.is_relative_to(root):
            raise ops._invalid("security source directory escapes the snapshot")
        expected = {
            path
            for path in retained
            if path.is_relative_to(directory)
            and path.suffix.lower() == ".c"
            and not any(part in _EXCLUDE_DIRS for part in path.relative_to(directory).parts[:-1])
        }
        published = {root / entry.path for entry in req.files}
        if not expected.issubset(published):
            raise ops._invalid("security source is not in the published snapshot")
        paths = iter_sources(directory) if directory.is_dir() else []
        if (
            any(path.is_symlink() or path.resolve() not in retained for path in paths)
            or set(paths) != expected
        ):
            raise ops._invalid("security sources differ from the retained snapshot")
        verify_files()
        try:
            findings = scan_paths(paths, strict=True)
        except OSError:
            raise ops._invalid("retained security source is unreadable") from None
        verify_files()
        for finding in findings:
            path = ops._project_file(root, finding["file"].removeprefix(str(root) + "/"), "source")
            if path not in expected:
                raise ops._invalid("security finding escapes the retained snapshot")
            finding["file"] = path.relative_to(root).as_posix()
        by_severity = dict.fromkeys(SEVERITY_ORDER, 0)
        for finding in findings:
            by_severity[str(finding["severity"])] += 1
        result = filter_by_severity(
            {
                "root": directory.relative_to(root).as_posix(),
                "files_scanned": len(paths),
                "findings": findings,
                "count": len(findings),
                "by_severity": by_severity,
            },
            req.min_severity,
        )
    return {
        "result": result,
        "source_revision": req.source_revision,
        "source_snapshot_sha256": req.source_snapshot_sha256,
        "generation": req.generation,
        "analysis_manifest_sha256": req.analysis_manifest_sha256,
    }
