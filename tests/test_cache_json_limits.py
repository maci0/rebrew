"""Malformed JSON sidecars remain cache misses rather than command failures."""

lazy from pathlib import Path

import pytest

from rebrew import data_scan, todo, verify_cache
from rebrew import test as test_module
from rebrew.metadata import document


class TestJsonCacheNumericLimits:
    @pytest.mark.parametrize(
        "kind", ["verify", "names", "roles", "externs", "metadata", "name-map"]
    )
    def test_oversized_integer_is_an_unchanged_cache_miss(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture, kind: str
    ) -> None:
        cache_dir = tmp_path / ".rebrew"
        cache_dir.mkdir()
        filenames = {
            "verify": "verify.json",
            "names": "name-map-cover.json",
            "roles": "data-scan-roles.json",
            "externs": "extern-names.json",
            "metadata": "metadata-doc/rebrew-functions.toml.json",
            "name-map": "name_to_va_cache.json",
        }
        path = cache_dir / filenames[kind]
        path.parent.mkdir(exist_ok=True)
        raw = b'{"value":' + b"9" * 5000 + b"}"
        path.write_bytes(raw)
        if kind == "verify":
            toml = path.with_suffix(".toml")
            toml.write_text("")
            assert verify_cache._read_verify_json(toml, toml.stat()) is None
        elif kind == "names":
            assert data_scan._begin_name_cover(tmp_path)["files"] == {}
        elif kind == "roles":
            assert data_scan._begin_role_cache(tmp_path, None)["files"] == {}
        elif kind == "externs":
            assert todo._begin_extern_cache(tmp_path)["files"] == {}
        elif kind == "metadata":
            assert document._read_doc_cache(tmp_path / "rebrew-functions.toml", (), None) is None
        else:
            assert test_module._read_name_map_payload(path) is None
        if kind not in {"metadata", "name-map"}:
            assert any(str(path) in record.getMessage() for record in caplog.records)
        assert path.read_bytes() == raw
