"""Tests for the rebrew annotation linter."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from source_util import SourceFixture, write_source, write_store_fixture

from rebrew.config import ProjectConfig
from rebrew.lint import LintResult, lint_file


def _write_c(tmp_path: Path, name: str, content: str) -> Path:
    """Create a .c file in tmp_path and return its Path."""
    p = tmp_path / name
    write_source(p, content, encoding="utf-8")
    return p


def _make_cfg(
    marker: str = "SERVER",
    base_cflags: str = "/nologo /c /MT",
    library_modules: set | None = None,
    reversed_dir: Path | None = None,
    cflags: str = "",
    root: Path = Path("/tmp"),
) -> ProjectConfig:
    """Create a minimal config-like namespace for config-aware lint tests."""
    return ProjectConfig(
        root=root,
        marker=marker,
        base_cflags=base_cflags,
        library_modules=library_modules or set(),
        reversed_dir=reversed_dir or root,
        cflags=cflags,
    )


def _write_inventory(reversed_dir: Path, *entries: tuple[int, int, str]) -> None:
    """Write function_structure.json next to the target for index tests."""
    import json as _json

    reversed_dir.mkdir(parents=True, exist_ok=True)
    (reversed_dir / "function_structure.json").write_text(
        _json.dumps([{"va": va, "size": size, "name": name} for va, size, name in entries]),
        encoding="utf-8",
    )


VALID_HEADER = SourceFixture(
    "/* ADDRESS: SERVER 0x10008880 */\n\n\nint __cdecl bit_reverse(int x)\n{\n    return x;\n}\n",
    {"SERVER.0x10008880": {"kind": "FUNCTION", "status": "EXACT"}},
)
VALID_LIBRARY_HEADER = SourceFixture(
    "\n\n\n#include <stdlib.h>\n/* ADDRESS: SERVER 0x10023714 */\nint stub(void) { return 0; }\n",
    {"SERVER.0x10023714": {"kind": "STUB", "status": "STUB"}},
)


class TestValidAnnotations:
    def test_valid_function_no_errors(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f)
        assert result.passed
        assert len(result.errors) == 0

    def test_valid_function_no_warnings(self, tmp_path: Path) -> None:
        """With a config providing default cflags, a clean file has no warnings."""
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        cfg = _make_cfg(cflags="/O2", root=tmp_path)
        result = lint_file(f, cfg=cfg)
        assert result.passed, f"Expected lint to pass, errors: {result.errors}"
        non_w019 = [w for w in result.warnings if w[1] != "W019"]
        assert non_w019 == [], f"Unexpected warnings: {non_w019}"

    def test_valid_library_no_errors(self, tmp_path: Path) -> None:
        cfg = _make_cfg(root=tmp_path)
        f = _write_c(tmp_path, "copy_environ.c", VALID_LIBRARY_HEADER)
        result = lint_file(f, cfg=cfg)
        assert result.passed, f"Expected lint to pass, errors: {result.errors}"
        assert result.errors == [], f"Unexpected errors: {result.errors}"


class TestMissingAnnotation:
    def test_empty_file(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "empty.c", "")
        result = lint_file(f)
        assert not result.passed
        assert any((c == "E001" for _, c, _ in result.errors))

    def test_no_annotation(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "noannot.c", "#include <stdio.h>\nint main() {}\n")
        result = lint_file(f)
        assert not result.passed
        assert any((c == "E001" for _, c, _ in result.errors))

    def test_invalid_kind(self, tmp_path: Path) -> None:
        content = "// BADTYPE: SERVER 0x10008880\n// STATUS: EXACT\n// SIZE: 31\n// CFLAGS: /O2 /Gd\nint foo(void) { return 0; }\n"
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "E001" for _, c, _ in result.errors))


class TestInvalidVA:
    def test_va_too_small(self, tmp_path: Path) -> None:
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x00000001 */\n\n\n\nint foo(void) { return 0; }\n",
            {
                "SERVER.0x00000001": {
                    "kind": "FUNCTION",
                    "size": 10,
                    "cflags": "/O2 /Gd",
                    "status": "EXACT",
                }
            },
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "E002" for _, c, _ in result.errors))


class TestMissingFields:
    def test_missing_origin_no_error_when_module_present(self, tmp_path: Path) -> None:
        """ORIGIN is optional when FUNCTION: MODULE field is present — no E005 error."""
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\n\nint foo(void) { return 0; }\n",
            {
                "SERVER.0x10008880": {
                    "kind": "FUNCTION",
                    "size": 31,
                    "cflags": "/O2",
                    "status": "EXACT",
                }
            },
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any((c == "E005" for _, c, _ in result.errors))

    def test_missing_size_no_error(self, tmp_path: Path) -> None:
        """Missing SIZE in source should not cause lint errors — SIZE lives in metadata."""
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\nint foo(void) { return 0; }\n",
            {"SERVER.0x10008880": {"kind": "FUNCTION", "cflags": "/O2", "status": "EXACT"}},
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any((c == "E007" for _, c, _ in result.errors))

    def test_missing_cflags_no_config(self, tmp_path: Path) -> None:
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\nint foo(void) { return 0; }\n",
            {"SERVER.0x10008880": {"kind": "FUNCTION", "size": 31, "status": "EXACT"}},
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "W018" for _, c, _ in result.warnings))

    def test_missing_cflags_with_config_default(self, tmp_path: Path) -> None:
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\nint foo(void) { return 0; }\n",
            {"SERVER.0x10008880": {"kind": "FUNCTION", "size": 31, "status": "EXACT"}},
        )
        f = _write_c(tmp_path, "foo.c", content)
        cfg = _make_cfg(cflags="/O2", root=tmp_path)
        result = lint_file(f, cfg=cfg)
        assert not any((c == "W018" for _, c, _ in result.warnings))


class TestUnknownKeys:
    def test_unknown_annotation_key(self, tmp_path: Path) -> None:
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\n\n// FLAVOR: vanilla\nint foo(void) { return 0; }\n",
            {
                "SERVER.0x10008880": {
                    "kind": "FUNCTION",
                    "size": 31,
                    "cflags": "/O2",
                    "status": "EXACT",
                }
            },
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any((c == "W010" for _, c, _ in result.warnings))


class TestConfigMarkerValidation:
    def test_wrong_module_raises_no_error_without_cfg(self, tmp_path: Path) -> None:
        """Without cfg, module is not validated against marker."""
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\n\nint foo(void) { return 0; }\n",
            {
                "SERVER.0x10008880": {
                    "kind": "FUNCTION",
                    "size": 31,
                    "cflags": "/O2",
                    "status": "EXACT",
                }
            },
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any((c == "E006" for _, c, _ in result.errors))

    def test_valid_function_with_cfg_no_errors(self, tmp_path: Path) -> None:
        cfg = _make_cfg(root=tmp_path)
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f, cfg=cfg)
        assert not any((c == "E006" for _, c, _ in result.errors))


class TestConfigMarker:
    def test_wrong_module_name(self, tmp_path: Path) -> None:
        cfg = _make_cfg(marker="SERVER", root=tmp_path)
        content = SourceFixture(
            "/* ADDRESS: CLIENT 0x10008880 */\n\n\n\nint foo(void) { return 0; }\n",
            {
                "CLIENT.0x10008880": {
                    "kind": "FUNCTION",
                    "size": 31,
                    "cflags": "/O2",
                    "status": "EXACT",
                }
            },
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f, cfg=cfg)
        assert any((c == "E012" for _, c, _ in result.errors))

    def test_correct_module_name(self, tmp_path: Path) -> None:
        cfg = _make_cfg(marker="SERVER", root=tmp_path)
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f, cfg=cfg)
        assert not any((c == "E012" for _, c, _ in result.errors))


class TestDuplicateVA:
    def test_duplicate_va_detected(self, tmp_path: Path) -> None:
        seen_vas: dict[int, str] = {}
        f1 = _write_c(tmp_path, "first.c", VALID_HEADER)
        f2 = _write_c(tmp_path, "second.c", VALID_HEADER)
        r1 = lint_file(f1, seen_vas=seen_vas)
        r2 = lint_file(f2, seen_vas=seen_vas)
        assert not any((c == "E013" for _, c, _ in r1.errors))
        assert any(
            c == "E001" and "stored source binding" in message for _, c, message in r1.errors
        )
        assert not any(c == "E013" for _, c, _ in r2.errors)

    def test_different_vas_no_duplicate(self, tmp_path: Path) -> None:
        seen_vas: dict[int, str] = {}
        content2 = VALID_HEADER.replace("0x10008880", "0x10009999")
        f1 = _write_c(tmp_path, "first.c", VALID_HEADER)
        f2 = _write_c(tmp_path, "second.c", content2)
        r1 = lint_file(f1, seen_vas=seen_vas)
        r2 = lint_file(f2, seen_vas=seen_vas)
        assert not any((c == "E013" for _, c, _ in r1.errors))
        assert not any((c == "E013" for _, c, _ in r2.errors))

    def test_same_va_different_modules_no_duplicate(self, tmp_path: Path) -> None:
        """Cross-target same-VA blocks share one file: not a duplicate."""
        seen_vas: dict[Any, str] = {}
        server = VALID_HEADER
        goldtl = VALID_HEADER.replace("SERVER", "GOLDTL")
        f1 = _write_c(tmp_path, "first.c", server)
        f2 = _write_c(tmp_path, "second.c", goldtl)
        r1 = lint_file(f1, seen_vas=seen_vas)
        r2 = lint_file(f2, seen_vas=seen_vas)
        assert not any((c == "E013" for _, c, _ in r1.errors))
        assert not any((c == "E013" for _, c, _ in r2.errors))

    def test_same_va_same_module_in_one_file_detected(self, tmp_path: Path) -> None:
        """Two same-module blocks at one VA in one file still collide."""
        seen_vas: dict[Any, str] = {}
        content = VALID_HEADER + VALID_HEADER.replace("bit_reverse", "bit_reverse2")
        f = _write_c(tmp_path, "twin.c", content)
        r = lint_file(f, seen_vas=seen_vas)
        assert any((c == "E001" for _, c, _ in r.errors))


class TestWarnings:
    def test_w001_missing_symbol(self, tmp_path: Path) -> None:
        """SYMBOL is derived from C function definitions — W001 should not fire."""
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\n\nint foo(void) { return 0; }\n",
            {
                "SERVER.0x10008880": {
                    "kind": "FUNCTION",
                    "size": 31,
                    "cflags": "/O2 /Gd",
                    "status": "EXACT",
                }
            },
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any((c == "W001" for _, c, _ in result.warnings))

    def test_w003_no_code(self, tmp_path: Path) -> None:
        content = SourceFixture(
            "\n\n\n\n",
            {
                "SERVER.0x10008880": {
                    "kind": "FUNCTION",
                    "size": 31,
                    "cflags": "/O2 /Gd",
                    "status": "EXACT",
                }
            },
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "W003" for _, c, _ in result.warnings))

    def test_e015_marker_origin_mismatch(self, tmp_path: Path) -> None:
        """FUNCTION marker with library module should trigger E015 (should be LIBRARY)."""
        cfg = _make_cfg(library_modules={"SERVER"}, root=tmp_path)
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\n\nint foo(void) { return 0; }\n",
            {
                "SERVER.0x10008880": {
                    "kind": "FUNCTION",
                    "size": 31,
                    "cflags": "/O2",
                    "status": "EXACT",
                }
            },
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f, cfg=cfg)
        assert any((c == "E015" for _, c, _ in result.errors))

    def test_target_scoped_library_marker_allowed(self, tmp_path: Path) -> None:
        source = _write_c(
            tmp_path,
            "gzread.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10003960 */\nint gzread(void) { return 0; }\n",
                {"SERVER.0x10003960": {"kind": "LIBRARY"}},
            ),
        )
        result = lint_file(source, cfg=_make_cfg(root=tmp_path))
        assert not any(code == "E015" for _, code, _ in result.errors)

    def test_w005_stub_without_blocker(self, tmp_path: Path) -> None:
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\n\nint foo(void) { return 0; }\n",
            {"SERVER.0x10008880": {"kind": "STUB", "size": 31, "cflags": "/O2", "status": "STUB"}},
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "W005" for _, c, _ in result.warnings))

    def test_w006_library_without_source(self, tmp_path: Path) -> None:
        """Library module without SOURCE annotation should trigger W006."""
        cfg = _make_cfg(library_modules={"SERVER"}, root=tmp_path)
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\n\nint foo(void) { return 0; }\n",
            {
                "SERVER.0x10008880": {
                    "kind": "LIBRARY",
                    "size": 31,
                    "cflags": "/O1",
                    "status": "EXACT",
                }
            },
        )
        f = _write_c(tmp_path, "crt_foo.c", content)
        result = lint_file(f, cfg=cfg)
        assert any((c == "W006" for _, c, _ in result.warnings))

    def test_e017_contradictory_matching_stub(self, tmp_path: Path) -> None:
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\n\nint foo(void) { return 0; }\n",
            {
                "SERVER.0x10008880": {
                    "kind": "STUB",
                    "size": 31,
                    "cflags": "/O2",
                    "status": "NEAR_MATCHING",
                }
            },
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "E017" for _, c, _ in result.errors))

    @pytest.mark.parametrize("status", ["EXACT", "PROVEN"])
    def test_e017_contradictory_developed_stub_marker(self, tmp_path: Path, status: str) -> None:
        """A byte-matched or proven function must not carry a STUB marker
        (stale marker from stub generation; regression: 3 smygb functions were
        silently mislabeled this way)."""
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\nint foo(void) { return 0; }\n",
            {"SERVER.0x10008880": {"kind": "STUB", "size": 31, "status": status}},
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any(c == "E017" and status in m for _, c, m in result.errors)

    def test_e017_ok_function_marker_exact(self, tmp_path: Path) -> None:
        """FUNCTION marker + EXACT status is the healthy state — no E017."""
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\nint foo(void) { return 0; }\n",
            {"SERVER.0x10008880": {"kind": "FUNCTION", "size": 31, "status": "EXACT"}},
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any((c == "E017" for _, c, _ in result.errors))


class TestCflagsPreset:
    def test_invalid_annotation_key_no_error_for_valid(self, tmp_path: Path) -> None:
        """Valid annotations should not produce unknown-key warnings."""
        cfg = _make_cfg(root=tmp_path)
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f, cfg=cfg)
        assert not any((c == "W010" for _, c, _ in result.warnings))


class TestJsonOutput:
    def test_to_dict_structure(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f)
        d = result.to_dict()
        assert "file" in d
        assert "path" in d
        assert "errors" in d
        assert "warnings" in d
        assert "passed" in d
        assert d["passed"] is True

    def test_to_dict_errors(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "empty.c", "")
        result = lint_file(f)
        d = result.to_dict()
        assert d["passed"] is False
        assert len(d["errors"]) > 0
        err = d["errors"][0]
        assert "line" in err
        assert "code" in err
        assert "message" in err


class TestNoConfig:
    def test_lint_without_config(self, tmp_path: Path) -> None:
        """Config-aware checks should not fire when cfg is None."""
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f, cfg=None)
        assert result.passed
        assert not any((c in ("E011", "E012") for _, c, _ in result.errors))

    def test_fix_without_config_warns_instead_of_silent_noop(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--fix outside a project must explain that nothing can migrate
        (functionality-review: previously a silent no-op — the user saw zero
        effect with no message)."""
        from typer.testing import CliRunner

        from rebrew.lint import app

        f = _write_c(
            tmp_path,
            "fcn.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x00401000 */\n\n\nint __cdecl f(void) { return 0; }\n",
                {"SERVER.0x00401000": {"kind": "FUNCTION", "size": 16, "status": "EXACT"}},
            ),
        )
        monkeypatch.chdir(tmp_path)  # no rebrew-project.toml here
        result = CliRunner().invoke(app, ["--fix", str(f)])
        assert result.exit_code == 0
        assert "needs a rebrew-project.toml" in result.output
        # The inline keys must remain untouched.
        assert "// STATUS:" not in f.read_text()
        assert "// SIZE:" not in f.read_text()

    def test_bare_lint_without_config_exits_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No project and no file list is a usage error, not an empty pass.

        The fallback used to rglob the whole cwd, so `rebrew lint` outside a
        project linted vendored trees and reported 0 files (exit 0) when there
        were none."""
        from typer.testing import CliRunner

        from rebrew.lint import app

        monkeypatch.chdir(tmp_path)  # no rebrew-project.toml here
        result = CliRunner().invoke(app, [])
        assert result.exit_code == 2
        assert "rebrew-project.toml" in result.output
        assert "rebrew lint path/to/file.c" in result.output

    def test_bare_lint_without_config_json_envelope(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--json keeps the {"error", "code"} contract on this path too."""
        from typer.testing import CliRunner

        from rebrew.lint import app

        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 2
        payload = json.loads(result.output)
        assert payload["code"] == 2
        assert "rebrew-project.toml" in payload["error"]


class TestVAHexCase:
    def test_w015_mixed_case_va(self, tmp_path: Path) -> None:
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x1000AbCd */\n\n\n\nint foo(void) { return 0; }\n",
            {
                "SERVER.0x1000AbCd": {
                    "kind": "FUNCTION",
                    "size": 31,
                    "cflags": "/O2 /Gd",
                    "status": "EXACT",
                }
            },
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any((c == "W015" for _, c, _ in result.warnings))

    def test_w015_consistent_lowercase(self, tmp_path: Path) -> None:
        """All-lowercase VA should not warn."""
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f)
        assert not any((c == "W015" for _, c, _ in result.warnings))

    def test_w015_consistent_uppercase(self, tmp_path: Path) -> None:
        """All-uppercase VA should not warn."""
        content = VALID_HEADER.replace("0x10008880", "0x10008ABF")
        f = _write_c(tmp_path, "bit_reverse.c", content)
        result = lint_file(f)
        assert not any((c == "W015" for _, c, _ in result.warnings))


class TestW016Section:
    def test_w016_global_missing_section(self, tmp_path: Path) -> None:
        """GLOBAL without SECTION in metadata fires W016."""
        metadata_toml = tmp_path / "rebrew-functions.toml"
        write_store_fixture(
            metadata_toml, 'format = 2\n["SERVER.0x10050000"]\nsize = 4\n', encoding="utf-8"
        )
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10050000 */\nint g_foo;\n",
            {"SERVER.0x10050000": {"kind": "GLOBAL"}},
        )
        f = _write_c(tmp_path, "g_foo.c", content)
        result = lint_file(f)
        assert any((c == "W016" for _, c, _ in result.warnings))

    def test_w016_data_missing_section(self, tmp_path: Path) -> None:
        """DATA without SECTION in metadata fires W016."""
        metadata_toml = tmp_path / "rebrew-functions.toml"
        write_store_fixture(
            metadata_toml, 'format = 2\n["SERVER.0x10050000"]\nsize = 10\n', encoding="utf-8"
        )
        content = SourceFixture(
            '/* ADDRESS: SERVER 0x10050000 */\nchar s_hello[] = "hello";\n',
            {"SERVER.0x10050000": {"kind": "DATA"}},
        )
        f = _write_c(tmp_path, "s_hello.c", content)
        result = lint_file(f)
        assert any((c == "W016" for _, c, _ in result.warnings))

    def test_w016_global_with_section_no_warning(self, tmp_path: Path) -> None:
        """SECTION from the metadata should suppress W016 without inline SECTION."""
        metadata_toml = tmp_path / "rebrew-functions.toml"
        write_store_fixture(
            metadata_toml,
            'format = 2\n["SERVER.0x10050000"]\nsize = 4\nsection = ".bss"\n',
            encoding="utf-8",
        )
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10050000 */\nint g_foo;\n",
            {"SERVER.0x10050000": {"kind": "GLOBAL"}},
        )
        f = _write_c(tmp_path, "g_foo.c", content)
        result = lint_file(f)
        assert not any((c == "W016" for _, c, _ in result.warnings))
        assert not any(("SECTION" in m for _, c, m in result.warnings if c == "W019"))

    def test_w016_function_no_warning(self, tmp_path: Path) -> None:
        f = _write_c(tmp_path, "bit_reverse.c", VALID_HEADER)
        result = lint_file(f)
        assert not any((c == "W016" for _, c, _ in result.warnings))


class TestPrintSummary:
    def test_summary_counters_populated(self, tmp_path: Path) -> None:
        """LintResult should have status/marker counters populated after lint."""
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\nint __cdecl bit_reverse(int x) { return x; }\n",
            {"SERVER.0x10008880": {"kind": "FUNCTION", "status": "EXACT"}},
        )
        f = _write_c(tmp_path, "bit_reverse.c", content)
        result = lint_file(f)
        assert result._status_counts["EXACT"] == 1
        assert result._marker_counts["FUNCTION"] == 1

    def test_summary_counters_multi_block(self, tmp_path: Path) -> None:
        """Multi-block file should accumulate counters across blocks."""
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\nint func1() { return 1; }\n\n/* ADDRESS: SERVER 0x10009990 */\n\n\nint func2() { return 0; }\n",
            {
                "SERVER.0x10008880": {"kind": "FUNCTION", "status": "EXACT"},
                "SERVER.0x10009990": {"kind": "STUB", "status": "STUB"},
            },
        )
        f = _write_c(tmp_path, "multi.c", content)
        result = lint_file(f)
        assert result._status_counts["EXACT"] == 1
        assert result._status_counts["STUB"] == 1
        assert result._marker_counts["FUNCTION"] == 1
        assert result._marker_counts["STUB"] == 1


class TestLintResult:
    def test_empty_passes(self) -> None:
        r = LintResult(filepath=Path("test.c"))
        assert r.passed is True

    def test_error_fails(self) -> None:
        r = LintResult(filepath=Path("test.c"))
        r.error(1, "E001", "bad thing")
        assert r.passed is False
        assert len(r.errors) == 1

    def test_warning_still_passes(self) -> None:
        r = LintResult(filepath=Path("test.c"))
        r.warning(1, "W001", "minor thing")
        assert r.passed is True
        assert len(r.warnings) == 1

    def test_to_dict(self) -> None:
        r = LintResult(filepath=Path("test.c"))
        r.error(1, "E001", "msg")
        r.warning(2, "W001", "msg2")
        d = r.to_dict()
        assert d["file"] == "test.c"
        assert len(d["errors"]) == 1
        assert len(d["warnings"]) == 1

    def test_display_no_crash(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = LintResult(filepath=Path("test.c"))
        r.error(1, "E001", "err")
        r.warning(2, "W001", "warn")
        # Both display modes must render the file, and --quiet may only drop
        # the warnings. A renderer that printed nothing would satisfy a bare
        # no-crash check, and the check would still pass.
        r.display()
        full = capsys.readouterr()
        r.display(quiet=True)
        quiet = capsys.readouterr()
        combined = full.out + full.err
        assert "test.c" in combined
        assert "E001" in combined
        assert "W001" in combined
        kept = quiet.out + quiet.err
        assert "E001" in kept
        assert "W001" not in kept


def _make_c_file(tmp_path: Path, name: str = "my_func.c", content: str | None = None) -> Path:
    if content is None:
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\nvoid __cdecl _my_func(void) {\n    // stub\n}\n",
            {
                "SERVER.0x10001000": {
                    "kind": "STUB",
                    "size": 64,
                    "cflags": "/O2 /Gd",
                    "symbol": "_my_func",
                    "status": "STUB",
                }
            },
        )
    f = tmp_path / name
    write_source(f, content, encoding="utf-8")
    return f


class TestLintFile:
    def test_valid_file(self, tmp_path: Path) -> None:
        f = _make_c_file(tmp_path)
        result = lint_file(f)
        assert result.passed is True

    def test_missing_function_annotation(self, tmp_path: Path) -> None:
        f = _make_c_file(tmp_path, content="void f() {}\n")
        result = lint_file(f)
        assert result.passed is False

    def test_missing_symbol(self, tmp_path: Path) -> None:
        """SYMBOL is derived from C function definitions — W001 should not fire."""
        f = _make_c_file(
            tmp_path,
            content=SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\nvoid __cdecl _my_func(void) {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "cflags": "/O2 /Gd",
                        "status": "STUB",
                    }
                },
            ),
        )
        result = lint_file(f)
        assert not any((c == "W001" for _, c, _ in result.warnings))

    def test_missing_size(self, tmp_path: Path) -> None:
        """SIZE lives in metadata — a FUNCTION+STUB file without inline SIZE
        is valid (no error); only the metadata-migration warning fires."""
        f = _make_c_file(
            tmp_path,
            content=SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\nvoid __cdecl _my_func(void) {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "cflags": "/O2 /Gd",
                        "symbol": "_my_func",
                        "status": "STUB",
                    }
                },
            ),
        )
        result = lint_file(f)
        assert result.passed
        assert result.errors == []

    def test_duplicate_va_detection(self, tmp_path: Path) -> None:
        seen_vas: dict[int, str] = {}
        f1 = _make_c_file(tmp_path, name="func1.c")
        f2 = _make_c_file(tmp_path, name="func2.c")
        result1 = lint_file(f1, seen_vas=seen_vas)
        result2 = lint_file(f2, seen_vas=seen_vas)
        assert any(
            c == "E001" and "stored source binding" in message for _, c, message in result1.errors
        )
        assert not any(c == "E013" for _, c, _ in result2.errors)

    def test_with_config(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(root=tmp_path, marker="SERVER")
        f = _make_c_file(tmp_path)
        result = lint_file(f, cfg=cfg)
        assert result.passed
        assert result.errors == []

    def test_multiple_functions_in_file(self, tmp_path: Path) -> None:
        f = _make_c_file(
            tmp_path,
            content=SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\nvoid __cdecl _func_a(void) {}\n\n/* ADDRESS: SERVER 0x10002000 */\n\n\n\n\n\nvoid __cdecl _func_b(void) {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "cflags": "/O2 /Gd",
                        "symbol": "_func_a",
                        "status": "STUB",
                    },
                    "SERVER.0x10002000": {
                        "kind": "FUNCTION",
                        "size": 128,
                        "cflags": "/O2 /Gd",
                        "symbol": "_func_b",
                        "status": "STUB",
                    },
                },
            ),
        )
        result = lint_file(f)
        # Both function blocks should be detected (warnings expected for inline metadata)
        assert result._marker_counts["FUNCTION"] == 2

    def test_empty_file(self, tmp_path: Path) -> None:
        f = _make_c_file(tmp_path, content="")
        result = lint_file(f)
        assert not result.passed

    def test_bad_cflags(self, tmp_path: Path) -> None:
        f = _make_c_file(
            tmp_path,
            content=SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\n\n\n\n\nvoid __cdecl _my_func(void) {}\n",
                {
                    "SERVER.0x10001000": {
                        "kind": "FUNCTION",
                        "size": 64,
                        "cflags": "",
                        "symbol": "_my_func",
                        "status": "STUB",
                    }
                },
            ),
        )
        result = lint_file(f)
        # FUNCTION+STUB is a valid marker combination (status lives in
        # metadata); the real issue is the empty inline CFLAGS.
        assert result.passed
        # Empty CFLAGS should produce W018 (missing CFLAGS with no config fallback)
        assert any(c == "W018" for _, c, _ in result.warnings)
        assert any("CFLAGS" in m for _, c, m in result.warnings if c == "W018")


class TestLintFileBranches:
    def test_w019_silent_for_metadata_backed_after_name_hint(self, tmp_path: Path) -> None:
        """SIZE after a name-hint line that metadata already owns stays silent."""
        from rebrew.lint import lint_file
        from rebrew.metadata.functions import update_field

        src = tmp_path / "src"
        src.mkdir()
        write_source(
            src / "foo.c",
            "/* ADDRESS: SERVER 0x1000 */\n// FooBar\n\nint FooBar(void) { return 0; }\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION", "size": 42}},
            metadata_dir=tmp_path,
        )
        update_field(tmp_path, 0x1000, "size", 42, module="SERVER")
        cfg = SimpleNamespace(
            metadata_dir=tmp_path,
            marker="SERVER",
            library_modules=set(),
            cflags_presets={},
            default_cflags="/O2",
            origins=[],
        )
        result = lint_file(src / "foo.c", cfg=cfg)  # type: ignore[arg-type]
        w019 = [m for _, c, m in result.warnings if c == "W019"]
        assert w019 == []  # metadata-sourced keys must not fire W019

    def test_preloaded_data_metadata_overlay(self, tmp_path: Path) -> None:
        """DATA markers pull size/section/note from rebrew-data.toml without W019."""
        from rebrew.lint import lint_file
        from rebrew.metadata.data import set_data_field

        src = tmp_path / "src"
        src.mkdir()
        write_source(
            src / "globals.c",
            "/* ADDRESS: SERVER 0x1000 */\nint g_x;\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "DATA"}},
            metadata_dir=tmp_path,
        )
        set_data_field(tmp_path, 0x1000, "size", 16, "SERVER")
        set_data_field(tmp_path, 0x1000, "section", ".data", "SERVER")
        set_data_field(tmp_path, 0x1000, "note", "counter", "SERVER")
        cfg = SimpleNamespace(
            metadata_dir=tmp_path,
            marker="SERVER",
            library_modules=set(),
            cflags_presets={},
            default_cflags="/O2",
            origins=[],
        )
        result = lint_file(src / "globals.c", cfg=cfg)  # type: ignore[arg-type]
        w019 = [e for e in result.errors + result.warnings if e[1] == "W019"]
        assert w019 == []  # metadata-sourced keys must not fire W019

    def test_invalid_va_reports_e002(self, tmp_path: Path) -> None:
        from rebrew.lint import lint_file

        src = tmp_path / "src"
        src.mkdir()
        write_source(
            src / "f.c",
            "/* ADDRESS: SERVER 0x123 */\nint f(void) { return 0; }\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x123": {"kind": "FUNCTION"}},
        )
        result = lint_file(src / "f.c")
        assert any(e[1] == "E002" for e in result.errors)


class TestLintCli:
    def _invoke(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]) -> object:
        from typer.testing import CliRunner

        from rebrew.lint import app

        cfg = SimpleNamespace(
            root=tmp_path,
            metadata_dir=tmp_path,
            reversed_dir=tmp_path / "src",
            marker="SERVER",
            source_ext=".c",
            library_modules=set(),
            cflags_presets={},
            default_cflags="/O2",
            origins=["GAME", "SERVER"],
        )
        monkeypatch.setattr("rebrew.lint.load_config", lambda root=None, **kw: cfg)
        return CliRunner().invoke(app, args)

    def test_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        src = tmp_path / "src"
        src.mkdir()
        write_source(
            src / "ok.c",
            "/* ADDRESS: SERVER 0x1000 */\nint f(void) { return 0; }\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        result = self._invoke(tmp_path, monkeypatch, ["--json", str(src / "ok.c")])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["files"][0]["path"] == str(src / "ok.c")

    def test_json_quiet_lists_errors_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        src = tmp_path / "src"
        src.mkdir()
        write_source(
            src / "ok.c",
            "/* ADDRESS: SERVER 0x1000 */\nint f(void) { return 0; }\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        (src / "bad.c").write_text("not a c file\n", encoding="utf-8")
        args = ["--quiet", "--json", str(src / "ok.c"), str(src / "bad.c")]
        data = json.loads(self._invoke(tmp_path, monkeypatch, args).stdout)
        assert data["warnings"] > 0
        assert [f["file"] for f in data["files"]] == ["bad.c"]
        assert data["files"][0]["errors"]
        assert data["files"][0]["warnings"] == []

    def test_errors_exit_nonzero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        src = tmp_path / "src"
        src.mkdir()
        (src / "bad.c").write_text("not a c file\n", encoding="utf-8")
        result = self._invoke(tmp_path, monkeypatch, ["--json", str(src / "bad.c")])
        assert result.exit_code == 1
        data = json.loads(result.stdout)
        assert [e["code"] for e in data["files"][0]["errors"]] == ["E001"]

    def test_summary_flag(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        src = tmp_path / "src"
        src.mkdir()
        write_source(
            src / "ok.c",
            "/* ADDRESS: SERVER 0x1000 */\nint f(void) { return 0; }\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        result = self._invoke(tmp_path, monkeypatch, ["--summary", str(src / "ok.c")])
        assert result.exit_code == 0
        assert "Summary" in result.output
        assert "MARKER" in result.output
        assert "FUNCTION" in result.output


class TestLintFix:
    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            root=tmp_path,
            metadata_dir=tmp_path,
            reversed_dir=tmp_path / "src",
            marker="SERVER",
            source_ext=".c",
            library_modules=set(),
            cflags_presets={},
            default_cflags="/O2",
            origins=["GAME", "SERVER"],
        )

    def _write_inline(self, tmp_path: Path) -> Path:
        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        f = src / "f.c"
        write_source(
            f,
            "/* ADDRESS: SERVER 0x1000 */\n\n\nint f(void) { return 0; }\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION", "size": 42, "status": "EXACT"}},
        )
        return f


class TestW020AsmDump:
    """Asm-dump placeholders (__emit / __asm blocks) must be flagged as W020."""

    def _lint(self, tmp_path: Path, body: str) -> LintResult:
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n" + body,
            {"SERVER.0x10008880": {"status": "EXACT", "size": 31, "cflags": "/O2 /Gd"}},
        )
        f = _write_c(tmp_path, "foo.c", content)
        return lint_file(f)

    def test_emit_byte_dump_warns(self, tmp_path: Path) -> None:
        # Whole-function __declspec(naked) + __asm/__emit is now E023 (error),
        # not W020. Only 1-2 nop/0x90/0xCC padding bytes are allowed as naked.
        body = "__declspec(naked) int f(void) {\n    __asm {\n        _emit 0x55\n        _emit 0x8b\n    }\n}\n"
        result = self._lint(tmp_path, body)
        assert any(c == "E023" for _, c, _ in result.errors), (
            f"expected E023, got errors={result.errors} warnings={result.warnings}"
        )
        assert not any(c == "W020" for _, c, _ in result.warnings)  # naked dumps are E023, not W020
        msg = next(m for _, c, m in result.errors if c == "E023")
        assert "naked" in msg.lower()

    def test_inline_asm_block_warns(self, tmp_path: Path) -> None:
        body = "int f(void) {\n    __asm { mov eax, 1 }\n    return 0;\n}\n"
        result = self._lint(tmp_path, body)
        assert any(c == "W020" for _, c, _ in result.warnings)

    def test_plain_c_does_not_warn(self, tmp_path: Path) -> None:
        body = "int f(void) { return 42; }\n"
        result = self._lint(tmp_path, body)
        assert not any(c == "W020" for _, c, _ in result.warnings)

    def _pure_c(self, tmp_path: Path, blocker: str | None) -> LintResult:
        """A pure-C file: its blocker lives only in the function store."""
        from rebrew.metadata.functions import record_function_identity, set_fields

        record_function_identity(
            tmp_path,
            module="SERVER",
            va=0x10008880,
            file="foo.c",
            kind="FUNCTION",
            symbol="_f",
            name="f",
        )
        if blocker:
            set_fields(tmp_path, 0x10008880, {"blocker": blocker}, "SERVER")
        f = _write_c(
            tmp_path, "foo.c", "int f(void) {\n    __asm { mov eax, 1 }\n    return 0;\n}\n"
        )
        return lint_file(f)

    def test_pure_c_asm_under_a_store_blocker_does_not_warn(self, tmp_path: Path) -> None:
        result = self._pure_c(tmp_path, "inline asm kept by decision")
        assert not any(c == "W020" for _, c, _ in result.warnings)

    def test_pure_c_asm_without_a_blocker_warns(self, tmp_path: Path) -> None:
        result = self._pure_c(tmp_path, None)
        assert any(c == "W020" for _, c, _ in result.warnings)

    def test_shared_file_uses_only_the_asm_functions_metadata(self, tmp_path: Path) -> None:
        from rebrew.metadata.functions import (
            record_function_identity,
            set_fields,
            update_source_status,
        )

        for va, name in ((0x10008880, "documented"), (0x10008900, "pending")):
            record_function_identity(
                tmp_path,
                module="SERVER",
                va=va,
                file="shared.c",
                kind="FUNCTION",
                symbol="_" + name,
                name=name,
            )
        update_source_status(tmp_path, "EXACT", "SERVER", 0x10008880)
        set_fields(tmp_path, 0x10008880, {"blocker": "original asm"}, "SERVER")
        update_source_status(tmp_path, "STUB", "SERVER", 0x10008900)
        source = (
            "int documented(void) {\n    __asm { mov eax, 1 }\n    return 0;\n}\n"
            "int pending(void) {\n    __asm { mov eax, 2 }\n    return 0;\n}\n"
        )
        result = lint_file(_write_c(tmp_path, "shared.c", source))
        warnings = [(line, msg) for line, code, msg in result.warnings if code == "W020"]
        assert len(warnings) == 1
        assert warnings[0][0] == 6
        assert "EXACT" not in warnings[0][1]

    def test_unrelated_status_does_not_escalate_asm(self, tmp_path: Path) -> None:
        source = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\nint complete(void) { return 0; }\n/* ADDRESS: SERVER 0x10008900 */\n\nint pending(void) {\n    __asm { mov eax, 2 }\n    return 0;\n}\n",
            {
                "SERVER.0x10008880": {"kind": "FUNCTION", "status": "EXACT"},
                "SERVER.0x10008900": {"kind": "FUNCTION", "status": "STUB"},
            },
        )
        result = lint_file(_write_c(tmp_path, "shared.c", source))
        warnings = [msg for _, code, msg in result.warnings if code == "W020"]
        assert len(warnings) == 1
        assert "EXACT" not in warnings[0]

    def test_naked_function_does_not_hide_another_functions_asm(self, tmp_path: Path) -> None:
        source = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n__declspec(naked) void dump(void) {\n    __asm { _emit 0x55 }\n}\n/* ADDRESS: SERVER 0x10008900 */\nint pending(void) {\n    __asm { mov eax, 2 }\n    return 0;\n}\n",
            {
                "SERVER.0x10008880": {"kind": "FUNCTION", "status": "EXACT"},
                "SERVER.0x10008900": {"kind": "FUNCTION"},
            },
        )
        result = lint_file(_write_c(tmp_path, "shared.c", source))
        assert any(code == "E023" for _, code, _ in result.errors)
        assert [line for line, code, _ in result.warnings if code == "W020"] == [7]

    def test_reports_each_undocumented_function(self, tmp_path: Path) -> None:
        source = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\nint first(void) {\n    __asm { mov eax, 1 }\n    return 0;\n}\n/* ADDRESS: SERVER 0x10008900 */\nint second(void) {\n    __asm { mov eax, 2 }\n    return 0;\n}\n",
            {
                "SERVER.0x10008880": {"kind": "FUNCTION", "status": "EXACT"},
                "SERVER.0x10008900": {"kind": "FUNCTION"},
            },
        )
        result = lint_file(_write_c(tmp_path, "shared.c", source))
        assert [line for line, code, _ in result.warnings if code == "W020"] == [3, 8]

    def test_store_blocker_and_status_do_not_leak_between_targets(self, tmp_path: Path) -> None:
        from rebrew.metadata.functions import (
            record_function_identity,
            set_fields,
            update_source_status,
        )

        for module, va, status in (("SERVER", 0x10008880, "EXACT"), ("GOLDTL", 0x408880, "STUB")):
            record_function_identity(
                tmp_path,
                module=module,
                va=va,
                file="shared.c",
                kind="FUNCTION",
                symbol="_shared",
                name="shared",
            )
            update_source_status(tmp_path, status, module, va)
        set_fields(tmp_path, 0x10008880, {"blocker": "original asm"}, "SERVER")
        cfg = _make_cfg(marker="GOLDTL", reversed_dir=tmp_path, root=tmp_path)
        cfg.root = tmp_path
        cfg.all_markers = {"SERVER", "GOLDTL"}
        source = "int shared(void) {\n    __asm { mov eax, 1 }\n    return 0;\n}\n"
        result = lint_file(_write_c(tmp_path, "shared.c", source), cfg=cfg)
        warnings = [msg for _, code, msg in result.warnings if code == "W020"]
        assert len(warnings) == 1
        assert "EXACT" not in warnings[0]
        cfg.marker = "SERVER"
        assert not any(
            code == "W020" for _, code, _ in lint_file(tmp_path / "shared.c", cfg=cfg).warnings
        )

    def test_inline_target_status_does_not_leak(self, tmp_path: Path) -> None:
        cfg = _make_cfg(marker="GOLDTL", reversed_dir=tmp_path, root=tmp_path)
        cfg.root = tmp_path
        cfg.all_markers = {"SERVER", "GOLDTL"}
        source = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n/* ADDRESS: GOLDTL 0x408880 */\n\nint shared(void) {\n    __asm { mov eax, 1 }\n    return 0;\n}\n",
            {
                "SERVER.0x10008880": {"kind": "FUNCTION", "status": "EXACT"},
                "GOLDTL.0x408880": {"kind": "FUNCTION", "status": "STUB"},
            },
        )
        result = lint_file(_write_c(tmp_path, "shared.c", source), cfg=cfg)
        warnings = [msg for _, code, msg in result.warnings if code == "W020"]
        assert len(warnings) == 1
        assert "EXACT" not in warnings[0]

    def test_foreign_target_assembly_is_not_reported(self, tmp_path: Path) -> None:
        cfg = _make_cfg(marker="SERVER", reversed_dir=tmp_path, root=tmp_path)
        cfg.root = tmp_path
        cfg.all_markers = {"SERVER", "GOLDTL"}
        source = SourceFixture(
            "static void fill(void) {\n    __asm { mov eax, 1 }\n}\n/* ADDRESS: GOLDTL 0x408880 */\nint client(void) {\n    __asm { mov eax, 1 }\n    return 0;\n}\n",
            {"GOLDTL.0x408880": {"kind": "FUNCTION"}},
        )
        assert not any(
            code == "W020"
            for _, code, _ in lint_file(_write_c(tmp_path, "client.c", source), cfg=cfg).warnings
        )

    def test_string_literals_do_not_break_function_ownership(self, tmp_path: Path) -> None:
        from rebrew.metadata.functions import record_function_identity, set_fields

        record_function_identity(
            tmp_path,
            module="SERVER",
            va=0x10008880,
            file="strings.c",
            kind="FUNCTION",
            symbol="_f",
            name="display_name",
        )
        set_fields(tmp_path, 0x10008880, {"blocker": "original asm"}, "SERVER")
        source = (
            'char* f(void) {\n    char* text[] = { "a", "b" };\n'
            "    __asm { mov eax, 1 }\n    return text[0];\n}\n"
            "int pending(void) {\n    __asm { mov eax, 2 }\n    return 0;\n}\n"
        )
        result = lint_file(_write_c(tmp_path, "strings.c", source))
        assert [line for line, code, _ in result.warnings if code == "W020"] == [7]

    def test_bare_emit_spelling_warns(self, tmp_path: Path) -> None:
        """`rebrew asm` writes the bare `_emit 0xNN` form, so W020 must match it."""
        body = "int f(void) {\n    __asm { _emit 0x55 }\n    return 0;\n}\n"
        result = self._lint(tmp_path, body)
        assert any(c == "W020" for _, c, _ in result.warnings)

    def test_asm_in_comment_does_not_warn(self, tmp_path: Path) -> None:
        # "// __asm" in a comment is not an implementation.
        body = "// __asm notes about the original\nint f(void) { return 0; }\n"
        result = self._lint(tmp_path, body)
        assert not any(c == "W020" for _, c, _ in result.warnings)

    def test_stub_asm_dump_is_documented_placeholder(self, tmp_path: Path) -> None:
        """STUB + asm dump is an expected placeholder — base message, no escalation."""
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\n\nint f(void) {\n    __asm { _emit 0x55 }\n}\n",
            {
                "SERVER.0x10008880": {
                    "kind": "FUNCTION",
                    "size": 31,
                    "cflags": "/O2 /Gd",
                    "status": "STUB",
                }
            },
        )
        result = lint_file(_write_c(tmp_path, "stub.c", content))
        msg = next(m for _, c, m in result.warnings if c == "W020")
        assert "cannot be a byte-match" not in msg  # STUB is fine — not escalated
        assert "assembly" in msg.lower()

    def test_exact_claim_on_asm_dump_escalates(self, tmp_path: Path) -> None:
        """EXACT + asm dump is a metadata contradiction — W020 escalates."""
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\n\nint f(void) {\n    __asm { _emit 0x55 }\n}\n",
            {
                "SERVER.0x10008880": {
                    "kind": "FUNCTION",
                    "size": 31,
                    "cflags": "/O2 /Gd",
                    "status": "EXACT",
                }
            },
        )
        result = lint_file(_write_c(tmp_path, "claimed.c", content))
        msg = next(m for _, c, m in result.warnings if c == "W020")
        assert "EXACT" in msg
        assert "original assembly provenance" in msg

    def test_recorded_blocker_documents_the_asm_body(self, tmp_path: Path) -> None:
        """A BLOCKER is the remedy the escalated message names, so it must
        actually clear the warning: a partial __asm under a documented blocker
        is the end state, not a placeholder."""
        metadata_toml = tmp_path / "rebrew-functions.toml"
        write_store_fixture(
            metadata_toml,
            'format = 2\n["SERVER.0x10008880"]\nblocker = "block-fill prelude: pure C cannot emit; kept as __asm"\n',
            encoding="utf-8",
        )
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n\n\n\nint f(void) {\n    __asm { mov eax, 1 }\n    return 0;\n}\n",
            {
                "SERVER.0x10008880": {
                    "kind": "FUNCTION",
                    "size": 31,
                    "cflags": "/O2 /Gd",
                    "status": "RELOC",
                }
            },
        )
        result = lint_file(_write_c(tmp_path, "documented.c", content))
        assert not any(c == "W020" for _, c, _ in result.warnings), (
            f"a recorded blocker must clear W020, got {result.warnings}"
        )


class TestE023NakedAsm:
    """E023: whole-function __declspec(naked)+__asm is an error; minor padding (1-2 nops) is allowed."""

    def _lint(self, tmp_path: Path, body: str) -> LintResult:
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n" + body,
            {"SERVER.0x10008880": {"status": "EXACT", "size": 31, "cflags": "/O2 /Gd"}},
        )
        f = _write_c(tmp_path, "foo.c", content)
        return lint_file(f)

    def test_whole_function_naked_asm_is_error(self, tmp_path: Path) -> None:
        body = "__declspec(naked) int f(void) {\n    __asm { push ebp }\n    __asm { mov eax, 1 }\n    __asm { ret }\n}\n"
        result = self._lint(tmp_path, body)
        assert any(c == "E023" for _, c, _ in result.errors)
        assert not result.passed
        msg = next(m for _, c, m in result.errors if c == "E023")
        assert "naked" in msg.lower()

    def test_whole_function_naked_emit_is_error(self, tmp_path: Path) -> None:
        body = "__declspec(naked) int f(void) {\n    __asm {\n        _emit 0x55\n        _emit 0x8b\n        _emit 0xc3\n    }\n}\n"
        result = self._lint(tmp_path, body)
        assert any(c == "E023" for _, c, _ in result.errors)

    def test_naked_minor_padding_one_nop_allowed(self, tmp_path: Path) -> None:
        body = "__declspec(naked) int f(void) {\n    __asm nop\n}\n"
        result = self._lint(tmp_path, body)
        assert not any(c == "E023" for _, c, _ in result.errors)

    def test_naked_minor_padding_two_emit_padding_allowed(self, tmp_path: Path) -> None:
        body = "__declspec(naked) int f(void) {\n    __asm { _emit 0x90 }\n    __asm { _emit 0x90 }\n}\n"
        result = self._lint(tmp_path, body)
        assert not any(c == "E023" for _, c, _ in result.errors)

    def test_non_naked_asm_still_W020_not_E023(self, tmp_path: Path) -> None:
        body = "int f(void) {\n    __asm { mov eax, 1 }\n    __asm { mov ebx, 2 }\n    __asm { ret }\n}\n"
        result = self._lint(tmp_path, body)
        assert not any(c == "E023" for _, c, _ in result.errors)
        assert any(c == "W020" for _, c, _ in result.warnings)

    def test_naked_without_asm_no_error(self, tmp_path: Path) -> None:
        body = "__declspec(naked) int f(void) { return 0; }\n"
        result = self._lint(tmp_path, body)
        assert not any(c == "E023" for _, c, _ in result.errors)

    def test_metadata_cflags_rebrew_allow_naked_skips_e023(self, tmp_path: Path) -> None:
        """REBREW_ALLOW_NAKED in rebrew-functions.toml (not source) suppresses E023."""
        metadata_toml = tmp_path / "rebrew-functions.toml"
        write_store_fixture(
            metadata_toml,
            'format = 2\n["SERVER.0x10008880"]\ncflags = "/O2 /Gd /DREBREW_ALLOW_NAKED"\n',
            encoding="utf-8",
        )
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n__declspec(naked) int f(void) {\n    __asm { push ebp }\n    __asm { mov eax, 1 }\n    __asm { ret }\n}\n",
            {"SERVER.0x10008880": {"kind": "FUNCTION", "status": "EXACT"}},
        )
        f = _write_c(tmp_path, "naked.c", content)
        result = lint_file(f)
        assert not any(c == "E023" for _, c, _ in result.errors), (
            f"E023 must not fire when metadata cflags carry /DREBREW_ALLOW_NAKED, "
            f"got errors={result.errors}"
        )

    def test_metadata_cflags_without_guard_keeps_e023(self, tmp_path: Path) -> None:
        """Metadata cflags that lack REBREW_ALLOW_NAKED must not suppress E023."""
        metadata_toml = tmp_path / "rebrew-functions.toml"
        write_store_fixture(
            metadata_toml,
            'format = 2\n["SERVER.0x10008880"]\ncflags = "/O2 /Gd"\n',
            encoding="utf-8",
        )
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10008880 */\n__declspec(naked) int f(void) {\n    __asm { push ebp }\n    __asm { mov eax, 1 }\n    __asm { ret }\n}\n",
            {"SERVER.0x10008880": {"kind": "FUNCTION", "status": "EXACT"}},
        )
        f = _write_c(tmp_path, "naked2.c", content)
        result = lint_file(f)
        assert any(c == "E023" for _, c, _ in result.errors)


class TestW021W022:
    """Duplicate-global (W021) and zero-init .bss (W022) checks."""

    def test_duplicate_global_across_files(self, tmp_path: Path) -> None:
        from rebrew.lint import lint_file

        def _write(name: str, symbol: str, va: int) -> Path:
            content = SourceFixture(
                f"/* ADDRESS: SERVER 0x{va:08x} */\nextern int {symbol};\n",
                {f"SERVER.0x{va:08x}": {"kind": "DATA"}},
            )
            f = _write_c(tmp_path, name, content)
            return f

        f1 = _write("one.c", "g_counter", 0x10001000)
        seen: dict[str, tuple[str, int, bool]] = {}
        r1 = lint_file(f1, seen_globals=seen)
        assert not any(c == "W021" for _, c, _ in r1.warnings)

        f2 = _write("two.c", "g_counter", 0x10002000)
        r2 = lint_file(f2, seen_globals=seen)
        assert any(c == "W021" for _, c, _ in r2.warnings)
        msg = next(m for _, c, m in r2.warnings if c == "W021")
        assert "g_counter" in msg

    def test_same_name_on_different_modules_is_not_a_duplicate(self, tmp_path: Path) -> None:
        """SERVER and GOLDTL each own a g_counter. Same C name, different binary."""
        from rebrew.lint import lint_file

        seen: dict[str, tuple[str, int, bool]] = {}
        f1 = _write_c(
            tmp_path,
            "server.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\nextern int g_counter;\n",
                {"SERVER.0x10001000": {"kind": "DATA"}},
            ),
        )
        f2 = _write_c(
            tmp_path,
            "client.c",
            SourceFixture(
                "/* ADDRESS: GOLDTL 0x00677918 */\nextern int g_counter;\n",
                {"GOLDTL.0x00677918": {"kind": "DATA"}},
            ),
        )
        assert not any(c == "W021" for _, c, _ in lint_file(f1, seen_globals=seen).warnings)
        assert not any(c == "W021" for _, c, _ in lint_file(f2, seen_globals=seen).warnings)

    def test_unique_globals_no_warning(self, tmp_path: Path) -> None:
        from rebrew.lint import lint_file

        seen: dict[str, tuple[str, int, bool]] = {}
        for i, name in enumerate(("g_a", "g_b", "g_c")):
            f = _write_c(
                tmp_path,
                f"f{i}.c",
                SourceFixture(
                    f"/* ADDRESS: SERVER 0x1000{i:03x} */\nextern int {name};\n",
                    {f"SERVER.0x1000{i:03x}": {"kind": "DATA"}},
                ),
            )
            r = lint_file(f, seen_globals=seen)
            assert not any(c == "W021" for _, c, _ in r.warnings)

    def test_block_comment_marker_across_files(self, tmp_path: Path) -> None:
        """`/* DATA: */` is a marker form the parser accepts, so W021 must see
        it too. Recognising only `//` left every C89-strict block
        unreported."""
        from rebrew.lint import lint_file

        seen: dict[str, tuple[str, int, bool]] = {}
        f1 = _write_c(
            tmp_path,
            "one.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x1000 */\nextern int g_counter;\n",
                {"SERVER.0x1000": {"kind": "DATA"}},
            ),
        )
        r1 = lint_file(f1, seen_globals=seen)
        assert not any(c == "W021" for _, c, _ in r1.warnings)
        f2 = _write_c(
            tmp_path,
            "two.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x2000 */\nextern int g_counter;\n",
                {"SERVER.0x2000": {"kind": "DATA"}},
            ),
        )
        r2 = lint_file(f2, seen_globals=seen)
        assert any(c == "W021" for _, c, _ in r2.warnings)

    @pytest.mark.parametrize("owner_first", [False, True])
    def test_owner_and_references_preserve_duplicate_detection(
        self, tmp_path: Path, owner_first: bool
    ) -> None:
        """Same-address externs are references, and cannot hide a second owner."""
        seen: dict[str, tuple[str, int, bool]] = {}
        owner = SourceFixture(
            "/* ADDRESS: SERVER 0x10001000 */\nint g_counter = 0;\n",
            {"SERVER.0x10001000": {"kind": "DATA"}},
        )
        reference = SourceFixture(
            "/* ADDRESS: SERVER 0x10001000 */\nextern int g_counter;\n",
            {"SERVER.0x10001000": {"kind": "GLOBAL"}},
        )
        sources = [owner, reference] if owner_first else [reference, owner]
        sources.append(reference)
        for i, content in enumerate(sources):
            result = lint_file(_write_c(tmp_path, f"f{i}.c", content), seen_globals=seen)
            assert not any(code == "W021" for _, code, _ in result.warnings)
        duplicate = lint_file(_write_c(tmp_path, "duplicate.c", owner), seen_globals=seen)
        assert any(code == "W021" for _, code, _ in duplicate.warnings)

    def test_repeated_externs_still_detect_conflicting_address(self, tmp_path: Path) -> None:
        """An extern may repeat its address, but cannot identify two addresses."""
        seen: dict[str, tuple[str, int, bool]] = {}
        for i in range(2):
            source = SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\nextern int g_counter;\n",
                {"SERVER.0x10001000": {"kind": "GLOBAL"}},
            )
            result = lint_file(_write_c(tmp_path, f"f{i}.c", source), seen_globals=seen)
            assert not any(code == "W021" for _, code, _ in result.warnings)
        conflict = SourceFixture(
            "/* ADDRESS: SERVER 0x10002000 */\nextern int g_counter;\n",
            {"SERVER.0x10002000": {"kind": "DATA"}},
        )
        result = lint_file(_write_c(tmp_path, "conflict.c", conflict), seen_globals=seen)
        assert any(code == "W021" for _, code, _ in result.warnings)

    def test_zero_init_global_warns(self, tmp_path: Path) -> None:
        from rebrew.lint import lint_file

        content = SourceFixture(
            "\nint g_buf[256] = {0};\n/* ADDRESS: SERVER 0x1000 */\nvoid f(void) {}\n",
            {"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "z.c", content)
        result = lint_file(f)
        assert any(c == "W022" for _, c, _ in result.warnings)

    def test_zero_init_nested_bracket_bound_warns(self, tmp_path: Path) -> None:
        """A bound that contains brackets is still a file-scope zero initializer.

        ``char g[sizeof(wchar_t[3])] = {0};`` and ``char g[2][4] = {0};``
        stopped at the first ``]``, so W022 never fired. A recorded ``.data``
        name with the nested bound stays exempt.
        """
        content = SourceFixture(
            "\nchar g_wide[sizeof(wchar_t[3])] = {0};\nchar g_rows[2][4] = {0};\n/* ADDRESS: SERVER 0x1000 */\nvoid f(void) {}\n",
            {"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "w.c", content)
        result = lint_file(f)
        w022 = [line for line, c, _ in result.warnings if c == "W022"]
        assert w022 == [2, 3]

        exempt = lint_file(
            f,
            preloaded_metadata={},
            preloaded_data_metadata={
                ("SERVER", 0x10034628): {"name": "g_wide", "section": ".data"}
            },
        )
        kept = [line for line, c, _ in exempt.warnings if c == "W022"]
        assert kept == [3]

    def test_zero_init_link_symbol_exempt(self, tmp_path: Path) -> None:
        """A ``.bss`` row whose source defines it under ``link_symbol`` is a placement pin."""
        content = "char g_entity_end[4] = {0};\nint g_other = 0;\n"
        f = _write_c(tmp_path, "pin.c", content)
        result = lint_file(
            f,
            preloaded_metadata={},
            preloaded_data_metadata={
                ("SERVER", 0x1009B760): {
                    "name": "g_town_records",
                    "section": ".bss",
                    "link_symbol": "_g_entity_end",
                }
            },
        )
        assert [line for line, c, _ in result.warnings if c == "W022"] == [2]

    def test_duplicate_nested_bracket_global(self, tmp_path: Path) -> None:
        """W021 names the global when its bound contains a bracket."""
        seen: dict[str, tuple[str, int, bool]] = {}
        body = "char g_wide[sizeof(wchar_t[3])] = {0};\n"
        first = lint_file(
            _write_c(
                tmp_path,
                "one.c",
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n" + body,
                    {"SERVER.0x10001000": {"kind": "DATA"}},
                ),
            ),
            seen_globals=seen,
        )
        assert not any(c == "W021" for _, c, _ in first.warnings)
        second = lint_file(
            _write_c(
                tmp_path,
                "two.c",
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10002000 */\n" + body,
                    {"SERVER.0x10002000": {"kind": "DATA"}},
                ),
            ),
            seen_globals=seen,
        )
        assert any(c == "W021" for _, c, _ in second.warnings)

    def test_zero_init_pointer_array_warns(self, tmp_path: Path) -> None:
        """A pointer array's ``= {0}`` is still a file-scope zero initializer.

        ``int *table[4] = {0}`` glues the star to the name, and
        ``int (*rows[4]) = {0}`` puts the brackets inside the parentheses,
        so W022 never fired. A recorded ``.data`` name stays exempt.
        """
        content = SourceFixture(
            "\nint *table[4] = {0};\nint (*rows[4]) = {0};\n/* ADDRESS: SERVER 0x1000 */\nvoid f(void) {}\n",
            {"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "p.c", content)
        result = lint_file(f)
        w022 = [line for line, c, _ in result.warnings if c == "W022"]
        assert w022 == [2, 3]

        exempt = lint_file(
            f,
            preloaded_metadata={},
            preloaded_data_metadata={("SERVER", 0x10034628): {"name": "table", "section": ".data"}},
        )
        kept = [line for line, c, _ in exempt.warnings if c == "W022"]
        assert kept == [3]

    def test_zero_init_cdecl_pointer_array_warns(self, tmp_path: Path) -> None:
        """``int (__cdecl *table[2])[3] = {0}`` is a file-scope zero initializer.

        ``__cdecl`` sat before the star, so W022 never fired.
        ``char (__cdecl *row)[4]`` is one pointer and still warns.
        A recorded ``.data`` name stays exempt. ``int (*plain[2])[3]``
        stays a warning.
        """
        content = SourceFixture(
            "\nint (__cdecl *table[2])[3] = {0};\nint (__stdcall *rows[2])[3] = {0};\nchar (__cdecl *row)[4] = {0};\nint (*plain[2])[3] = {0};\nint g_a = 0;\n/* ADDRESS: SERVER 0x1000 */\nvoid f(void) {}\n",
            {"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "cdecl.c", content)
        result = lint_file(f)
        w022 = [line for line, c, _ in result.warnings if c == "W022"]
        assert w022 == [2, 3, 4, 5, 6]

        exempt = lint_file(
            f,
            preloaded_metadata={},
            preloaded_data_metadata={("SERVER", 0x10034628): {"name": "table", "section": ".data"}},
        )
        kept = [line for line, c, _ in exempt.warnings if c == "W022"]
        assert kept == [3, 4, 5, 6]

    def test_zero_init_const_pointer_array_warns(self, tmp_path: Path) -> None:
        """``int (* const table[2])[3] = {0}`` is a file-scope zero initializer.

        ``const`` sat between the star and the name, so W022 never fired.
        ``char (* const row)[4]`` is one pointer and still warns.
        A recorded ``.data`` name stays exempt.
        """
        content = SourceFixture(
            "\nint (* const table[2])[3] = {0};\nint (* volatile rows[2])[4] = {0};\nchar (* const row)[4] = {0};\nint (__cdecl * const hooks[2])[3] = {0};\nint (*plain[2])[3] = {0};\n/* ADDRESS: SERVER 0x1000 */\nvoid f(void) {}\n",
            {"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "const.c", content)
        result = lint_file(f)
        w022 = [line for line, c, _ in result.warnings if c == "W022"]
        assert w022 == [2, 3, 4, 5, 6]

        exempt = lint_file(
            f,
            preloaded_metadata={},
            preloaded_data_metadata={("SERVER", 0x10034628): {"name": "table", "section": ".data"}},
        )
        kept = [line for line, c, _ in exempt.warnings if c == "W022"]
        assert kept == [3, 4, 5, 6]

    def test_array_of_pointers_to_array_is_named(self, tmp_path: Path) -> None:
        """``int (*table[2])[3]`` is the global ``table``.

        The pointee brackets sat after the closing parenthesis, so W021
        never named it and a recorded ``.data`` ``= {0}`` was not exempt.
        """
        seen: dict[str, tuple[str, int, bool]] = {}
        body = "int (*table[2])[3];\n"
        first = lint_file(
            _write_c(
                tmp_path,
                "one.c",
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n" + body,
                    {"SERVER.0x10001000": {"kind": "DATA"}},
                ),
            ),
            seen_globals=seen,
        )
        assert not any(c == "W021" for _, c, _ in first.warnings)
        second = lint_file(
            _write_c(
                tmp_path,
                "two.c",
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10002000 */\n" + body,
                    {"SERVER.0x10002000": {"kind": "DATA"}},
                ),
            ),
            seen_globals=seen,
        )
        assert any(c == "W021" for _, c, _ in second.warnings)
        msg = next(m for _, c, m in second.warnings if c == "W021")
        assert "table" in msg

        zero = lint_file(
            _write_c(
                tmp_path,
                "z.c",
                SourceFixture(
                    "\nint (*table[2])[3] = {0};\n/* ADDRESS: SERVER 0x1000 */\nvoid f(void) {}\n",
                    {"SERVER.0x1000": {"kind": "FUNCTION"}},
                ),
            ),
            preloaded_metadata={},
            preloaded_data_metadata={("SERVER", 0x10034628): {"name": "table", "section": ".data"}},
        )
        assert not any(c == "W022" for _, c, _ in zero.warnings)

    def test_function_pointer_array_is_named(self, tmp_path: Path) -> None:
        """``void (*cbs[4])(int)`` is the global ``cbs``.

        The parameter list ``(int)`` matched the name pattern before the
        declarator did, so W021 reported ``int``. ``__cdecl`` and ``const``
        before the name are the same global.
        """
        seen: dict[str, tuple[str, int, bool]] = {}
        body = "void (*cbs[4])(int);\n"
        first = lint_file(
            _write_c(
                tmp_path,
                "cbs-one.c",
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n" + body,
                    {"SERVER.0x10001000": {"kind": "DATA"}},
                ),
            ),
            seen_globals=seen,
        )
        assert not any(c == "W021" for _, c, _ in first.warnings)
        second = lint_file(
            _write_c(
                tmp_path,
                "cbs-two.c",
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10002000 */\n" + body,
                    {"SERVER.0x10002000": {"kind": "DATA"}},
                ),
            ),
            seen_globals=seen,
        )
        msg = next(m for _, c, m in second.warnings if c == "W021")
        assert "'cbs'" in msg
        assert "'int'" not in msg

        seen_hooks: dict[str, tuple[str, int, bool]] = {}
        hooks = "void (__cdecl * const hooks[4])(int);\n"
        lint_file(
            _write_c(
                tmp_path,
                "hooks-one.c",
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10003000 */\n" + hooks,
                    {"SERVER.0x10003000": {"kind": "DATA"}},
                ),
            ),
            seen_globals=seen_hooks,
        )
        hooked = lint_file(
            _write_c(
                tmp_path,
                "hooks-two.c",
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10004000 */\n" + hooks,
                    {"SERVER.0x10004000": {"kind": "DATA"}},
                ),
            ),
            seen_globals=seen_hooks,
        )
        hook_msg = next(m for _, c, m in hooked.warnings if c == "W021")
        assert "'hooks'" in hook_msg
        assert "'int'" not in hook_msg

    def test_zero_init_function_pointer_array_warns(self, tmp_path: Path) -> None:
        """``void (*cbs[4])(int) = {0}`` is a file-scope zero initializer.

        The parameter list sat before ``=``, so W022 never fired.
        ``void (*cb)(int) = 0`` is one function pointer and still warns.
        A recorded ``.data`` name stays exempt. ``int g_a = 0`` stays a warning.
        """
        content = SourceFixture(
            "\nvoid (*cbs[4])(int) = {0};\nvoid (__cdecl *hooks[4])(int) = {0};\nvoid (* const slots[2])(int) = {0};\nint (*fns[4])(int) = {0};\nvoid (*cb)(int) = 0;\nint g_a = 0;\n/* ADDRESS: SERVER 0x1000 */\nvoid f(void) {}\n",
            {"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "fn.c", content)
        result = lint_file(f)
        w022 = [line for line, c, _ in result.warnings if c == "W022"]
        assert w022 == [2, 3, 4, 5, 6, 7]

        exempt = lint_file(
            f,
            preloaded_metadata={},
            preloaded_data_metadata={("SERVER", 0x10034628): {"name": "cbs", "section": ".data"}},
        )
        kept = [line for line, c, _ in exempt.warnings if c == "W022"]
        assert kept == [3, 4, 5, 6, 7]

    def test_zero_init_inside_function_no_warning(self, tmp_path: Path) -> None:
        from rebrew.lint import lint_file

        content = SourceFixture(
            "/* ADDRESS: SERVER 0x1000 */\nvoid f(void) {\n    int local[4] = {0};\n    (void)local;\n}\n",
            {"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "l.c", content)
        result = lint_file(f)
        assert not any(c == "W022" for _, c, _ in result.warnings)

    def test_zero_init_in_comment_no_warning(self, tmp_path: Path) -> None:
        from rebrew.lint import lint_file

        # A commented-out zero-init at file scope must not warn, and a
        # string literal that looks like one must not either.
        content = SourceFixture(
            '\n// int g_buf[4] = {0};  // old layout\nconst char *kMsg = "= 0";\n/* ADDRESS: SERVER 0x1000 */\nvoid f(void) {}\n',
            {"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "c.c", content)
        result = lint_file(f)
        assert not any(c == "W022" for _, c, _ in result.warnings)

    def test_zero_init_after_multiline_comment_warns(self, tmp_path: Path) -> None:
        from rebrew.lint import lint_file

        # The file-scope preamble spans lines; the declaration after it must
        # still be seen (block-comment state must not leak).
        content = SourceFixture(
            "/*\n * preamble\n */\n\nint g_buf[4] = {0};\n/* ADDRESS: SERVER 0x1000 */\nvoid f(void) {}\n",
            {"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "m.c", content)
        result = lint_file(f)
        assert any(c == "W022" for _, c, _ in result.warnings)

    def test_zero_init_data_section_name_no_warning(self, tmp_path: Path) -> None:
        """A zero-init global annotated section='.data' in rebrew-data.toml
        is exempt — the original stored the zero-init data in .data."""
        from rebrew.lint import lint_file

        data_toml = tmp_path / "rebrew-data.toml"
        write_store_fixture(
            data_toml,
            'format = 2\n["SERVER.0x10034628"]\nname = "g_stat1"\nsection = ".data"\n',
            encoding="utf-8",
        )
        content = SourceFixture(
            "\nint g_stat1 = 0;\n/* ADDRESS: SERVER 0x1000 */\nvoid f(void) {}\n",
            {"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "d.c", content)
        result = lint_file(f)
        assert not any(c == "W022" for _, c, _ in result.warnings)

    def test_zero_init_bss_section_name_no_warning(self, tmp_path: Path) -> None:
        """A recorded .bss symbol may keep = 0; that pin holds raw .data pointers."""
        from rebrew.lint import lint_file

        data_toml = tmp_path / "rebrew-data.toml"
        write_store_fixture(
            data_toml,
            'format = 2\n["SERVER.0x1004a000"]\nname = "g_buf"\nsection = ".bss"\n',
            encoding="utf-8",
        )
        content = SourceFixture(
            "\nint g_buf[4] = {0};\n/* ADDRESS: SERVER 0x1000 */\nvoid f(void) {}\n",
            {"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "b.c", content)
        result = lint_file(f)
        assert not any(c == "W022" for _, c, _ in result.warnings)

    def test_zero_init_different_name_still_warns(self, tmp_path: Path) -> None:
        """A .data exemption for another symbol does not suppress this global."""
        from rebrew.lint import lint_file

        data_toml = tmp_path / "rebrew-data.toml"
        write_store_fixture(
            data_toml,
            'format = 2\n["SERVER.0x10034628"]\nname = "g_other"\nsection = ".data"\n',
            encoding="utf-8",
        )
        content = SourceFixture(
            "\nint g_buf = 0;\n/* ADDRESS: SERVER 0x1000 */\nvoid f(void) {}\n",
            {"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "n.c", content)
        result = lint_file(f)
        assert any(c == "W022" for _, c, _ in result.warnings)

    def test_zero_init_exempt_and_warn_in_same_file(self, tmp_path: Path) -> None:
        """Exempt .data globals are skipped; a later non-exempt zero-init warns."""
        from rebrew.lint import lint_file

        data_toml = tmp_path / "rebrew-data.toml"
        write_store_fixture(
            data_toml,
            'format = 2\n["SERVER.0x10034628"]\nname = "g_stat1"\nsection = ".data"\n',
            encoding="utf-8",
        )
        content = SourceFixture(
            "\nint g_stat1 = 0;\nint g_bss_var = 0;\n/* ADDRESS: SERVER 0x1000 */\nvoid f(void) {}\n",
            {"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "mx.c", content)
        result = lint_file(f)
        w022 = [(line, m) for line, c, m in result.warnings if c == "W022"]
        assert len(w022) == 1
        assert w022[0][0] == 3

    def test_all_zero_inits_reported(self, tmp_path: Path) -> None:
        """Every file-scope zero initializer warns — the check must not stop
        after the first site."""
        from rebrew.lint import lint_file

        content = SourceFixture(
            "\nint g_a[4] = {0};\nint g_b = 0;\nint g_c[8] = {0};\n/* ADDRESS: SERVER 0x1000 */\nvoid f(void) {}\n",
            {"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "all.c", content)
        result = lint_file(f)
        w022 = sorted(line for line, c, _ in result.warnings if c == "W022")
        assert w022 == [2, 3, 4]


class TestDuplicateVAMultiBlock:
    """E013 must flag a duplicate VA in a LATER block of a multi-function file
    (round-4: the old i == 0 guard only checked the first block)."""

    def test_duplicate_in_later_block_flagged(self, tmp_path: Path) -> None:
        f = tmp_path / "multi.c"
        write_source(
            f,
            "/* ADDRESS: SERVER 0x10008880 */\n\nint first(void) { return 0; }\n\n/* ADDRESS: SERVER 0x10008880 */\n\nint second(void) { return 0; }\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x10008880": {"kind": "FUNCTION", "status": "EXACT"}},
        )
        result = lint_file(f)
        assert any((c in {"E001", "E013"} for _, c, _ in result.errors))

    def test_same_va_different_module_allowed(self, tmp_path: Path) -> None:
        f = tmp_path / "multi.c"
        write_source(
            f,
            "/* ADDRESS: SERVER 0x10008880 */\n\nint first(void) { return 0; }\n\n/* ADDRESS: CLIENT 0x10008880 */\n\nint second(void) { return 0; }\n",
            encoding="utf-8",
            metadata_fields={
                "SERVER.0x10008880": {"kind": "FUNCTION", "status": "EXACT"},
                "CLIENT.0x10008880": {"kind": "FUNCTION", "status": "EXACT"},
            },
        )
        result = lint_file(f)
        assert not any((c == "E013" for _, c, _ in result.errors))


class TestAnnotationStaleness:
    """W028 — FUNCTION/STUB marker VAs must match a function start in the
    current function list (moved from `rebrew doctor`; corpus-content
    checks belong to lint, environment checks to doctor)."""

    # (starts, spans) as built by _build_function_index from a funcs.txt
    # with func_a@0x1000 (256B) and func_b@0x2000 (128B).
    INDEX = (
        {0x1000, 0x2000},
        [(0x1000, 0x1100, "func_a"), (0x2000, 0x2080, "func_b")],
    )

    @staticmethod
    def _w028(result: LintResult) -> list[tuple[int, str]]:
        return [(line, m) for line, c, m in result.warnings if c == "W028"]

    def test_matching_start_silent(self, tmp_path: Path) -> None:
        f = _write_c(
            tmp_path,
            "a.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x1000 */\nint a(void) { return 0; }\n",
                {"SERVER.0x1000": {"kind": "FUNCTION"}},
            ),
        )
        result = lint_file(f, cfg=_make_cfg(root=tmp_path), function_index=self.INDEX)
        assert self._w028(result) == []

    def test_dangling_va_warns(self, tmp_path: Path) -> None:
        f = _write_c(
            tmp_path,
            "a.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x3000 */\nint a(void) { return 0; }\n",
                {"SERVER.0x3000": {"kind": "FUNCTION"}},
            ),
        )
        result = lint_file(f, cfg=_make_cfg(root=tmp_path), function_index=self.INDEX)
        w028 = self._w028(result)
        assert len(w028) == 1
        assert w028[0][0] == 1
        assert "0x3000 has no function" in w028[0][1]
        assert "re-annotate" in w028[0][1]

    def test_va_inside_span_warns(self, tmp_path: Path) -> None:
        f = _write_c(
            tmp_path,
            "a.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x1050 */\nint a(void) { return 0; }\n",
                {"SERVER.0x1050": {"kind": "FUNCTION"}},
            ),
        )
        result = lint_file(f, cfg=_make_cfg(root=tmp_path), function_index=self.INDEX)
        w028 = self._w028(result)
        assert len(w028) == 1
        assert "points inside function 'func_a'" in w028[0][1]

    def test_byte_matched_va_inside_span_is_not_flagged(self, tmp_path: Path) -> None:
        """A matched annotation outranks the heuristic inventory.

        Regression: the inventory comes from rizin plus a capstone sweep, which
        merges adjacent functions when the only boundary is `ret` plus
        alignment padding.  W028 then fired on annotations that had ALREADY
        compiled and compared byte-for-byte at that VA, and its advice
        ("re-annotate the marker VA") would have broken a matched function.
        guild-rebrew hit 15 at once, one of them EXACT, whose supposed host was
        separated from it by `ret; nop; nop`.
        """
        for status in ("EXACT", "RELOC"):
            f = _write_c(
                tmp_path,
                f"m_{status}.c",
                SourceFixture(
                    "/* ADDRESS: SERVER 0x1050 */\nint a(void) { return 0; }\n",
                    {"SERVER.0x1050": {"kind": "FUNCTION"}},
                ),
            )
            meta = {("SERVER", 0x1050): {"status": status}}
            result = lint_file(
                f, cfg=_make_cfg(root=tmp_path), function_index=self.INDEX, preloaded_metadata=meta
            )
            assert self._w028(result) == [], (status, result.warnings)

        # An unmatched status is still a real finding: the inventory is the
        # only evidence available, so keep warning.
        f = _write_c(
            tmp_path,
            "m_stub.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x1050 */\nint a(void) { return 0; }\n",
                {"SERVER.0x1050": {"kind": "FUNCTION"}},
            ),
        )
        meta = {("SERVER", 0x1050): {"status": "STUB"}}
        result = lint_file(
            f, cfg=_make_cfg(root=tmp_path), function_index=self.INDEX, preloaded_metadata=meta
        )
        assert len(self._w028(result)) == 1

        # PROVEN is not a byte match, so it is no evidence against the inventory.
        meta = {("SERVER", 0x1050): {"status": "PROVEN"}}
        result = lint_file(
            f, cfg=_make_cfg(root=tmp_path), function_index=self.INDEX, preloaded_metadata=meta
        )
        assert len(self._w028(result)) == 1

    def test_annotations_tiling_a_merged_host_are_not_flagged(self, tmp_path: Path) -> None:
        """The host's start is annotated and ends at or before this marker.

        Discovery merged two adjacent annotated functions into one inventory
        entry (guild-rebrew: cm_ExTransferCurrencyNoKill at 0x1000d8a0, 0x90
        bytes, then cm_ExSellObjekt at 0x1000d930).  The annotations tile the
        host's range, so the marker is a real function start whatever its status.
        """
        f = _write_c(
            tmp_path,
            "b.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x1050 */\nint b(void) { return 0; }\n",
                {"SERVER.0x1050": {"kind": "FUNCTION"}},
            ),
        )
        tiled = {
            ("SERVER", 0x1000): {"status": "RELOC", "size": 0x50},
            ("SERVER", 0x1050): {"status": "NEAR_MATCHING", "size": 0xB0},
        }
        result = lint_file(
            f, cfg=_make_cfg(root=tmp_path), function_index=self.INDEX, preloaded_metadata=tiled
        )
        assert self._w028(result) == []

        # A host annotation that runs past the marker does not tile it.
        overlapping = {
            ("SERVER", 0x1000): {"status": "RELOC", "size": 0x60},
            ("SERVER", 0x1050): {"status": "NEAR_MATCHING", "size": 0xB0},
        }
        result = lint_file(
            f,
            cfg=_make_cfg(root=tmp_path),
            function_index=self.INDEX,
            preloaded_metadata=overlapping,
        )
        assert len(self._w028(result)) == 1

    def test_inline_exact_status_suppresses_w028(self, tmp_path: Path) -> None:
        """Inline STATUS (pre-migration) must suppress W028 like metadata.

        Regression: W028 read only the store entry, so an inline
        ``// STATUS: EXACT`` on a byte-matched VA inside another span still
        warned even though the merged found_keys view already claimed EXACT.
        """
        f = _write_c(
            tmp_path,
            "inline_exact.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x1050 */\n\nint a(void) { return 0; }\n",
                {"SERVER.0x1050": {"kind": "FUNCTION", "status": "EXACT"}},
            ),
        )
        result = lint_file(f, cfg=_make_cfg(root=tmp_path), function_index=self.INDEX)
        assert self._w028(result) == [], result.warnings

    def test_library_marker_ignored(self, tmp_path: Path) -> None:
        # LIBRARY markers may point at import stubs the parser filters out.
        f = _write_c(
            tmp_path,
            "l.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x3000 */\nint l(void) { return 0; }\n",
                {"SERVER.0x3000": {"kind": "LIBRARY"}},
            ),
        )
        result = lint_file(f, cfg=_make_cfg(root=tmp_path), function_index=self.INDEX)
        assert self._w028(result) == []

    def test_data_marker_ignored(self, tmp_path: Path) -> None:
        f = _write_c(
            tmp_path,
            "d.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x3000 */\n\nint d = 1;\n",
                {"SERVER.0x3000": {"kind": "DATA", "section": ".rdata"}},
            ),
        )
        result = lint_file(f, cfg=_make_cfg(root=tmp_path), function_index=self.INDEX)
        assert self._w028(result) == []

    def test_other_target_marker_filtered(self, tmp_path: Path) -> None:
        # A shared source carrying a marker for a different target must not
        # be cross-checked against this target's function list.
        f = _write_c(
            tmp_path,
            "s.c",
            SourceFixture(
                "/* ADDRESS: CLIENT 0x3000 */\nint s(void) { return 0; }\n",
                {"CLIENT.0x3000": {"kind": "FUNCTION"}},
            ),
        )
        result = lint_file(
            f, cfg=_make_cfg(marker="SERVER", root=tmp_path), function_index=self.INDEX
        )
        assert self._w028(result) == []

    def test_no_index_silent(self, tmp_path: Path) -> None:
        # No function list (or cfg=None): the check is silent, matching the
        # old doctor SKIP-on-missing-list behavior.
        f = _write_c(
            tmp_path,
            "a.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x3000 */\nint a(void) { return 0; }\n",
                {"SERVER.0x3000": {"kind": "FUNCTION"}},
            ),
        )
        result = lint_file(f, cfg=_make_cfg(root=tmp_path))
        assert self._w028(result) == []

    def test_build_function_index(self, tmp_path: Path) -> None:
        from rebrew.lint import _build_function_index

        cfg = _make_cfg(reversed_dir=tmp_path, root=tmp_path)
        _write_inventory(tmp_path, (0x1000, 256, "func_a"), (0x2000, 128, "func_b"))
        index = _build_function_index(cfg)
        assert index == self.INDEX

    def test_build_function_index_empty_list(self, tmp_path: Path) -> None:
        from rebrew.lint import _build_function_index

        cfg = _make_cfg(reversed_dir=tmp_path / "missing", root=tmp_path)
        assert _build_function_index(cfg) is None


class TestFunctionContainingVa:
    def test_outer_tail_past_a_nested_span_stays_inside(self) -> None:
        from rebrew.lint import _function_containing_va

        spans = [(0x1000, 0x1300, "outer"), (0x1100, 0x1120, "inner")]
        assert _function_containing_va(spans, 0x1200) == (0x1000, 0x1300, "outer")
        assert _function_containing_va(spans, 0x1110) == (0x1100, 0x1120, "inner")
        assert _function_containing_va(spans, 0x1000) is None
        assert _function_containing_va(spans, 0x1400) is None


class TestBuildFunctionIndexVaFloor:
    def test_va_zero_kept_for_16bit(self, tmp_path: Path) -> None:
        """DOS targets address code from segment 0: VA 0 is legitimate
        (min_valid_va_for == 0), so dropping it fired a false W028 on every
        `// FUNCTION: GAME 0x0` annotation."""
        from rebrew.lint import _build_function_index

        cfg = _make_cfg(reversed_dir=tmp_path, root=tmp_path)
        _write_inventory(tmp_path, (0x0, 8, "seg_start"), (0x100, 16, "other"))
        cfg.arch = "x86_16"

        index = _build_function_index(cfg)
        assert index is not None
        starts, spans = index
        assert 0 in starts
        assert [s[2] for s in spans] == ["seg_start", "other"]


class TestW029RedundantCflags:
    """W029: flag settings that only repeat the fallback chain (now in lint)."""

    def _cfg(self, tmp_path: Path, **overrides: object) -> SimpleNamespace:
        base: dict[str, object] = {
            "root": tmp_path,
            "metadata_dir": tmp_path,
            "cflags": "/O2 /Gd",
            "cflags_presets": {},
        }
        base.update(overrides)
        return SimpleNamespace(**base)

    def _redundant(self, cfg: SimpleNamespace) -> tuple[list[Any], list[Any]]:
        from rebrew.lint import check_redundant_cflags

        return check_redundant_cflags(cfg)

    def test_clean_project_passes(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\nstatus = "EXACT"\nsize = 42\n',
            encoding="utf-8",
        )
        presets, fns = self._redundant(self._cfg(tmp_path))
        assert presets == [] and fns == []

    def test_function_override_redundant(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\nstatus = "EXACT"\ncflags = "/O2 /Gd"\n',
            encoding="utf-8",
        )
        _presets, fns = self._redundant(self._cfg(tmp_path))
        assert any(hit.va == 0x1000 for hit in fns)

    def test_flag_order_does_not_matter(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\ncflags = "/Gd /O2"\n',
            encoding="utf-8",
        )
        _presets, fns = self._redundant(self._cfg(tmp_path))
        assert len(fns) == 1

    def test_extra_flags_not_redundant(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\ncflags = "/O2 /Gd /DREBREW_ALLOW_NAKED"\n',
            encoding="utf-8",
        )
        presets, fns = self._redundant(self._cfg(tmp_path))
        assert presets == [] and fns == []

    def test_function_override_matching_module_preset_is_redundant(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["GAME.0x1000"]\ncflags = "/O2 /Gd"\n',
            encoding="utf-8",
        )
        cfg = self._cfg(tmp_path, cflags="/O1 /Gd", cflags_presets={"GAME": "/O2 /Gd"})
        _presets, fns = self._redundant(cfg)
        assert any(hit.module == "GAME" and hit.va == 0x1000 for hit in fns)

    def test_module_preset_redundant_with_project(self, tmp_path: Path) -> None:
        write_store_fixture(tmp_path / "rebrew-functions.toml", "format = 2\n", encoding="utf-8")
        cfg = self._cfg(tmp_path, cflags_presets={"GAME": "/O2 /Gd", "MSVCRT": "/O1"})
        presets, _fns = self._redundant(cfg)
        assert any(hit.module == "GAME" for hit in presets)
        assert not any(hit.module == "MSVCRT" for hit in presets)

    def test_no_metadata_file_passes(self, tmp_path: Path) -> None:
        presets, fns = self._redundant(self._cfg(tmp_path))
        assert presets == [] and fns == []

    def test_w029_appears_in_lint_output(self, tmp_path: Path) -> None:
        """End-to-end: W029 warnings are attributed and counted in lint_file/main."""
        from unittest.mock import patch

        from typer.testing import CliRunner

        from rebrew.lint import app

        src = tmp_path / "reversed"
        src.mkdir()
        write_source(
            src / "foo.c",
            "/* ADDRESS: SERVER 0x1000 */\nint foo(void){return 0;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
            metadata_dir=tmp_path,
        )
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\ncflags = "/O2 /Gd"\n',
            encoding="utf-8",
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=tmp_path,
            source_ext=".c",
            cflags="/O2 /Gd",
            cflags_presets={},
            marker="SERVER",
            library_modules=set(),
        )
        with patch("rebrew.lint.load_config", return_value=cfg):
            result = CliRunner().invoke(app, [])
        assert result.exit_code == 0, result.output
        assert "W029" in result.output
        assert "redundant cflags" in result.output.lower()

    def test_w029_emits_one_batched_print(self, tmp_path: Path) -> None:
        """Work counter: every attributed W029 line rides ONE console.print.

        The per-hit loop used to print each W029 separately (1600 Rich
        calls on a 400-file tree — ~21% of lint's runtime); this pins the
        batching without touching a clock.
        """
        from unittest.mock import patch

        from typer.testing import CliRunner

        import rebrew.lint as lint_mod
        from rebrew.lint import app

        src = tmp_path / "reversed"
        src.mkdir()
        for i, va in enumerate((0x1000, 0x2000)):
            write_source(
                src / f"f{i}.c",
                f"/* ADDRESS: SERVER 0x{va:x} */\nint f{i}(void){{return 0;}}\n",
                encoding="utf-8",
                metadata_fields={f"SERVER.0x{va:x}": {"kind": "FUNCTION"}},
                metadata_dir=tmp_path,
            )
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\ncflags = "/O2 /Gd"\n\n["SERVER.0x2000"]\ncflags = "/O2 /Gd"\n',
            encoding="utf-8",
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=tmp_path,
            source_ext=".c",
            cflags="/O2 /Gd",
            cflags_presets={},
            marker="SERVER",
            library_modules=set(),
        )
        w029_prints: list[str] = []
        orig_print = lint_mod.console.print

        def _spy(*args: object, **kwargs: object) -> object:
            if args and isinstance(args[0], str) and "W029" in args[0]:
                w029_prints.append(args[0])
            return orig_print(*args, **kwargs)

        with (
            patch("rebrew.lint.load_config", return_value=cfg),
            patch.object(lint_mod.console, "print", _spy),
        ):
            result = CliRunner().invoke(app, [])
        assert result.exit_code == 0, result.output
        assert len(w029_prints) == 1, (
            f"expected exactly one batched W029 print, got {len(w029_prints)} — "
            "a per-hit print loop is back"
        )
        assert w029_prints[0].count("W029") == 2, "both files' W029 lines must share the batch"

    def test_passed_never_exceeds_total(self, tmp_path: Path) -> None:
        """The synthetic W029 entries carry no file: counting them as passed
        printed 'Checked 1 files: 2 passed' and a JSON passed > total."""
        import json as json_mod
        from unittest.mock import patch

        from typer.testing import CliRunner

        from rebrew.lint import app

        src = tmp_path / "reversed"
        src.mkdir()
        write_source(
            src / "foo.c",
            "/* ADDRESS: SERVER 0x1000 */\nint foo(void){return 0;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
            metadata_dir=tmp_path,
        )
        write_store_fixture(tmp_path / "rebrew-functions.toml", "format = 2\n", encoding="utf-8")
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=tmp_path,
            source_ext=".c",
            cflags="/O2 /Gd",
            cflags_presets={"SERVER": "/O2 /Gd"},  # redundant preset → synthetic W029 entry
            marker="SERVER",
            library_modules=set(),
            target_name="",
        )
        with patch("rebrew.lint.load_config", return_value=cfg):
            result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 0, result.output
        data = json_mod.loads(result.output)
        assert data["passed"] <= data["total"]

    def _lint_cfg(self, tmp_path: Path, src: Path, **overrides: object) -> SimpleNamespace:
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=tmp_path,
            source_ext=".c",
            cflags="/O2 /Gd",
            cflags_presets={},
            marker="SERVER",
            library_modules=set(),
            target_name="",
        )
        for k, v in overrides.items():
            setattr(cfg, k, v)
        return cfg

    def test_fix_drops_redundant_function_cflags(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.lint import app
        from rebrew.metadata.functions import get_entry

        src = tmp_path / "reversed"
        src.mkdir()
        f = src / "foo.c"
        write_source(
            f,
            "/* ADDRESS: SERVER 0x1000 */\nint foo(void){return 0;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\nstatus = "EXACT"\ncflags = "/O2 /Gd"\nsize = 16\n',
            encoding="utf-8",
        )
        cfg = self._lint_cfg(tmp_path, src)
        monkeypatch.setattr("rebrew.lint.load_config", lambda root=None, **kw: cfg)
        result = CliRunner().invoke(app, ["--fix", str(f)])
        assert result.exit_code == 0, result.output
        assert "dropped" in result.output.lower()
        entry = get_entry(tmp_path, 0x1000, "SERVER")
        assert "cflags" not in entry
        assert entry.get("status") == "EXACT"
        assert entry.get("size") == 16

    def test_fix_dry_run_leaves_redundant_cflags(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.lint import app
        from rebrew.metadata.functions import get_entry

        src = tmp_path / "reversed"
        src.mkdir()
        f = src / "foo.c"
        write_source(
            f,
            "/* ADDRESS: SERVER 0x1000 */\nint foo(void){return 0;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\ncflags = "/O2 /Gd"\n',
            encoding="utf-8",
        )
        cfg = self._lint_cfg(tmp_path, src)
        monkeypatch.setattr("rebrew.lint.load_config", lambda root=None, **kw: cfg)
        result = CliRunner().invoke(app, ["--fix", "--dry-run", str(f)])
        assert result.exit_code == 0, result.output
        assert "Would drop" in result.output
        assert get_entry(tmp_path, 0x1000, "SERVER").get("cflags") == "/O2 /Gd"

    def test_fix_drops_redundant_preset(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.lint import app

        src = tmp_path / "reversed"
        src.mkdir()
        f = src / "foo.c"
        write_source(
            f,
            "/* ADDRESS: SERVER 0x1000 */\nint foo(void){return 0;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\nstatus = "EXACT"\n',
            encoding="utf-8",
        )
        (tmp_path / "rebrew-project.toml").write_text(
            '[compiler]\ncflags = "/O2 /Gd"\n'
            '[compiler.cflags_presets]\nSERVER = "/O2 /Gd"\nMSVCRT = "/O1"\n',
            encoding="utf-8",
        )
        cfg = self._lint_cfg(tmp_path, src, cflags_presets={"SERVER": "/O2 /Gd", "MSVCRT": "/O1"})
        monkeypatch.setattr("rebrew.lint.load_config", lambda root=None, **kw: cfg)
        result = CliRunner().invoke(app, ["--fix", str(f)])
        assert result.exit_code == 0, result.output
        text = (tmp_path / "rebrew-project.toml").read_text(encoding="utf-8")
        assert "SERVER" not in text
        assert "MSVCRT" in text
        assert "/O1" in text

    def test_w016_backfills_section_from_resolver(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.lint import app
        from rebrew.metadata.data import get_data_entry

        src = tmp_path / "reversed"
        src.mkdir()
        f = src / "g.c"
        write_source(
            f,
            "/* ADDRESS: SERVER 0x2000 */\nint g;\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x2000": {"kind": "GLOBAL"}},
        )
        write_store_fixture(tmp_path / "rebrew-functions.toml", "format = 2\n", encoding="utf-8")
        cfg = self._lint_cfg(tmp_path, src)
        (tmp_path / "target.dll").write_bytes(b"MZ")
        cfg.target_binary = tmp_path / "target.dll"
        monkeypatch.setattr("rebrew.lint.load_config", lambda root=None, **kw: cfg)
        from rebrew.formats.binary_model import SectionInfo

        class _Info:
            sections = {".data": SectionInfo(".data", 0x2000, 0x100, 0, 0x100)}

        import rebrew.formats.binary_loader as bl

        monkeypatch.setattr(bl, "load_binary", lambda path: _Info())
        result = CliRunner().invoke(app, ["--fix", str(f)])
        assert result.exit_code == 0, result.output
        assert "backfilled 1 missing SECTION" in result.output
        assert get_data_entry(tmp_path, 0x2000, "SERVER").get("section") == ".data"

    def test_w016_dry_run_leaves_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.lint import app
        from rebrew.metadata.data import get_data_entry

        src = tmp_path / "reversed"
        src.mkdir()
        f = src / "g.c"
        write_source(
            f,
            "/* ADDRESS: SERVER 0x2000 */\nint g;\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x2000": {"kind": "GLOBAL"}},
        )
        write_store_fixture(tmp_path / "rebrew-functions.toml", "format = 2\n", encoding="utf-8")
        cfg = self._lint_cfg(tmp_path, src)
        (tmp_path / "target.dll").write_bytes(b"MZ")
        cfg.target_binary = tmp_path / "target.dll"
        monkeypatch.setattr("rebrew.lint.load_config", lambda root=None, **kw: cfg)
        import rebrew.formats.binary_loader as bl
        from rebrew.formats.binary_model import SectionInfo

        class _Info:
            sections = {".rdata": SectionInfo(".rdata", 0x2000, 0x100, 0, 0x100)}

        monkeypatch.setattr(bl, "load_binary", lambda path: _Info())
        result = CliRunner().invoke(app, ["--fix", "--dry-run", str(f)])
        assert result.exit_code == 0, result.output
        assert "Would set" in result.output
        assert "section" not in get_data_entry(tmp_path, 0x2000, "SERVER")

    def test_fix_strips_metadata_duplicated_cflags(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Inline CFLAGS equal to the store's cflags is stripped in one run.

        Regression: metadata-sourced keys never raised W019, so the dead
        inline copy survived --fix until a later run dropped the store field.
        """
        from typer.testing import CliRunner

        from rebrew.lint import app

        src = tmp_path / "reversed"
        src.mkdir()
        f = src / "foo.c"
        write_source(
            f,
            "\n/* ADDRESS: SERVER 0x1000 */\nint foo(void){return 0;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION", "cflags": "/O2 /Gd"}},
        )
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\nstatus = "EXACT"\ncflags = "/O2 /Gd"\n',
            encoding="utf-8",
        )
        cfg = self._lint_cfg(tmp_path, src)
        monkeypatch.setattr("rebrew.lint.load_config", lambda root=None, **kw: cfg)
        result = CliRunner().invoke(app, ["--fix", str(f)])
        assert result.exit_code == 0, result.output
        assert "CFLAGS" not in f.read_text(encoding="utf-8")
        assert "W019" not in result.output


class TestSupportTu:
    def test_support_blessed(self, tmp_path: Path) -> None:
        from rebrew.metadata.source_provenance import set_source_file

        f = _write_c(tmp_path, "shim.c", "int __cdecl shim(void){return 0;}\n")
        set_source_file(
            tmp_path,
            file="shim.c",
            module="SERVER",
            purpose="linker shims keep LIBCMT sbheap.obj out",
        )
        result = lint_file(f)
        assert result.errors == result.warnings == []
        assert result._marker_counts["SUPPORT"] == 1

    def test_support_for_another_target_has_no_missing_identity(self, tmp_path: Path) -> None:
        from types import SimpleNamespace

        from rebrew.metadata.source_provenance import set_source_file

        f = _write_c(tmp_path, "client.c", "int client(void){return 0;}\n")
        set_source_file(tmp_path, "client.c", "CLIENT", "client-only link helper")
        cfg = SimpleNamespace(metadata_dir=tmp_path, marker="SERVER")
        result = lint_file(f, cfg=cfg)
        assert result.errors == result.warnings == []

    def test_support_without_code_warns(self, tmp_path: Path) -> None:
        from rebrew.metadata.source_provenance import set_source_file

        f = _write_c(tmp_path, "empty.c", "")
        set_source_file(tmp_path, file="empty.c", module="SERVER", purpose="pads .bss")
        result = lint_file(f)
        assert result.errors == []
        assert [c for _, c, _ in result.warnings] == ["W003"]

    def test_markerless_without_support_still_e001(self, tmp_path: Path) -> None:
        result = lint_file(_write_c(tmp_path, "bare.c", "int x;\n"))
        assert [c for _, c, _ in result.errors] == ["E001"]


class TestE004StatusValue:
    def test_unknown_status_flagged(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x10001000"]\nstatus = "TOTALLY_MATCHED"\n',
            encoding="utf-8",
        )
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10001000 */\nint foo(void) { return 0; }\n",
            {"SERVER.0x10001000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "E004" for _, c, _ in result.errors))

    def test_lowercase_inline_status_not_flagged(self, tmp_path: Path) -> None:
        """canonical_status upper-cases, so `exact` is EXACT to test/verify;
        lint must compare canonicalized values, not the raw spelling."""
        f = _make_c_file(
            tmp_path,
            content=(
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\n\nint foo(void) { return 0; }\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 8, "status": "exact"}},
                )
            ),
        )
        result = lint_file(f)
        assert not any(c == "E004" for _, c, _ in result.errors)

    def test_w019_hex_metadata_size_agrees_numerically(self, tmp_path: Path) -> None:
        """E008 accepts `size = "0x20"`, so W019 must compare SIZE numerically:
        a textual compare warned about `// SIZE: 32` vs metadata `0x20`."""
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x10001000"]\nsize = "0x20"\n',
            encoding="utf-8",
        )
        f = _make_c_file(
            tmp_path,
            content=SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n\nint foo(void) { return 0; }\n",
                {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 32}},
            ),
        )
        result = lint_file(f)
        assert not any(c == "W019" and "disagrees" in m for _, c, m in result.warnings)

    def test_known_status_not_flagged(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x10001000"]\nstatus = "EXACT"\n',
            encoding="utf-8",
        )
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10001000 */\nint foo(void) { return 0; }\n",
            {"SERVER.0x10001000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any((c == "E004" for _, c, _ in result.errors))


class TestE008SizeValue:
    def test_non_integer_size_flagged(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x10001000"]\nsize = "abc"\n',
            encoding="utf-8",
        )
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10001000 */\nint foo(void) { return 0; }\n",
            {"SERVER.0x10001000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert any((c == "E008" for _, c, _ in result.errors))

    def test_integer_size_ok(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x10001000"]\nsize = 8\n',
            encoding="utf-8",
        )
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10001000 */\nint foo(void) { return 0; }\n",
            {"SERVER.0x10001000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any((c == "E008" for _, c, _ in result.errors))

    def test_hex_string_size_ok(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x10001000"]\nsize = "0x20"\n',
            encoding="utf-8",
        )
        content = SourceFixture(
            "/* ADDRESS: SERVER 0x10001000 */\nint foo(void) { return 0; }\n",
            {"SERVER.0x10001000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "foo.c", content)
        result = lint_file(f)
        assert not any((c == "E008" for _, c, _ in result.errors))


class TestBlockCommentMarkers:
    def test_block_comment_marker_is_valid(self, tmp_path: Path) -> None:
        """`/* STUB: MAIN 0x1000 */` is the form intake emits for C89-strict
        profiles (borland-2.0/msvc-1.52) and annotation.NEW_FUNC_CAPTURE_RE reads it,
        so lint must not report E001/E002 on it."""
        f = _write_c(
            tmp_path,
            "stub.c",
            SourceFixture(
                "/* ADDRESS: MAIN 0x00401000 */\n\nint f(void) { return 0; }\n",
                {"MAIN.0x00401000": {"kind": "STUB", "size": 16}},
            ),
        )
        result = lint_file(f, cfg=None)
        codes = [code for _, code, _ in result.errors]
        assert "E001" not in codes
        assert "E002" not in codes


class TestMultiExtensionFileFilter:
    def test_explicit_files_match_any_configured_ext(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`source_ext = ".c,.cpp"` must accept a .cpp argument; comparing the
        raw comma-joined string against `f.suffix` checked 0 files and exited 0,
        masking every issue in them."""
        from typer.testing import CliRunner

        from rebrew.lint import app

        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "T"\n\n'
            '[targets.T]\nbinary = "t.exe"\nsource_ext = ".c,.cpp"\n',
            encoding="utf-8",
        )
        src = tmp_path / "src" / "T"
        src.mkdir(parents=True)
        f = src / "bad.cpp"
        write_source(
            f,
            "/* ADDRESS: T 0x00401000 */\nint f(void) { return 0; }\n",
            encoding="utf-8",
            metadata_fields={"T.0x00401000": {"kind": "FUNCTION"}},
        )
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, [str(f)])
        assert "Checked 0 files" not in result.output
        assert "Checked 1 files" in result.output


class TestCommentInteriorIsNotCode:
    def test_commented_out_naked_body_is_not_code(self, tmp_path: Path) -> None:
        """A commented-out naked body must not raise E023/W020: the interior of
        a block comment need not start with `*`, and the old filter only skipped
        lines that did."""
        f = _write_c(
            tmp_path,
            "old.c",
            SourceFixture(
                "\n/* old:\n__declspec(naked) void f(void) {\n    __asm { mov eax, 1 }\n}\n*/\n/* ADDRESS: SERVER 0x1000 */\nint f(void) { return 0; }\n",
                {"SERVER.0x1000": {"kind": "FUNCTION"}},
            ),
        )
        result = lint_file(f, cfg=None)
        assert "E023" not in [code for _, code, _ in result.errors]
        assert "W020" not in [code for _, code, _ in result.warnings]


class TestStackedSharedMarkers:
    """One shared file, one marker per target (ADR-010): no E012."""

    def test_other_target_marker_allowed(self, tmp_path: Path) -> None:
        cfg = _make_cfg(marker="V2", root=tmp_path)
        cfg.all_markers = {"V1", "V2"}
        content = SourceFixture(
            "/* ADDRESS: V1 0x401000 */\n/* ADDRESS: V2 0x501000 */\nint common(void){ return 1; }\n",
            {"V1.0x401000": {"kind": "FUNCTION"}, "V2.0x501000": {"kind": "FUNCTION"}},
        )
        f = _write_c(tmp_path, "common.c", content)
        result = lint_file(f, cfg=cfg)
        assert not any((c == "E012" for _, c, _ in result.errors))

    def test_unknown_module_still_e012(self, tmp_path: Path) -> None:
        cfg = _make_cfg(marker="V2", root=tmp_path)
        cfg.all_markers = {"V1", "V2"}
        f = _write_c(
            tmp_path,
            "bad.c",
            SourceFixture(
                "/* ADDRESS: NOPE 0x401000 */\nint f(void){ return 1; }\n",
                {"NOPE.0x401000": {"kind": "FUNCTION"}},
            ),
        )
        result = lint_file(f, cfg=cfg)
        assert any((c == "E012" for _, c, _ in result.errors))


class TestStripWorkCounter:
    """Deterministic perf gate: one shared strip pass per file.

    E023/W020/W022 read one ``_strip_all`` code view; before, each check
    re-stripped every line (four full passes per file — ~70% of batch-lint
    CPU).  The counter is load-independent, so this holds on busy CI.
    """

    def test_one_strip_call_per_line(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew import lint as lint_mod

        calls = 0
        orig = lint_mod._strip_c_comments_strings

        def counting(line: str, in_block_comment: bool) -> tuple[str, bool]:
            nonlocal calls
            calls += 1
            return orig(line, in_block_comment)

        monkeypatch.setattr(lint_mod, "_strip_c_comments_strings", counting)
        content = SourceFixture(
            "\n\n\nint g_zero = {0};   /* file-scope zero init — W022 */\n\n/* ADDRESS: SERVER 0x10008880 */\nint __cdecl helper(int x)\n{\n    // __declspec(naked) only inside this comment — no E023\n    return x / 2;   // divide\n}\n",
            {"SERVER.0x10008880": {"kind": "FUNCTION", "size": 32, "status": "EXACT"}},
        )
        f = _write_c(tmp_path, "strip_counter.c", content)
        lines = content.splitlines()
        result = lint_file(f, cfg=None)
        assert calls == len(lines), (
            f"expected one strip call per line ({len(lines)}), got {calls} — "
            "a check is re-stripping lines instead of reading the shared view"
        )
        # The shared view keeps the checks correct, not just fast.
        assert any((c == "W022" for _, c, _ in result.warnings))
        assert not any((c == "E023" for _, c, _ in result.errors))


def _reference_strip(line: str, in_block_comment: bool) -> tuple[str, bool]:
    """The original per-character stripper, pinned verbatim as the oracle.

    ``_strip_c_comments_strings`` now jumps between special characters with
    regex ``search`` and copies ordinary runs as slices; this naive loop is
    the behaviour it must match exactly, quirks included (a backslash escape
    inside a literal emits nothing, literal content becomes one space per
    character, ``//`` drops the rest of the line).
    """
    if not in_block_comment and '"' not in line and "'" not in line and "/" not in line:
        return line, False
    out: list[str] = []
    i = 0
    n = len(line)
    in_str = False
    in_char = False
    while i < n:
        c = line[i]
        nxt = line[i + 1] if i + 1 < n else ""
        if in_block_comment:
            if c == "*" and nxt == "/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
            out.append(" ")
            i += 1
            continue
        if in_char:
            if c == "\\":
                i += 2
                continue
            if c == "'":
                in_char = False
            out.append(" ")
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(" ")
            i += 1
            continue
        if c == "'":
            in_char = True
            out.append(" ")
            i += 1
            continue
        if c == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if c == "/" and nxt == "/":
            break  # line comment — rest of the line is not code
        out.append(c)
        i += 1
    return "".join(out), in_block_comment


class TestStripOracle:
    """Differential gate: fast stripper == pinned per-character oracle."""

    def test_edge_cases(self) -> None:
        from rebrew.lint import _strip_c_comments_strings

        lines = [
            "",
            "plain code;",
            "a / b; c++",
            "// whole line /* not a block",
            "x = 1;   // trailing",
            's = "// not a comment"; y',
            "c = '/'; d = '\\'';",
            'str = "a/*b"; /* real */ tail',
            'unterminated "string at eol',
            "unterminated 'c at eol",
            'escape at end "\\\\',
            'escape quote "a\\"b" next',
            "/* block opens here",
            "still in block */ code /* again */ more",
            "char with slash '/' and quote with slash \"//\"",
            "/* inline */ a /* b */ c",
            "#define M(x) ((x) / 2) // divide",
            "L\"wide\" u8'n'",
        ]
        state = False
        for line in lines:
            want_out, want_state = _reference_strip(line, state)
            got_out, got_state = _strip_c_comments_strings(line, state)
            assert (got_out, got_state) == (want_out, want_state), (
                f"line={line!r} state={state}: got {(got_out, got_state)!r}, "
                f"want {(want_out, want_state)!r}"
            )
            state = want_state

    def test_fuzz_matches_oracle(self) -> None:
        import random

        from rebrew.lint import _strip_c_comments_strings

        rng = random.Random(1337)
        pool = [
            "a",
            " ",
            "/*",
            "*/",
            "//",
            '"',
            "'",
            "\\",
            "/",
            "*",
            "0x1F",
            "\\'",
            '\\"',
            '"a',
            "b'",
            "*/c",
            "/*d",
            "//e",
            "'/'",
            '"//"',
            "i++",
            "--",
            "/*f*/",
            "\\\\",
            "{",
            "}",
            ";",
            "g_zero = {0}",
            "'\\''",
            '"\\""',
            "  ",
            "x",
            "//",
            "*/",
        ]
        state = False
        for _ in range(400):
            line = "".join(rng.choice(pool) for _ in range(rng.randrange(0, 12)))
            want = _reference_strip(line, state)
            got = _strip_c_comments_strings(line, state)
            assert got == want, f"line={line!r} state={state}: got {got!r}, want {want!r}"
            state = want[1]


class TestMarkerVaOrder:
    """W030: a file's FUNCTION/STUB markers for one module ascend by VA.

    The linker lays out a translation unit's functions in source order, so a
    function defined above a lower-VA one lands at the wrong address and
    every function between them is displaced.  guild-rebrew lost 2945 linked
    bytes to seven files whose definitions a tree reshuffle had reordered.
    """

    @staticmethod
    def _w030(result: LintResult) -> list[tuple[int, str]]:
        return [(line, m) for line, c, m in result.warnings if c == "W030"]

    @pytest.mark.parametrize("descending", [False, True])
    def test_metadata_only_definition_uses_its_actual_source_line(
        self, tmp_path: Path, descending: bool
    ) -> None:
        """Optional anchors must not move an unanchored definition to the file end."""
        from rebrew.metadata.functions import record_function_identity

        first, second = (0x2000, 0x1000) if descending else (0x1000, 0x2000)
        f = tmp_path / "a.c"
        f.write_text(
            f"int first(void) {{ return 0; }}\n\n/* ADDRESS: SERVER 0x{second:x} */\n"
            "int second(void) { return 0; }\n\n/* ADDRESS: SERVER 0x3000 */\n"
            "int third(void) { return 0; }\n",
            encoding="utf-8",
        )
        for va, name in [(first, "first"), (second, "second"), (0x3000, "third")]:
            record_function_identity(
                tmp_path,
                module="SERVER",
                va=va,
                file="a.c",
                kind="FUNCTION",
                name=name,
                symbol="_" + name,
                size=16,
            )
        warnings = self._w030(lint_file(f, cfg=_make_cfg(root=tmp_path)))
        assert len(warnings) == int(descending)
        if descending:
            assert warnings[0][0] == 3

    def test_descending_marker_warns(self, tmp_path: Path) -> None:
        f = _write_c(
            tmp_path,
            "a.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x2000 */\nint b(void) { return 0; }\n\n/* ADDRESS: SERVER 0x1000 */\nint a(void) { return 0; }\n",
                {"SERVER.0x2000": {"kind": "FUNCTION"}, "SERVER.0x1000": {"kind": "FUNCTION"}},
            ),
        )
        w030 = self._w030(lint_file(f, cfg=_make_cfg(root=tmp_path)))
        assert len(w030) == 1
        assert w030[0][0] == 4
        assert "0x1000" in w030[0][1] and "0x2000" in w030[0][1]

    def test_ascending_and_per_module_silent(self, tmp_path: Path) -> None:
        """Each module is ordered on its own: a twin marker for another build
        carries that build's VA, which need not follow this build's."""
        f = _write_c(
            tmp_path,
            "a.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x1000 */\n/* ADDRESS: OTHER 0x9000 */\nint a(void) { return 0; }\n\n/* ADDRESS: SERVER 0x2000 */\n/* ADDRESS: OTHER 0x8000 */\nint b(void) { return 0; }\n",
                {
                    "SERVER.0x1000": {"kind": "FUNCTION"},
                    "OTHER.0x9000": {"kind": "FUNCTION"},
                    "SERVER.0x2000": {"kind": "FUNCTION"},
                    "OTHER.0x8000": {"kind": "FUNCTION"},
                },
            ),
        )
        result = lint_file(f, cfg=_make_cfg(root=tmp_path))
        assert [w for w in self._w030(result) if "SERVER" in w[1]] == []

    def test_markers_sharing_one_body_are_one_definition(self, tmp_path: Path) -> None:
        """Identical copies at several VAs share one body: their markers stack
        above it in any order, and the group is placed by its lowest VA."""
        f = _write_c(
            tmp_path,
            "a.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x3000 */\n\n/* ADDRESS: SERVER 0x1000 */\nint a(void) { return 0; }\n\n/* ADDRESS: SERVER 0x2000 */\nint b(void) { return 0; }\n",
                {
                    "SERVER.0x3000": {"kind": "FUNCTION", "size": 16},
                    "SERVER.0x1000": {"kind": "FUNCTION"},
                    "SERVER.0x2000": {"kind": "FUNCTION"},
                },
            ),
        )
        w030 = self._w030(lint_file(f, cfg=_make_cfg(root=tmp_path)))
        assert w030 == []


class TestDataSectionNamesMemoConcurrent:
    """The W022 exemption memo is shared, so its two parallel dicts must be
    mutated under one lock.  A racing owner store lands after an eviction
    clear, leaving an OWNER entry with no INDEX entry; the owner hit must
    then rebuild instead of raising KeyError, and every caller must get the
    names of the document it passed in."""

    @staticmethod
    def _entries(prefix: str) -> dict[tuple[str, int], dict[str, Any]]:
        return {
            ("SERVER", 0x1000 + i): {"name": f"{prefix}_g{i}", "section": ".data"} for i in range(4)
        }

    def test_concurrent_lookups_return_their_own_document(self) -> None:
        from concurrent.futures import ThreadPoolExecutor

        from rebrew.lint import _DATA_SECTION_NAMES, _data_section_names_for

        _DATA_SECTION_NAMES.clear()
        docs = [self._entries(f"t{i}") for i in range(8)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(_data_section_names_for, docs * 16))
        for doc, names in zip(docs * 16, results, strict=True):
            assert names == frozenset(e["name"] for e in doc.values())

    def test_missing_index_entry_after_a_racing_clear_rebuilds(self) -> None:
        from rebrew import lint

        entries = self._entries("solo")
        key = id(entries)
        expected = frozenset(e["name"] for e in entries.values())
        assert lint._data_section_names_for(entries) == expected
        # The interleaving an unlocked eviction can produce: the owner store
        # lands after the index clear, so the owner hits with no index entry.
        lint._DATA_SECTION_NAMES.pop(key, None)
        assert lint._data_section_names_for(entries) == expected


class TestW031MetadataStore:
    """W031: the store shapes a reader silently ignores."""

    def test_function_fields_share_the_writer_validation(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\nsize=-1\nstatus="FINISHED"\ncflags=false\nskip=[]\nfile=7\n',
            encoding="utf-8",
        )
        warnings = self._warnings(self._cfg(tmp_path))
        for problem in (
            "size must be non-negative",
            "unknown STATUS",
            "cflags must be",
            "skip must be",
            "file must be a string",
        ):
            assert problem in warnings

    @pytest.mark.parametrize("filename", ["rebrew-functions.toml", "rebrew-data.toml"])
    def test_uppercase_field_is_reported(self, tmp_path: Path, filename: str) -> None:
        (tmp_path / filename).write_text(
            'format = 2\n["SERVER.0x1000"]\nSIZE=4\n', encoding="utf-8"
        )
        assert "field 'SIZE' must use lower-case spelling" in self._warnings(self._cfg(tmp_path))

    @pytest.mark.parametrize("filename", ["rebrew-data.toml", "rebrew-functions.toml"])
    def test_duplicate_identity_is_reported(self, tmp_path: Path, filename: str) -> None:
        (tmp_path / filename).write_text(
            'format = 2\n["SERVER.0x00001000"]\nnote="first"\n["SERVER.0X1000"]\nnote="last"\n',
            encoding="utf-8",
        )
        assert "duplicate metadata keys" in self._warnings(self._cfg(tmp_path))

    def test_data_field_types_share_the_writer_validation(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x1000"]\nsize = 1.5\nname = false\nsection = 7\n',
            encoding="utf-8",
        )
        warnings = self._warnings(self._cfg(tmp_path))
        assert "size must be a non-negative integer" in warnings
        assert "name must be a string" in warnings
        assert "section must be a string" in warnings

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(root=tmp_path, metadata_dir=tmp_path)

    def _warnings(self, cfg: SimpleNamespace) -> str:
        from rebrew.lint import _check_W031_metadata_store

        return "\n".join(m for res in _check_W031_metadata_store(cfg) for _, _, m in res.warnings)

    def test_clean_store_with_stamps_is_silent(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\nstatus = "EXACT"\nupdated_by = "test"\nupdated_at = "2026-01-01T00:00:00+00:00"\n',
            encoding="utf-8",
        )
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x2000"]\nstatus = "DRIFT"\nname = "g"\nupdated_by = "verify"\nupdated_at = "2026-01-01T00:00:00+00:00"\n',
            encoding="utf-8",
        )
        assert self._warnings(self._cfg(tmp_path)) == ""

    def test_unparsable_store_is_reported(self, tmp_path: Path) -> None:
        """A store this check cannot read is a finding, not a clean run.

        Returning early would report success over a file whose W031 findings
        (format stamp, unknown fields, provenance pairs) were never seen.
        """
        write_store_fixture(
            tmp_path / "rebrew-functions.toml", "this is not = = toml\n", encoding="utf-8"
        )
        warnings = self._warnings(self._cfg(tmp_path))
        assert "could not be parsed" in warnings

    def test_unknown_field_is_reported(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x1000"]\nname = "g"\nbogus = 1\n',
            encoding="utf-8",
        )
        assert "unknown field 'bogus'" in self._warnings(self._cfg(tmp_path))

    def test_function_store_unknown_field_is_reported(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\nblocked = "typo"\n',
            encoding="utf-8",
        )
        assert "unknown field 'blocked'" in self._warnings(self._cfg(tmp_path))

    def test_marker_identity_fields_are_known(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\nfile = "a.c"\nsymbol = "_f"\nname = "f"\nkind = "FUNCTION"\n',
            encoding="utf-8",
        )
        assert self._warnings(self._cfg(tmp_path)) == ""

    def test_non_verdict_status_is_reported(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x1000"]\nstatus = "RELOC"\n',
            encoding="utf-8",
        )
        assert "not one of DISPLACED, DRIFT, EXACT, UNCHECKED, VERIFIED" in self._warnings(
            self._cfg(tmp_path)
        )

    def test_half_a_provenance_pair_is_reported(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x1000"]\nstatus = "VERIFIED"\nupdated_by = "verify"\n',
            encoding="utf-8",
        )
        assert "half a provenance pair" in self._warnings(self._cfg(tmp_path))

    def test_unknown_provenance_tag_is_reported(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\nupdated_by = "my-tool"\nupdated_at = "2026-01-01T00:00:00+00:00"\n',
            encoding="utf-8",
        )
        assert "unknown provenance tag 'my-tool'" in self._warnings(self._cfg(tmp_path))

    def test_missing_and_foreign_format_stamps_are_reported(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\nstatus = "STUB"\n',
            encoding="utf-8",
        )
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 7\n\n["SERVER.0x2000"]\nstatus = "DRIFT"\n',
            encoding="utf-8",
        )
        messages = self._warnings(self._cfg(tmp_path))
        assert "format = 7" in messages
        assert "format = 7" in messages

    def test_unknown_top_level_key_is_reported(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\nfmt = 1\n\n["SERVER.0x1000"]\nstatus = "STUB"\n',
            encoding="utf-8",
        )
        assert "top-level 'fmt'" in self._warnings(self._cfg(tmp_path))

    def test_missing_store_is_silent(self, tmp_path: Path) -> None:
        assert self._warnings(self._cfg(tmp_path)) == ""


class TestW036StrayMetadataStoreSingleDir:
    """W036 with one configured directory (no ``shared_dir``/``reversed_dir`` pair)."""

    def _messages(self, tmp_path: Path, metadata_dir: Path) -> str:
        from rebrew.lint import _check_W036_stray_metadata_store

        cfg = SimpleNamespace(
            root=tmp_path,
            metadata_dir=metadata_dir,
            reversed_dir=metadata_dir,
            shared_dir=None,
        )
        return "\n".join(
            m for res in _check_W036_stray_metadata_store(cfg) for _, _, m in res.warnings
        )

    def test_store_in_the_configured_directory_is_silent(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        write_store_fixture(src / "rebrew-data.toml", "format = 1\n", encoding="utf-8")
        write_store_fixture(src / "rebrew-functions.toml", "format = 1\n", encoding="utf-8")
        assert self._messages(tmp_path, src) == ""

    def test_stray_store_is_reported(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        write_store_fixture(src / "rebrew-data.toml", "format = 1\n", encoding="utf-8")
        write_store_fixture(tmp_path / "rebrew-data.toml", "format = 1\n", encoding="utf-8")
        message = self._messages(tmp_path, src)
        assert "outside the configured directory" in message
        assert str(tmp_path) in message

    def test_store_under_an_ignored_directory_is_skipped(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        scratch = tmp_path / ".scratch"
        scratch.mkdir()
        write_store_fixture(scratch / "rebrew-data.toml", "format = 1\n", encoding="utf-8")
        assert self._messages(tmp_path, src) == ""

    def test_other_toml_files_are_not_stores(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (tmp_path / "rebrew-project.toml").write_text("[project]\n", encoding="utf-8")
        assert self._messages(tmp_path, src) == ""


class TestW031Cli:
    """End-to-end: the store checks ride the normal lint report and count."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        src = tmp_path / "reversed"
        src.mkdir(exist_ok=True)
        (tmp_path / "db").mkdir(exist_ok=True)
        return SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=tmp_path,
            source_ext=".c",
            cflags="/O2 /Gd",
            cflags_presets={},
            marker="SERVER",
            library_modules=set(),
            db_dir="db",
            target_name="SERVER",
        )

    def test_store_findings_appear_and_count(self, tmp_path: Path) -> None:
        from unittest.mock import patch

        from typer.testing import CliRunner

        from rebrew.lint import app

        cfg = self._cfg(tmp_path)
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x1000"]\nstatus = "RELOC"\n',
            encoding="utf-8",
        )
        (tmp_path / "db" / "coverage.db").write_bytes(b"SQLite format 3\x00")
        with patch("rebrew.lint.load_config", return_value=cfg):
            result = CliRunner().invoke(app, [])
        assert result.exit_code == 0, result.output
        assert "W031" in result.output
        assert "W032" not in result.output
        # The bare tmp project has no rendered scaffold either (W033).
        assert "W033" in result.output
        # Every store check is a warning, so it never fails the run.
        assert "0 errors" in result.output
        # W031 reports the hand-edited status plus the missing format stamp,
        # W032 the leftover SQLite store, W033 the absent scaffold.
        assert "2 warnings" in result.output

    def test_json_lists_the_offending_artifacts(self, tmp_path: Path) -> None:
        import json
        from unittest.mock import patch

        from typer.testing import CliRunner

        from rebrew.lint import app

        cfg = self._cfg(tmp_path)
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x1000"]\nstatus = "TYPO"\n',
            encoding="utf-8",
        )
        with patch("rebrew.lint.load_config", return_value=cfg):
            result = CliRunner().invoke(app, ["--json"])
        payload = json.loads(result.stdout)
        assert payload["warnings"] >= 1
        files = {entry["file"] for entry in payload["files"]}
        assert "rebrew-data.toml" in files


class TestW033AgentScaffold:
    """W033: the rendered workflow instructions vs the installed rebrew."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(root=tmp_path, target_name="bench")

    def _messages(self, cfg: SimpleNamespace) -> str:
        from rebrew.lint import _check_W033_agent_scaffold

        return "\n".join(m for res in _check_W033_agent_scaffold(cfg) for _, _, m in res.warnings)

    def test_missing_scaffold_is_reported(self, tmp_path: Path) -> None:
        assert "refresh-agents" in self._messages(self._cfg(tmp_path))

    @pytest.mark.parametrize("selected_target", ["bench", "client"])
    def test_fresh_scaffold_is_silent(self, tmp_path: Path, selected_target: str) -> None:
        """A project rendered from the packaged sources passes."""
        from rebrew.init import agent_skill_files

        for rel, data in agent_skill_files("bench").items():
            path = tmp_path / ".agents" / "skills" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        import shutil

        import rebrew

        shutil.copyfile(Path(rebrew.__file__).parent / "PRINCIPLES.md", tmp_path / "PRINCIPLES.md")
        cfg = self._cfg(tmp_path)
        cfg.target_name = selected_target
        cfg.all_targets = ["bench", "client"]
        assert self._messages(cfg) == ""
        victim = tmp_path / ".agents" / "skills" / "rebrew-workflow" / "SKILL.md"
        victim.write_text("old workflow instructions\n", encoding="utf-8")
        assert "rebrew-workflow/SKILL.md" in self._messages(cfg)

    def test_an_edited_skill_file_is_reported(self, tmp_path: Path) -> None:
        from rebrew.init import agent_skill_files

        for rel, data in agent_skill_files("bench").items():
            path = tmp_path / ".agents" / "skills" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        victim = tmp_path / ".agents" / "skills" / "rebrew-workflow" / "SKILL.md"
        victim.write_text("old workflow instructions\n", encoding="utf-8")
        assert "rebrew-workflow/SKILL.md" in self._messages(self._cfg(tmp_path))

    def test_the_render_manifest_is_not_a_skill(self, tmp_path: Path) -> None:
        """`--refresh-agents` writes `.rebrew-scaffold.json` beside the skills;
        reporting it would warn forever on a freshly refreshed project."""
        from rebrew.init import agent_skill_files

        for rel, data in agent_skill_files("bench").items():
            path = tmp_path / ".agents" / "skills" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (tmp_path / ".agents" / "skills" / ".rebrew-scaffold.json").write_text(
            "{}", encoding="utf-8"
        )
        import shutil

        import rebrew

        shutil.copyfile(Path(rebrew.__file__).parent / "PRINCIPLES.md", tmp_path / "PRINCIPLES.md")
        assert self._messages(self._cfg(tmp_path)) == ""

    def test_a_pruned_skill_is_reported(self, tmp_path: Path) -> None:
        from rebrew.init import agent_skill_files

        for rel, data in agent_skill_files("bench").items():
            path = tmp_path / ".agents" / "skills" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        ghost = tmp_path / ".agents" / "skills" / "rebrew-retired" / "SKILL.md"
        ghost.parent.mkdir(parents=True)
        ghost.write_text("# retired\n", encoding="utf-8")
        assert "rebrew-retired/SKILL.md" in self._messages(self._cfg(tmp_path))


class TestW034IdentityPaths:
    """W034: a stored `file` a consumer must not join onto the project."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(metadata_dir=tmp_path, root=tmp_path)

    def _warnings(self, cfg: SimpleNamespace) -> str:
        from rebrew.lint import _check_W034_identity_paths

        return "\n".join(m for res in _check_W034_identity_paths(cfg) for _, _, m in res.warnings)

    def test_relative_path_is_silent(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\nfile = "src/a.c"\n',
            encoding="utf-8",
        )
        assert self._warnings(self._cfg(tmp_path)) == ""

    def test_absolute_path_is_reported(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\nfile = "/etc/passwd"\n',
            encoding="utf-8",
        )
        assert "must be relative to the project" in self._warnings(self._cfg(tmp_path))

    def test_parent_escape_is_reported(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\nfile = "../../secret.c"\n',
            encoding="utf-8",
        )
        assert "must not escape the project" in self._warnings(self._cfg(tmp_path))

    def test_absolute_path_in_the_data_store_is_reported(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x1000"]\nfile = "/etc/passwd"\n',
            encoding="utf-8",
        )
        assert "must be relative to the project" in self._warnings(self._cfg(tmp_path))

    def test_relative_data_path_is_silent(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x1000"]\nfile = "src/SERVER/a.c"\n',
            encoding="utf-8",
        )
        assert self._warnings(self._cfg(tmp_path)) == ""


class TestW035UnknownModules:
    """W035: rows for a target this project no longer declares."""

    def _cfg(self, tmp_path: Path, **overrides: object) -> SimpleNamespace:
        base: dict[str, object] = {
            "metadata_dir": tmp_path,
            "root": tmp_path,
            "marker": "SERVER",
            "all_markers": ["SERVER"],
            "library_modules": [],
        }
        base.update(overrides)
        return SimpleNamespace(**base)

    def _warnings(self, cfg: SimpleNamespace) -> str:
        from rebrew.lint import _check_W035_unknown_modules

        return "\n".join(m for res in _check_W035_unknown_modules(cfg) for _, _, m in res.warnings)

    def test_declared_modules_are_silent(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["SERVER.0x1000"]\nstatus = "STUB"\n\n["MSVCRT.0x2000"]\nstatus = "EXACT"\n',
            encoding="utf-8",
        )
        assert self._warnings(self._cfg(tmp_path, library_modules=["MSVCRT"])) == ""

    def test_an_unknown_module_is_reported(self, tmp_path: Path) -> None:
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["CLIENT.0x1000"]\nstatus = "STUB"\n',
            encoding="utf-8",
        )
        assert "matches no target marker" in self._warnings(self._cfg(tmp_path))

    def test_module_another_target_links_is_silent(self, tmp_path: Path) -> None:
        """D3DX8 rows are read while server.dll is the default target, but only
        the TL client links d3dx8.lib. Every target's external libraries are
        known, not just the active one's library_modules."""
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["D3DX8.0x45d3f0"]\nstatus = "EXACT"\n',
            encoding="utf-8",
        )
        cfg = self._cfg(tmp_path, all_library_modules=["D3DX8"])
        assert self._warnings(cfg) == ""
        # Without the cross-target view it would still be flagged.
        assert "matches no target marker" in self._warnings(self._cfg(tmp_path))


class TestW036StrayMetadataStore:
    """W036: a store copy outside the directories the readers resolve."""

    def _warnings(self, tmp_path: Path, **overrides: object) -> str:
        from rebrew.lint import _check_W036_stray_metadata_store

        cfg = SimpleNamespace(
            root=tmp_path,
            **{"metadata_dir": tmp_path, "reversed_dir": tmp_path, **overrides},
        )
        return "\n".join(
            m for res in _check_W036_stray_metadata_store(cfg) for _, _, m in res.warnings
        )

    def test_the_configured_store_is_silent(self, tmp_path: Path) -> None:
        write_store_fixture(tmp_path / "rebrew-data.toml", "format = 1\n", encoding="utf-8")
        assert self._warnings(tmp_path) == ""

    def test_a_copy_elsewhere_is_reported(self, tmp_path: Path) -> None:
        stray = tmp_path / "src"
        stray.mkdir()
        write_store_fixture(stray / "rebrew-data.toml", "format = 1\n", encoding="utf-8")
        write_store_fixture(stray / "rebrew-functions.toml", "format = 1\n", encoding="utf-8")
        messages = self._warnings(tmp_path)
        assert "outside the configured directory" in messages
        assert messages.count("outside the configured directory") == 2

    def test_the_alternate_store_dirs_are_silent(self, tmp_path: Path) -> None:
        """`shared_dir` and `reversed_dir` hold stores the loaders also read."""
        for name in ("reversed", "shared"):
            (tmp_path / name).mkdir()
            write_store_fixture(
                tmp_path / name / "rebrew-data.toml", "format = 1\n", encoding="utf-8"
            )
        cfg = SimpleNamespace(
            root=tmp_path,
            metadata_dir=tmp_path / "reversed",
            reversed_dir=tmp_path / "reversed",
            shared_dir=tmp_path / "shared",
        )
        from rebrew.lint import _check_W036_stray_metadata_store

        assert _check_W036_stray_metadata_store(cfg) == []

    def test_a_skipped_tree_is_not_walked(self, tmp_path: Path) -> None:
        build = tmp_path / "build"
        build.mkdir()
        write_store_fixture(build / "rebrew-data.toml", "format = 1\n", encoding="utf-8")
        assert self._warnings(tmp_path) == ""

    def test_a_store_in_the_configured_directory_is_silent(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        write_store_fixture(src / "rebrew-data.toml", "format = 1\n", encoding="utf-8")
        write_store_fixture(src / "rebrew-functions.toml", "format = 1\n", encoding="utf-8")
        assert self._warnings(tmp_path, metadata_dir=src, reversed_dir=src) == ""

    def test_a_stray_store_names_its_directory(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        write_store_fixture(src / "rebrew-data.toml", "format = 1\n", encoding="utf-8")
        write_store_fixture(tmp_path / "rebrew-data.toml", "format = 1\n", encoding="utf-8")
        message = self._warnings(tmp_path, metadata_dir=src, reversed_dir=src)
        assert "outside the configured directory" in message
        assert str(tmp_path) in message

    def test_a_store_under_an_ignored_directory_is_skipped(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        scratch = tmp_path / ".scratch"
        scratch.mkdir()
        write_store_fixture(scratch / "rebrew-data.toml", "format = 1\n", encoding="utf-8")
        assert self._warnings(tmp_path, metadata_dir=src, reversed_dir=src) == ""

    def test_other_toml_files_are_not_stores(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (tmp_path / "rebrew-project.toml").write_text("[project]\n", encoding="utf-8")
        assert self._warnings(tmp_path, metadata_dir=src, reversed_dir=src) == ""


@pytest.mark.parametrize("metadata_in_src", [False, True])
def test_markerless_library_binding_uses_project_root(
    tmp_path: Path, metadata_in_src: bool
) -> None:
    """A migrated bound library body is annotated even with a separate metadata root."""
    from types import SimpleNamespace

    from rebrew.lint import lint_file

    src = tmp_path / "src"
    src.mkdir()
    metadata = src if metadata_in_src else tmp_path
    provider = src / "provider.c"
    provider.write_text("int provider(void) { return 0; }\n")
    cfg = SimpleNamespace(root=tmp_path, metadata_dir=metadata, marker="S", all_markers={"S"})
    entries = {
        ("S", 0x401000): {
            "file": "src/provider.c",
            "kind": "LIBRARY",
            "name": "provider",
            "symbol": "_provider",
        }
    }
    result = lint_file(provider, cfg=cfg, preloaded_metadata=entries, preloaded_data_metadata={})
    assert not any(code == "E001" for _, code, _ in result.errors)
    unrelated = tmp_path / "other" / "provider.c"
    unrelated.parent.mkdir()
    unrelated.write_text(provider.read_text())
    result = lint_file(unrelated, cfg=cfg, preloaded_metadata=entries, preloaded_data_metadata={})
    assert any(code == "E001" for _, code, _ in result.errors)


class TestW037W038DataRows:
    """W037: a data row that disagrees with its owning definition. W038: rows
    whose extents overlap. Driven through ``rebrew lint --json`` on a real
    project file, the way guild-rebrew hit it: a generator shrank
    ``g_gap_10034644`` to 36 bytes while its row still said ``char[44]``, so
    the stale row ran over the next two globals."""

    def _project(self, tmp_path: Path, source: str, rows: str) -> Path:
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "server.dll"\n\n'
            '[targets."server.dll"]\nbinary = "server.dll"\nmarker = "SERVER"\n'
            'reversed_dir = "src"\n',
            encoding="utf-8",
        )
        src = tmp_path / "src"
        src.mkdir()
        owner = src / "bss_head2.c"
        write_source(owner, source, encoding="utf-8")
        write_store_fixture(tmp_path / "rebrew-data.toml", "format = 2\n" + rows, encoding="utf-8")
        return owner

    def _row(self, va: int, name: str, type_: str, size: int, **extra: str) -> str:
        fields = "".join(f'{key} = "{value}"\n' for key, value in extra.items())
        return f'\n["SERVER.0x{va:08x}"]\nfile = "src/bss_head2.c"\nkind = "GLOBAL"\nname = "{name}"\ntype = "{type_}"\nsize = {size}\nsection = ".bss"\n{fields}'

    def _lint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> list[tuple[str, int, str, str]]:
        from typer.testing import CliRunner

        from rebrew.lint import app

        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["--json"])
        payload = json.loads(result.stdout)
        return [
            (entry["file"], warning["line"], warning["code"], warning["message"])
            for entry in payload["files"]
            for warning in entry["warnings"]
            if warning["code"] in {"W037", "W038"}
        ]

    def test_stale_row_size_is_reported_with_the_fix(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._project(
            tmp_path,
            "/* layout */\nchar g_gap_10034644[36] = {0};\nvoid *g_vfs_root;\n",
            self._row(0x10034644, "g_gap_10034644", "char[44]", 44)
            + self._row(0x10034668, "g_vfs_root", "void*", 4),
        )
        found = [w for w in self._lint(tmp_path, monkeypatch) if w[2] == "W037"]
        assert len(found) == 1, found
        file, line, _code, message = found[0]
        assert file.endswith("bss_head2.c")
        assert line == 2
        assert "SERVER.0x10034644" in message
        assert "type 'char[44]' (44 bytes), size 44" in message
        assert "'char[36]' (36 bytes)" in message
        assert "rebrew data set --size 0x10034644=36" in message
        assert "rebrew data set --type '0x10034644=char[36]'" in message

    def test_matching_rows_are_silent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Spelling differences (`void*` / `void *`, `[0x104]` / `[260]`) are
        not a disagreement: only byte sizes are compared."""
        self._project(
            tmp_path,
            "char g_gap[36] = {0};\nvoid * g_root;\nunsigned  short g_w;\nchar g_path[0x104];\n",
            self._row(0x1000, "g_gap", "char[36]", 36)
            + self._row(0x1024, "g_root", "void*", 4)
            + self._row(0x1028, "g_w", "unsigned short", 2)
            + self._row(0x102C, "g_path", "char[260]", 260),
        )
        assert self._lint(tmp_path, monkeypatch) == []

    def test_extern_declaration_is_not_the_definition(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Only the definition is compared: an extern of another extent in the
        owning file is a user, and a file with only the extern is skipped."""
        self._project(
            tmp_path,
            "extern char g_a[];\nchar g_a[8];\nextern int g_b[4];\n",
            self._row(0x1000, "g_a", "char[8]", 8) + self._row(0x1008, "g_b", "char[3]", 3),
        )
        assert self._lint(tmp_path, monkeypatch) == []

    def test_unsized_types_are_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A struct the size model cannot measure is skipped, not guessed."""
        self._project(
            tmp_path,
            "struct Pool { int a; };\nstruct Pool g_pool;\n",
            self._row(0x1000, "g_pool", "struct Pool", 12),
        )
        assert self._lint(tmp_path, monkeypatch) == []

    def test_overlapping_rows_are_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._project(
            tmp_path,
            "char g_gap[44];\nvoid *g_root;\n",
            self._row(0x1000, "g_gap", "char[44]", 44) + self._row(0x1024, "g_root", "void*", 4),
        )
        found = [w for w in self._lint(tmp_path, monkeypatch) if w[2] == "W038"]
        assert len(found) == 1, found
        file, _line, _code, message = found[0]
        assert file == "rebrew-data.toml"
        assert "SERVER.0x00001000 g_gap" in message
        assert "SERVER.0x00001024 g_root" in message
        assert "by 4 bytes" in message

    def test_views_and_disjoint_rows_do_not_overlap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An alias with a backing is a view of its allocation, not a second
        owner; adjacent rows touch without intersecting."""
        self._project(
            tmp_path,
            "char g_buf[16];\nint g_next;\n",
            self._row(0x1000, "g_buf", "char[16]", 16)
            + self._row(0x1004, "g_buf_tail", "char[4]", 4, storage_kind="alias", backing="g_buf")
            + self._row(0x1010, "g_next", "int", 4),
        )
        assert self._lint(tmp_path, monkeypatch) == []

    def test_span_row_is_compared_with_its_extern_view(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A span has no standalone owner: its owning file may hold only an
        extern inventory view, and that view's extent is what the row must
        match (guild-rebrew `g_before_g_array_count`, declared 7 bytes against
        a 3-byte span). A non-span row with only an extern stays skipped."""
        self._project(
            tmp_path,
            "extern unsigned char g_before[0x7];\nextern unsigned char g_other[0x7];\n",
            self._row(0x1000, "g_before", "unsigned char[3]", 3, storage_kind="span")
            + self._row(0x1010, "g_other", "unsigned char[3]", 3, storage_kind="object"),
        )
        found = [w for w in self._lint(tmp_path, monkeypatch) if w[2] == "W037"]
        assert len(found) == 1, found
        message = found[0][3]
        assert "g_before" in message
        assert "span view" in message
        assert "'unsigned char[0x7]' (7 bytes)" in message
        assert "--size 0x00001000=7" in message

    def test_stale_type_alone_gets_the_type_fix(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._project(
            tmp_path,
            "char g_gap[36];\n",
            self._row(0x1000, "g_gap", "char[44]", 36),
        )
        found = [w for w in self._lint(tmp_path, monkeypatch) if w[2] == "W037"]
        assert len(found) == 1, found
        message = found[0][3]
        assert "rebrew data set --type '0x00001000=char[36]'" in message
        assert "--size" not in message

    def _view(self, va: int, name: str, type_: str, size: int, backing: str) -> str:
        return self._row(va, name, type_, size, storage_kind="alias", backing=backing)

    def test_tiled_allocation_is_silent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """guild-rebrew `g_slot_table`: the row keeps the reference allocation's
        full extent while the source splits it into a short leading definition
        and separate definitions for its interior names and pads, each an alias
        row backed by the allocation. Covering the extent exactly is a match."""
        self._project(
            tmp_path,
            "unsigned char g_tab[2] = {0};\nshort g_field = 0;\nchar g_gap_4[12] = {0};\n"
            "extern int g_peek;\nint g_next;\n",
            self._row(0x1000, "g_tab", "unsigned char[16]", 16)
            + self._view(0x1002, "g_field", "char[2]", 2, "g_tab")
            + self._view(0x1004, "g_gap_4", "char[12]", 12, "g_tab")
            + self._view(0x1008, "g_peek", "int", 4, "g_tab")
            + self._row(0x1010, "g_next", "int", 4),
        )
        assert self._lint(tmp_path, monkeypatch) == []

    def test_tiling_with_a_hole_names_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A missing piece leaves bytes of the allocation no definition owns."""
        self._project(
            tmp_path,
            "unsigned char g_tab[2] = {0};\nchar g_gap_8[8] = {0};\n",
            self._row(0x1000, "g_tab", "unsigned char[16]", 16)
            + self._view(0x1008, "g_gap_8", "char[8]", 8, "g_tab"),
        )
        found = [w for w in self._lint(tmp_path, monkeypatch) if w[2] == "W037"]
        assert len(found) == 1, found
        message = found[0][3]
        assert "tiled" in message
        assert "[0x00001002, 0x00001008)" in message
        assert "--size" not in message

    def test_tiling_that_overruns_the_row_reports_its_extent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._project(
            tmp_path,
            "unsigned char g_tab[2] = {0};\nchar g_gap_2[20] = {0};\n",
            self._row(0x1000, "g_tab", "unsigned char[16]", 16)
            + self._view(0x1002, "g_gap_2", "char[20]", 20, "g_tab"),
        )
        found = [w for w in self._lint(tmp_path, monkeypatch) if w[2] == "W037"]
        assert len(found) == 1, found
        message = found[0][3]
        assert "tiled" in message
        assert "22 bytes" in message
        assert "rebrew data set --size 0x00001000=22" in message


class TestUnregisteredDuplicateAddresses:
    def test_duplicate_anchors_keep_the_duplicate_diagnostic(self, tmp_path: Path) -> None:
        first = tmp_path / "first.c"
        second = tmp_path / "second.c"
        for path in [first, second]:
            path.write_text("/* ADDRESS: SERVER 0x10008880 */\nint f(void) { return 1; }\n")
        seen: dict[int, str] = {}
        lint_file(first, seen_vas=seen)
        result = lint_file(second, seen_vas=seen)
        assert any(code == "E013" for _, code, _ in result.errors)
