#!/usr/bin/env python3

import argparse
import functools
import gzip
import json
import platform
import re
import sqlite3
import subprocess
import sys
import threading
import webbrowser
import gzip
import functools
from pathlib import Path
from urllib.parse import urlparse
import importlib.util

from typing import Any, cast
import bottle  # type: ignore

Bottle = cast(Any, bottle.Bottle)
request = cast(Any, bottle.request)
response = cast(Any, bottle.response)
static_file = cast(Any, bottle.static_file)
HTTPResponse = cast(Any, bottle.HTTPResponse)

HAS_CAPSTONE = importlib.util.find_spec("capstone") is not None


try:
    import rjsmin  # type: ignore
    import rcssmin  # type: ignore

    HAS_MINIFIERS = True
except ImportError:
    HAS_MINIFIERS = False

try:
    import brotli  # type: ignore

    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False

try:
    import zstandard as zstd  # type: ignore

    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False


def repo_root() -> Path:
    """Find the project root by searching for rebrew.toml from cwd upward."""
    p = Path.cwd().resolve()
    while True:
        if (p / "rebrew.toml").exists():
            return p
        parent = p.parent
        if parent == p:
            break
        p = parent
    # Fallback: parent of this file (for when running from rebrew repo itself)
    return Path(__file__).resolve().parents[1]


def ui_dir() -> Path:
    """Return the directory containing recoverage UI files (HTML/CSS/JS).
    These live alongside this script in the rebrew package."""
    return Path(__file__).resolve().parent


# ── DLL loading & disassembly ──────────────────────────────────────

DLL_DATA: dict[str, bytes | None] = {}
DLL_LOCK = threading.Lock()


def _load_dll(target: str) -> bytes | None:
    """Load DLL bytes for a target into DLL_DATA (thread-safe, double-checked)."""
    if target in DLL_DATA:
        return DLL_DATA[target]
    with DLL_LOCK:
        if target in DLL_DATA:
            return DLL_DATA[target]
        try:
            import yaml  # type: ignore

            yml_path = repo_root() / "reccmp-project.yml"
            with open(yml_path, "r") as f:
                project_config = yaml.safe_load(f)
            targets = project_config.get("targets", {})
            target_info = targets.get(target, targets.get("SERVER", {}))
            dll_path = repo_root() / target_info.get(
                "filename", "original/Server/server.dll"
            )
        except Exception:
            dll_path = repo_root() / "original" / "Server" / "server.dll"

        try:
            with open(dll_path, "rb") as f:
                DLL_DATA[target] = f.read()
        except FileNotFoundError:
            DLL_DATA[target] = None
    return DLL_DATA[target]


@functools.lru_cache(maxsize=2048)
def get_disassembly(
    va: int, size: int, file_offset: int, target: str = "SERVER"
) -> str:
    target_data = _load_dll(target)
    if target_data is None:
        return ""

    # Pyre2 does not correctly support slice overloads for bytes/memoryview yet
    code_bytes = target_data[file_offset : file_offset + size]  # type: ignore
    if len(code_bytes) < size:
        return ""

    import capstone as _capstone  # type: ignore # noqa: PLC0415

    md = _capstone.Cs(_capstone.CS_ARCH_X86, _capstone.CS_MODE_32)
    md.detail = False

    asm_lines = []
    for insn in md.disasm(code_bytes, va):
        asm_lines.append(f"0x{insn.address:08x}  {insn.mnemonic:8s} {insn.op_str}")

    return "\n".join(asm_lines) if asm_lines else "  (no instructions)"


# ── Minification ───────────────────────────────────────────────────


def minify_css(css: str) -> str:
    if HAS_MINIFIERS:
        return rcssmin.cssmin(css)  # type: ignore
    css = re.sub(r"/\*[\s\S]*?\*/", "", css)
    css = re.sub(r"\s+", " ", css)
    css = re.sub(r"\s*([{}:;,])\s*", r"\1", css)
    return css.strip()


def minify_js(js: str) -> str:
    if HAS_MINIFIERS:
        return rjsmin.jsmin(js)  # type: ignore
    js = re.sub(r"^\s*//.*$", "", js, flags=re.MULTILINE)
    js = re.sub(r"/\*[\s\S]*?\*/", "", js)
    lines = [line.strip() for line in js.split("\n")]
    return "\n".join(line for line in lines if line)


# ── Compression ────────────────────────────────────────────────────


def compress_payload(body: bytes, accept_encoding: str) -> tuple[bytes, str]:
    """Compress payload using the best available algorithm."""
    if HAS_ZSTD and "zstd" in accept_encoding:
        cctx = zstd.ZstdCompressor(level=3)  # type: ignore
        return cctx.compress(body), "zstd"
    if HAS_BROTLI and "br" in accept_encoding:
        return brotli.compress(body), "br"  # type: ignore
    if "gzip" in accept_encoding:
        return gzip.compress(body), "gzip"
    return body, ""


# ── Index caching ──────────────────────────────────────────────────

CACHED_INDEX_PAYLOAD: bytes | None = None
CACHED_INDEX_COMPRESSED: dict[str, bytes] = {}
INDEX_LOCK = threading.Lock()

# ── SQL fragments ──────────────────────────────────────────────────

_FN_JSON_SQL = (
    "json_object("
    "'va', va, 'name', name, 'vaStart', vaStart, 'size', size, "
    "'fileOffset', fileOffset, 'status', status, 'origin', origin, "
    "'cflags', cflags, 'symbol', symbol, 'markerType', markerType, "
    "'ghidra_name', ghidra_name, 'r2_name', r2_name, "
    "'is_thunk', is_thunk, 'is_export', is_export, 'sha256', sha256, "
    "'files', json(files)"
    ")"
)

_GLOBAL_JSON_SQL = (
    "json_object("
    "'va', va, 'name', name, 'decl', decl, "
    "'files', json(files), 'isGlobal', 1"
    ")"
)


def _open_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _db() -> sqlite3.Connection:
    return _open_db(ui_dir() / "coverage.db")


# ── Response helpers ───────────────────────────────────────────────


def _compressed(body: bytes, content_type: str, **headers: str) -> bytes:
    """Compress body, set response headers, return final body."""
    accept_enc = request.headers.get("Accept-Encoding", "")
    body, encoding = compress_payload(body, accept_enc)
    response.content_type = content_type
    if encoding:
        response.set_header("Content-Encoding", encoding)
    response.set_header("Content-Length", str(len(body)))
    for k, v in headers.items():
        response.set_header(k.replace("_", "-"), v)
    return body


def _json_ok(data, **headers: str) -> bytes:
    """Return compressed JSON 200."""
    body = json.dumps(data).encode("utf-8") if isinstance(data, dict) else data
    return _compressed(body, "application/json", **headers)


def _json_err(status: int, data: dict) -> Any:
    """Return a JSON error response."""
    body = json.dumps(data).encode("utf-8")
    accept_enc = request.headers.get("Accept-Encoding", "")
    body, encoding = compress_payload(body, accept_enc)
    resp = HTTPResponse(status=status, body=body)
    resp.content_type = "application/json"
    if encoding:
        resp.set_header("Content-Encoding", encoding)
    resp.set_header("Content-Length", str(len(body)))
    return resp


# ── Bottle app ─────────────────────────────────────────────────────

app = Bottle()


@app.get("/potato")
def handle_potato():
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from potato import render_potato  # type: ignore

        parsed = urlparse(request.url)
        body = render_potato(parsed).encode("utf-8")
        return _compressed(body, "text/html; charset=utf-8")
    except Exception as e:
        return HTTPResponse(status=500, body=f"Error: {e}")


@app.get("/")
@app.get("/index.html")
def handle_index():
    global CACHED_INDEX_PAYLOAD, CACHED_INDEX_COMPRESSED
    accept_encoding = request.headers.get("Accept-Encoding", "")

    with INDEX_LOCK:
        if CACHED_INDEX_PAYLOAD is None:
            _ui_dir = ui_dir()
            html = (_ui_dir / "index.html").read_text(encoding="utf-8")
            css = (_ui_dir / "style.css").read_text(encoding="utf-8")
            js = (_ui_dir / "app.js").read_text(encoding="utf-8")
            try:
                vanjs = (_ui_dir / "van.min.js").read_text(encoding="utf-8")
            except FileNotFoundError:
                vanjs = ""

            html = html.replace(
                "<!-- INJECT_CSS -->", f"<style>{minify_css(css)}</style>"
            )
            html = html.replace(
                "<!-- INJECT_JS -->",
                f"<script>{vanjs}\n{minify_js(js)}</script>",
            )
            CACHED_INDEX_PAYLOAD = html.encode("utf-8")
            CACHED_INDEX_COMPRESSED.clear()

    _, encoding = compress_payload(b"", accept_encoding)
    with INDEX_LOCK:
        if encoding not in CACHED_INDEX_COMPRESSED:
            compressed, _ = compress_payload(CACHED_INDEX_PAYLOAD, accept_encoding)
            CACHED_INDEX_COMPRESSED[encoding] = compressed
        body = CACHED_INDEX_COMPRESSED[encoding]

    response.content_type = "text/html; charset=utf-8"
    response.set_header("Cache-Control", "no-cache, no-store, must-revalidate")
    if encoding:
        response.set_header("Content-Encoding", encoding)
    response.set_header("Content-Length", str(len(body)))
    return body


@app.get("/api/targets")
def handle_api_targets():
    try:
        conn = _db()
        c = conn.cursor()
        c.execute("SELECT DISTINCT target FROM metadata")
        target_ids = [row[0] for row in c.fetchall()]
        conn.close()
    except sqlite3.OperationalError:
        target_ids = ["SERVER"]

    targets_info: dict[str, Any] = {}
    try:
        import yaml  # type: ignore

        yml_path = repo_root() / "reccmp-project.yml"
        with open(yml_path, "r") as f:
            doc = yaml.safe_load(f)
            if isinstance(doc, dict):
                t = doc.get("targets")
                if isinstance(t, dict):
                    targets_info.update(t)
    except Exception:
        pass

    targets_list = []
    for tid in target_ids:
        filename = tid
        t_info = targets_info.get(tid)
        if isinstance(t_info, dict) and "filename" in t_info:
            filename = Path(t_info["filename"]).name
        targets_list.append({"id": tid, "name": filename})

    return _json_ok(
        {"targets": targets_list},
        Cache_Control="no-cache, no-store, must-revalidate",
    )


@app.get("/api/data")
def handle_api_data():
    target = request.query.get("target", "SERVER")
    db_path = ui_dir() / "coverage.db"

    # ETag caching based on DB modification time + target
    etag = None
    try:
        mtime = db_path.stat().st_mtime
        etag = f'"{mtime}-{target}"'
        if request.headers.get("If-None-Match") == etag:
            return HTTPResponse(status=304)
    except FileNotFoundError:
        pass

    try:
        conn = _db()
    except sqlite3.OperationalError as e:
        return _json_err(503, {"error": str(e)})

    c = conn.cursor()
    data: dict = {}

    c.execute("SELECT key, value FROM metadata WHERE target = ?", (target,))
    for row in c.fetchall():
        try:
            data[row["key"]] = json.loads(row["value"])
        except (json.JSONDecodeError, TypeError):
            data[row["key"]] = row["value"]

    c.execute("SELECT * FROM sections WHERE target = ?", (target,))
    data["sections"] = {}
    for row in c.fetchall():
        sec = dict(row)
        sec["cells"] = []
        data["sections"][sec["name"]] = sec

    c.execute(
        "SELECT section_name, json_group_array(json_object("
        "'id', id, 'start', start, 'end', end, 'span', span, "
        "'state', state, 'functions', json(functions)"
        ")) FROM cells WHERE target = ? GROUP BY section_name",
        (target,),
    )
    for row in c.fetchall():
        sec_name = row[0]
        if sec_name in data["sections"]:
            data["sections"][sec_name]["cells"] = json.loads(row[1])

    # Lightweight search index
    data["search_index"] = {}
    c.execute(
        "SELECT name, vaStart, symbol FROM functions WHERE target = ?",
        (target,),
    )
    for row in c.fetchall():
        data["search_index"][row["name"]] = {
            "va": row["vaStart"],
            "symbol": row["symbol"],
        }
    c.execute("SELECT name, va FROM globals WHERE target = ?", (target,))
    for row in c.fetchall():
        data["search_index"][row["name"]] = {
            "va": hex(row["va"]) if row["va"] else "",
            "symbol": "",
        }

    # Per-section cell stats from SQL view
    data["section_cell_stats"] = {}
    c.execute(
        "SELECT section_name, total_cells, exact_count, reloc_count, "
        "matching_count, stub_count FROM section_cell_stats WHERE target = ?",
        (target,),
    )
    for row in c.fetchall():
        data["section_cell_stats"][row["section_name"]] = {
            "total": row["total_cells"],
            "exact": row["exact_count"],
            "reloc": row["reloc_count"],
            "matching": row["matching_count"],
            "stub": row["stub_count"],
        }

    conn.close()
    if etag is not None:
        return _json_ok(data, Cache_Control="no-cache, must-revalidate", ETag=str(etag))
    return _json_ok(data, Cache_Control="no-cache, must-revalidate")


@app.get("/api/function")
def handle_api_function():
    va = request.query.get("va")
    target = request.query.get("target", "SERVER")
    if not va:
        return _json_err(400, {"error": "missing va"})

    try:
        conn = _db()
    except sqlite3.OperationalError as e:
        return _json_err(503, {"error": str(e)})

    c = conn.cursor()
    no_cache = "no-cache, no-store, must-revalidate"

    # Try functions first (by va int or name string)
    try:
        va_int = int(va, 0)
        c.execute(
            f"SELECT {_FN_JSON_SQL} FROM functions WHERE target = ? AND va = ?",
            (target, va_int),
        )
    except ValueError:
        c.execute(
            f"SELECT {_FN_JSON_SQL} FROM functions WHERE target = ? AND name = ?",
            (target, va),
        )

    row = c.fetchone()
    if row:
        conn.close()
        return _json_ok(row[0].encode("utf-8"), Cache_Control=no_cache)

    # Try globals
    try:
        va_int = int(va, 0)
        c.execute(
            f"SELECT {_GLOBAL_JSON_SQL} FROM globals WHERE target = ? AND va = ?",
            (target, va_int),
        )
    except ValueError:
        c.execute(
            f"SELECT {_GLOBAL_JSON_SQL} FROM globals WHERE target = ? AND name = ?",
            (target, va),
        )

    row = c.fetchone()
    conn.close()
    if row:
        return _json_ok(row[0].encode("utf-8"), Cache_Control=no_cache)

    return _json_err(404, {"error": "not found"})


@app.get("/api/asm")
def handle_api_asm():
    if not HAS_CAPSTONE:
        return _json_err(500, {"error": "capstone not installed"})

    va_str = request.query.get("va")
    size_str = request.query.get("size")
    section = request.query.get("section", ".text")
    target = request.query.get("target", "SERVER")

    if not va_str or not size_str:
        return _json_err(400, {"error": "missing va or size"})

    try:
        va = int(va_str, 0)
        size = min(int(size_str, 0), 4096)
    except ValueError:
        return _json_err(400, {"error": "invalid va or size"})

    try:
        conn = _db()
    except sqlite3.OperationalError as e:
        return _json_err(503, {"error": str(e)})

    c = conn.cursor()
    c.execute(
        "SELECT * FROM sections WHERE target = ? AND name = ?",
        (target, section),
    )
    row = c.fetchone()
    conn.close()

    if not row:
        return _json_err(404, {"error": f"section {section} not found"})

    sec = dict(row)
    file_offset = sec["fileOffset"] + (va - sec["va"])

    asm_text = get_disassembly(va, size, file_offset, target)
    if not asm_text:
        return _json_err(404, {"error": "not enough bytes in DLL"})

    return _json_ok({"asm": asm_text}, Cache_Control="public, max-age=31536000")


@app.post("/regen")
def handle_regen():
    remote = request.environ.get("REMOTE_ADDR", "")
    if remote not in ("127.0.0.1", "::1", "localhost"):
        return _json_err(403, {"ok": False, "error": "Forbidden: localhost only"})

    global CACHED_INDEX_PAYLOAD, CACHED_INDEX_COMPRESSED
    with INDEX_LOCK:
        CACHED_INDEX_PAYLOAD = None
        CACHED_INDEX_COMPRESSED.clear()

    root = repo_root()
    try:
        subprocess.check_call(
            ["uv", "run", "rebrew-catalog"],
            cwd=str(root),
            timeout=60,
        )
        subprocess.check_call(
            ["python3", "recoverage/build_db.py"],
            cwd=str(root),
            timeout=60,
        )
        return _json_ok({"ok": True})
    except subprocess.TimeoutExpired:
        return _json_err(504, {"ok": False, "error": "Regen timed out"})
    except subprocess.CalledProcessError as e:
        return _json_err(500, {"ok": False, "code": e.returncode})


# ── Static file serving ────────────────────────────────────────────
# Serve /src/* and /original/* from repo root (for source viewing)
# Serve static assets (app.js, style.css) from recoverage/


@app.get("/src/<filepath:path>")
@app.get("/original/<filepath:path>")
def serve_repo_file(filepath):
    """Serve source and original files from repo root (path-traversal safe)."""
    # Determine prefix from the matched route
    prefix = "src" if request.path.startswith("/src/") else "original"
    return static_file(filepath, root=str(repo_root() / prefix))


@app.get("/<filename:re:(?:app\\.js|style\\.css|van\\.min\\.js)>")
def serve_static_asset(filename):
    return static_file(filename, root=str(ui_dir()))


# ── Browser opener ─────────────────────────────────────────────────


def open_browser(url: str) -> None:
    system = platform.system()
    try:
        if system == "Linux":
            subprocess.Popen(
                ["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        elif system == "Darwin":
            subprocess.Popen(
                ["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        elif system == "Windows":
            subprocess.Popen(
                ["start", url],
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            webbrowser.open(url)
    except Exception:
        webbrowser.open(url)


# ── Main ───────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Coverage dashboard dev server (VanJS + SQLite)"
    )
    parser.add_argument(
        "--port", type=int, default=8001, help="Port to serve on (default: 8001)"
    )
    parser.add_argument(
        "--no-open", action="store_true", help="Don't open browser automatically"
    )
    parser.add_argument(
        "--regen", action="store_true", help="Regenerate DB before starting"
    )
    args = parser.parse_args()

    root = repo_root()
    serve_dir = ui_dir()
    url = f"http://127.0.0.1:{args.port}"

    if args.regen:
        print("Regenerating coverage data...")
        subprocess.check_call(
            ["uv", "run", "rebrew-catalog"], cwd=str(root)
        )
        subprocess.check_call(["python3", "recoverage/build_db.py"], cwd=str(root))

    print(f"Serving coverage dashboard at {url}")
    print(f"  Root: {serve_dir}")
    print("  Regen: POST /regen or click Reload in UI")
    print("  Stop: Ctrl+C")

    if not args.no_open:
        threading.Timer(0.5, open_browser, args=(url,)).start()

    app.run(host="127.0.0.1", port=args.port, quiet=True, server="wsgiref")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
