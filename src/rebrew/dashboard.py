"""dashboard.py – Read-only web dashboard over the coverage database.

Serves the SQLite ``coverage.db`` (built by ``rebrew build-db``) over a tiny
HTTP server with no dependencies beyond the stdlib.  Every endpoint is
read-only: the database is opened in ``mode=ro`` and non-GET requests are
rejected with 405.

Endpoints
---------
``GET /``                      → minimal HTML app (vanilla JS, no build step)
``GET /api/targets``           → list of targets (includes count/total)
``GET /api/summary?target=``   → function stats + coverage % (target required)
``GET /api/functions?target=`` → function rows (filters: status, module, q, limit)
``GET /api/sections?target=``  → per-section cell stats (includes count/total)
``GET /api/globals?target=``   → global data rows (filter: q, limit; includes total)
``GET /api/history?target=``   → status-change history (limit; includes total)

Target-scoped endpoints return 400 when ``target`` is missing/empty and 404 when
the target is unknown.  Non-GET/HEAD methods return 405 with ``Allow: GET, HEAD``.
Requests whose ``Host`` header does not match the bound host (or a loopback
alias) are rejected with 403, so a web page the analyst visits cannot reach
the server via DNS rebinding.
List endpoints expose ``count`` (rows in this page) and ``total`` (matching rows).

The query layer (``Dashboard``) is separated from the HTTP plumbing so tests
exercise it without opening a socket.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import typer
from rich.console import Console

from rebrew.build_db import resolve_db_dir
from rebrew.cli import error_exit, json_print
from rebrew.workspace.db import sqlite_ro_uri

console = Console(stderr=True)
log = logging.getLogger(__name__)

_SQLITE_TIMEOUT_SECONDS = 30.0
_DEFAULT_LIMIT = 500
_MAX_LIMIT = 5000


_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rebrew coverage dashboard</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 1.5rem; color: #1a1a1a; }
  .filters { display: flex; flex-wrap: wrap; gap: .5rem 1rem; align-items: end;
    margin-bottom: .5rem; }
  .filters > div { display: flex; flex-direction: column; gap: .25rem; font-size: .9rem; }
  select, input { min-height: 2.75rem; padding: .3rem .5rem; min-width: 10rem; }
  :focus-visible { outline: 3px solid #005fcc; outline-offset: 2px; }
  h1 { margin-bottom: .25rem; }
  .cards { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }
  .card { border: 1px solid #ccc; border-radius: 6px; padding: .6rem 1rem; min-width: 110px; }
  .card b { font-size: 1.4rem; display: block; }
  .table-scroll { overflow-x: auto; position: relative; }
  .table-scroll[aria-busy="true"]::after {
    content: "Loading…"; position: absolute; inset: 0; display: flex; align-items: center;
    justify-content: center; background: rgba(255,255,255,.7); font-size: .95rem; color: #444;
  }
  .visually-hidden { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; font-size: .85rem; }
  th, td { border: 1px solid #ddd; padding: .3rem .5rem; text-align: left; }
  th { background: #f5f5f5; }
  td.va { font-family: monospace; }
  #dashboard-error { color: #9a3412; background: #fff7ed; border: 1px solid #fed7aa;
    border-radius: 6px; padding: .6rem .8rem; margin: .75rem 0; }
  #empty-state, #no-targets { color: #555; margin: 1rem 0; }
  #results-hint { color: #555; font-size: .9rem; margin: .25rem 0 0; }
</style>
</head>
<body>
<main>
<h1>Rebrew coverage</h1>
<p id="no-targets" hidden>No targets found in coverage.db. Run
  <code>rebrew build-db</code> for this project, then reload.</p>
<div id="controls" class="filters" hidden>
<div>
<label for="target">Target</label>
<select id="target"></select>
</div>
<div>
<label for="status">Status</label>
<select id="status"><option value="">any</option></select>
</div>
<div>
<label for="q">Search name or symbol</label>
<input id="q" type="search" size="24" placeholder="name or symbol" autocomplete="off">
</div>
</div>
<section id="summary" aria-labelledby="summary-heading" aria-busy="false" hidden>
<h2 class="visually-hidden" id="summary-heading">Coverage summary</h2>
<div class="cards" id="cards"></div>
</section>
<p class="visually-hidden" id="results-status" role="status" aria-live="polite"></p>
<p id="dashboard-error" role="alert" hidden></p>
<p id="results-hint" hidden></p>
<p id="empty-state" hidden>No functions match these filters. Clear search or set Status to any.</p>
<div id="results" class="table-scroll" tabindex="0" role="region"
  aria-label="Function results" aria-busy="false" hidden>
<table id="rows"><caption class="visually-hidden">Functions matching the selected filters</caption><thead><tr>
  <th scope="col">VA</th><th scope="col">Name</th><th scope="col">Symbol</th>
  <th scope="col">Size</th><th scope="col">Status</th>
  <th scope="col">Module</th><th scope="col">Files</th>
</tr></thead><tbody></tbody></table>
</div>
</main>
<script>
const $ = (id) => document.getElementById(id);
let targets = [];
let searchTimer = null;
let functionsSeq = 0;
const busyCounts = new Map();
async function get(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(path + " -> " + r.status);
  return r.json();
}
async function whileBusy(id, operation) {
  const element = $(id);
  const count = (busyCounts.get(id) || 0) + 1;
  busyCounts.set(id, count);
  element.setAttribute("aria-busy", "true");
  try {
    return await operation();
  } finally {
    const remaining = (busyCounts.get(id) || 1) - 1;
    busyCounts.set(id, remaining);
    if (remaining === 0) element.setAttribute("aria-busy", "false");
  }
}
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[c]);
}
function showError(message) {
  $("results-status").textContent = message;
  $("dashboard-error").textContent = message;
  $("dashboard-error").hidden = false;
}
function clearError() {
  $("dashboard-error").textContent = "";
  $("dashboard-error").hidden = true;
}
function setStatusOptions(byStatus) {
  const select = $("status");
  const previous = select.value;
  const names = Object.keys(byStatus || {}).sort();
  select.innerHTML = "<option value=''>any</option>"
    + names.map(s => "<option value='" + esc(s) + "'>" + esc(s) + "</option>").join("");
  if (previous && names.includes(previous)) select.value = previous;
  else select.value = "";
}
function setResultsMessage(count, total) {
  const hint = $("results-hint");
  if (!total) {
    $("results-status").textContent = "No functions match";
    hint.hidden = true;
    hint.textContent = "";
    return;
  }
  if (count < total) {
    const msg = "Showing " + count + " of " + total + " matching functions (page limit)";
    $("results-status").textContent = msg;
    hint.textContent = msg + ". Narrow Status or Search to see the rest.";
    hint.hidden = false;
  } else {
    const msg = count + " function" + (count === 1 ? "" : "s") + " shown";
    $("results-status").textContent = msg;
    hint.hidden = true;
    hint.textContent = "";
  }
}
async function loadFunctions() {
  const t = $("target").value; if (!t) return;
  const seq = ++functionsSeq;
  const params = new URLSearchParams({ target: t });
  if ($("status").value) params.set("status", $("status").value);
  if ($("q").value.trim()) params.set("q", $("q").value.trim());
  try {
    $("results").hidden = false;
    $("empty-state").hidden = true;
    const data = await whileBusy("results", () => get("/api/functions?" + params));
    if (seq !== functionsSeq) return;
    clearError();
    const body = $("rows").querySelector("tbody");
    body.innerHTML = "";
    for (const f of data.functions) {
      const tr = document.createElement("tr");
      tr.innerHTML = "<td class=va>" + esc(f.va) + "</td><td>" + esc(f.name || "")
        + "</td><td>" + esc(f.symbol || "") + "</td><td>" + esc(f.size ?? "")
        + "</td><td>" + esc(f.status || "") + "</td><td>" + esc(f.module || "")
        + "</td><td>" + esc(f.files || "") + "</td>";
      body.appendChild(tr);
    }
    const total = data.total ?? data.count;
    setResultsMessage(data.count, total);
    $("empty-state").hidden = data.count !== 0;
  } catch (error) {
    if (seq !== functionsSeq) return;
    showError("Failed to load functions: " + error.message);
  }
}
async function loadSummary() {
  const t = $("target").value; if (!t) return;
  try {
    const s = await whileBusy("summary", () =>
      get("/api/summary?target=" + encodeURIComponent(t)));
    clearError();
    const byStatus = s.function_stats.by_status || {};
    setStatusOptions(byStatus);
    const cards = [
      ["Functions", s.function_stats.total],
      ["Matched", (s.coverage_pct ?? 0).toFixed(1) + "%"],
      ["Identified", (s.identified_pct ?? 0).toFixed(1) + "%"],
    ];
    for (const [k, v] of Object.entries(byStatus)) cards.push([k, v]);
    $("cards").innerHTML = cards.map(([k, v]) =>
      "<div class=card><b>" + esc(v) + "</b>" + esc(k) + "</div>").join("");
    $("summary").hidden = false;
  } catch (error) {
    showError("Failed to load summary: " + error.message);
  }
}
function scheduleSearch() {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(loadFunctions, 200);
}
async function init() {
  targets = (await get("/api/targets")).targets;
  if (!targets.length) {
    $("no-targets").hidden = false;
    $("results-status").textContent = "No targets in coverage.db";
    return;
  }
  $("controls").hidden = false;
  $("target").innerHTML = targets.map(t =>
    "<option value='" + esc(t) + "'>" + esc(t) + "</option>").join("");
  $("target").onchange = () => {
    $("status").value = "";
    $("q").value = "";
    clearTimeout(searchTimer);
    void (async () => {
      await loadSummary();
      await loadFunctions();
    })();
  };
  $("status").onchange = loadFunctions;
  $("q").oninput = scheduleSearch;
  await loadSummary();
  await loadFunctions();
}
init().catch(error => {
  showError("Dashboard failed to load: " + error.message);
});
</script>
</body>
</html>
"""


def _int_param(params: dict[str, list[str]], name: str, default: int) -> int:
    """Parse a positive int query param, clamped to ``[_DEFAULT floor, _MAX_LIMIT]``.

    Missing, empty, non-numeric, or non-positive values fall back to *default*
    so ``limit=0`` / ``limit=-1`` never silently return an empty page.
    """
    values = params.get(name)
    raw = values[0] if values else None
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (ValueError, TypeError):
        return default
    if value <= 0:
        return default
    return min(value, _MAX_LIMIT)


def _opt_query(params: dict[str, list[str]], name: str) -> str | None:
    """Return a stripped optional query value, or None when missing/blank."""
    values = params.get(name)
    raw = values[0] if values else None
    if raw is None:
        return None
    stripped = raw.strip()
    return stripped or None


def _escape_like(term: str) -> str:
    """Escape LIKE wildcards so user input is matched literally.

    Mirrors recoverage's _escape_like: `%`, `_`, and `\\` are escaped and the
    query must add ``ESCAPE '\\'``.
    """
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class Dashboard:
    """Read-only query layer over a ``coverage.db`` file."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        """Yield a read-only connection, closed on every exit path.

        ``sqlite3.Connection`` used directly as a context manager only
        commits/rolls back the transaction — it never closes.  Under the
        threaded HTTP server that would leave one GC-dependent connection
        per request; closing here releases the handle deterministically.
        """
        # Percent-encode the path (``sqlite_ro_uri``): a raw ``file:{p}?mode=ro``
        # truncates or rewrites names that contain ``?`` / ``#`` / ``%``.
        conn = sqlite3.connect(
            sqlite_ro_uri(self.db_path), uri=True, timeout=_SQLITE_TIMEOUT_SECONDS
        )
        try:
            yield conn
        finally:
            conn.close()

    def targets(self) -> list[str]:
        with self._conn() as conn:
            rows = conn.execute("SELECT DISTINCT target FROM functions ORDER BY target").fetchall()
        return [r[0] for r in rows]

    def summary(self, target: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value FROM metadata WHERE target = ? AND key = 'function_stats'",
                (target,),
            ).fetchone()
        if row is None:
            return None
        try:
            stats = json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            stats = {
                "total": 0,
                "covered_bytes": 0,
                "matched_bytes": 0,
                "total_bytes": 0,
                "by_status": {},
            }
        # Headline coverage = reversed bytes (EXACT/RELOC/PROVEN) / text size.
        # Not byte-identity: PROVEN bytes differ from the target (verify's
        # _STATUS_RANK puts PROVEN below RELOC for that reason). —
        # the old covered_bytes summed every function's size, so an all-STUB
        # binary reported ~100% "coverage" (db-review F1).  Identified bytes
        # (incl. stubs) stays available as a separate field.
        covered = int(stats.get("matched_bytes") or 0)
        identified = int(stats.get("covered_bytes") or 0)
        # total_b comes solely from function_stats — the old fallback read a
        # second metadata row (key='summary') and probed its ".text" size, but
        # nothing writes a ".text" key there, so the branch never fired.
        total_b = int(stats.get("total_bytes") or 0)
        return {
            "target": target,
            "function_stats": stats,
            "coverage_pct": round(covered / total_b * 100.0, 1) if total_b else 0.0,
            "identified_pct": round(identified / total_b * 100.0, 1) if total_b else 0.0,
        }

    def functions(
        self,
        target: str,
        *,
        status: str | None = None,
        module: str | None = None,
        q: str | None = None,
        limit: int = _DEFAULT_LIMIT,
    ) -> dict[str, Any]:
        where = ["target = ?"]
        args: list[Any] = [target]
        if status:
            where.append("status = ?")
            args.append(status)
        if module:
            where.append("module = ?")
            args.append(module)
        if q:
            where.append("(name LIKE ? ESCAPE '\\' OR symbol LIKE ? ESCAPE '\\')")
            args.extend([f"%{_escape_like(q)}%", f"%{_escape_like(q)}%"])
        # Exclude non-function rows; must remain in *where* for the COUNT total.
        where.append("markerType NOT IN ('GLOBAL', 'DATA')")
        where_sql = " AND ".join(where)
        query = (
            "SELECT va, name, symbol, size, status, module, files, markerType "
            f"FROM functions WHERE {where_sql} ORDER BY va LIMIT ?"
        )
        with self._conn() as conn:
            rows = conn.execute(query, [*args, limit]).fetchall()
            total = conn.execute(
                f"SELECT COUNT(*) FROM functions WHERE {where_sql}",
                args,
            ).fetchone()[0]
        return {
            "target": target,
            "count": len(rows),
            "total": total,
            "functions": [
                {
                    "va": f"0x{r[0]:08x}" if r[0] else "???",
                    "name": r[1] or "",
                    "symbol": r[2] or "",
                    "size": r[3],
                    "status": r[4] or "",
                    "module": r[5] or "",
                    "files": ", ".join(_load_list(r[6])),
                    "markerType": r[7] or "",
                }
                for r in rows
            ],
        }

    def sections(self, target: str) -> dict[str, Any]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT section_name, total_cells, exact_count, reloc_count, "
                "near_match_count, stub_count, padding_count, data_count, "
                "thunk_count, none_count, proven_count, size_mismatch_count, "
                "other_count "
                "FROM section_cell_stats WHERE target = ? ORDER BY section_name",
                (target,),
            ).fetchall()
            sizes = dict(
                conn.execute(
                    "SELECT name, size FROM sections WHERE target = ?", (target,)
                ).fetchall()
            )
        sections = [
            {
                "name": r[0],
                "size": sizes.get(r[0]),
                "total_cells": r[1],
                "exact": r[2] or 0,
                "reloc": r[3] or 0,
                "near_match": r[4] or 0,
                "stub": r[5] or 0,
                "padding": r[6] or 0,
                "data": r[7] or 0,
                "thunk": r[8] or 0,
                "none": r[9] or 0,
                "proven": r[10] or 0,
                "size_mismatch": r[11] or 0,
                "other": r[12] or 0,
            }
            for r in rows
        ]
        return {
            "target": target,
            "count": len(sections),
            "total": len(sections),
            "sections": sections,
        }

    def globals(
        self, target: str, *, q: str | None = None, limit: int = _DEFAULT_LIMIT
    ) -> dict[str, Any]:
        where = ["target = ?"]
        args: list[Any] = [target]
        if q:
            where.append("name LIKE ? ESCAPE '\\'")
            args.append(f"%{_escape_like(q)}%")
        where_sql = " AND ".join(where)
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT va, name, decl, size, module FROM globals WHERE "
                f"{where_sql} ORDER BY va LIMIT ?",
                [*args, limit],
            ).fetchall()
            total = conn.execute(
                f"SELECT COUNT(*) FROM globals WHERE {where_sql}",
                args,
            ).fetchone()[0]
        return {
            "target": target,
            "count": len(rows),
            "total": total,
            "globals": [
                {
                    "va": f"0x{r[0]:08x}" if r[0] else "???",
                    "name": r[1] or "",
                    "decl": r[2] or "",
                    "size": r[3],
                    "module": r[4] or "",
                }
                for r in rows
            ],
        }

    def history(self, target: str, *, limit: int = 100) -> dict[str, Any]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT va, old_status, new_status, changed_at FROM history "
                "WHERE target = ? ORDER BY id DESC LIMIT ?",
                (target, limit),
            ).fetchall()
            total = conn.execute(
                "SELECT COUNT(*) FROM history WHERE target = ?",
                (target,),
            ).fetchone()[0]
        return {
            "target": target,
            "count": len(rows),
            "total": total,
            "history": [
                {
                    "va": f"0x{r[0]:08x}" if r[0] else "???",
                    "old_status": r[1],
                    "new_status": r[2],
                    "changed_at": r[3],
                }
                for r in rows
            ],
        }

    def target_known(self, target: str) -> bool:
        """True when *target* has function_stats metadata (same criterion as summary)."""
        if not target:
            return False
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM metadata WHERE target = ? AND key = 'function_stats' LIMIT 1",
                (target,),
            ).fetchone()
        return row is not None

    def handle(self, method: str, path: str, query: dict[str, list[str]]) -> tuple[int, str, str]:
        """Route a request.  Returns (status, content-type, body)."""
        if method not in ("GET", "HEAD"):
            return self._json(405, {"error": "method not allowed (read-only; GET, HEAD only)"})
        parsed = urlparse(path)
        if parsed.path == "/":
            return 200, "text/html; charset=utf-8", _INDEX_HTML
        if parsed.path == "/api/targets":
            targets = self.targets()
            return self._json(
                200,
                {"targets": targets, "count": len(targets), "total": len(targets)},
            )

        # All remaining endpoints require ?target=
        if parsed.path in (
            "/api/summary",
            "/api/functions",
            "/api/sections",
            "/api/globals",
            "/api/history",
        ):
            target = _opt_query(query, "target") or ""
            if not target:
                return self._json(400, {"error": "missing required query parameter 'target'"})
            if not self.target_known(target):
                return self._json(404, {"error": f"unknown target {target!r}"})
            if parsed.path == "/api/summary":
                result = self.summary(target)
                # target_known guarantees function_stats; summary still guards None.
                if result is None:
                    return self._json(404, {"error": f"unknown target {target!r}"})
                return self._json(200, result)
            if parsed.path == "/api/functions":
                return self._json(
                    200,
                    self.functions(
                        target,
                        status=_opt_query(query, "status"),
                        module=_opt_query(query, "module"),
                        q=_opt_query(query, "q"),
                        limit=_int_param(query, "limit", _DEFAULT_LIMIT),
                    ),
                )
            if parsed.path == "/api/sections":
                return self._json(200, self.sections(target))
            if parsed.path == "/api/globals":
                return self._json(
                    200,
                    self.globals(
                        target,
                        q=_opt_query(query, "q"),
                        limit=_int_param(query, "limit", _DEFAULT_LIMIT),
                    ),
                )
            return self._json(
                200,
                self.history(
                    target,
                    limit=_int_param(query, "limit", 100),
                ),
            )
        return self._json(404, {"error": f"no such endpoint {parsed.path!r}"})

    @staticmethod
    def _json(status: int, payload: dict[str, Any]) -> tuple[int, str, str]:
        return status, "application/json; charset=utf-8", json.dumps(payload)


def _load_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(v) for v in value] if isinstance(value, list) else []


def _local_interface_ips() -> set[str]:
    """The host's own addresses, for a wildcard bind's Host allow-list.

    A wildcard bind (``--host 0.0.0.0``) has no single expected Host: users
    reach it as ``localhost``, ``127.0.0.1``, or one of the machine's own
    addresses, and the previous allow-list held only the literal wildcard, so
    every real request was 403'd.  Resolver-based (no netlink walk): an
    unresolvable hostname just yields an empty set.
    """
    import socket

    try:
        infos = socket.getaddrinfo(socket.gethostname(), None)
    except OSError:
        return set()
    return {str(info[4][0]) for info in infos if info[4]}


def allowed_hosts_for(host: str, port: int) -> frozenset[str]:
    """Host-header values that must be accepted for a server bound to *host*:*port*.

    Loopback binds also accept their numeric/localhost aliases (users open
    ``localhost`` and ``127.0.0.1`` interchangeably); anything else would
    break normal use.  Every other Host value is rejected by
    :func:`_host_allowed`, which keeps browser-based attackers (DNS
    rebinding against ``127.0.0.1``, cross-site reads of the JSON APIs)
    from reaching the dashboard.

    A wildcard bind (``0.0.0.0`` / ``::`` / empty) listens on every interface,
    so its aliases also cover loopback and the machine's own addresses —
    without them the documented ``--host 0.0.0.0`` produced a server that
    answered only a literal ``Host: 0.0.0.0``.
    """
    wildcard = host in ("0.0.0.0", "::", "")
    loopback = wildcard or host in ("127.0.0.1", "localhost", "::1")
    names = {host} if host else set()
    if loopback:
        names |= {"127.0.0.1", "localhost", "::1"}
    if wildcard:
        names |= _local_interface_ips()
    hosts: set[str] = set()
    for name in names:
        display = f"[{name}]" if ":" in name else name
        hosts.add(f"{display}:{port}".lower())
        if port == 80:  # default port may be omitted in a Host header
            hosts.add(display.lower())
    return frozenset(hosts)


def _host_allowed(host_header: str, allowed: frozenset[str]) -> bool:
    """True when the request's Host header matches one of *allowed* exactly."""
    return host_header.strip().lower() in allowed


class _Handler(BaseHTTPRequestHandler):
    dashboard: Dashboard
    #: Host headers this server must answer; everything else gets 403.
    allowed_hosts: frozenset[str] = frozenset()

    def _respond(self, method: str) -> None:
        if not _host_allowed(self.headers.get("Host", ""), self.allowed_hosts):
            status, content_type, body = self.dashboard._json(
                403, {"error": "request Host not allowed (wrong or missing Host header)"}
            )
            body_bytes = body.encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body_bytes)))
            self._write_security_headers()
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(body_bytes)
            return

        query = parse_qs(urlparse(self.path).query)
        try:
            status, content_type, body = self.dashboard.handle(method, self.path, query)
        except sqlite3.Error as exc:
            # A vanished/corrupt database must answer 500 JSON instead of
            # killing the handler thread with no response at all.
            console.print(f"[red]dashboard query failed:[/red] {self.path}: {exc}")
            status, content_type, body = self.dashboard._json(
                500, {"error": f"database error: {exc}"}
            )
        except Exception as exc:  # last-resort handler guard
            # Any other unexpected error (a bug in a route, an OSError on a
            # sidecar read) gets the same treatment: without this the thread
            # dies and the client sees a connection reset instead of a 500.
            console.print(f"[red]dashboard handler failed:[/red] {self.path}: {exc!r}")
            log.debug("dashboard handler error for %s", self.path, exc_info=True)
            status, content_type, body = self.dashboard._json(
                500, {"error": "internal server error"}
            )
        body_bytes = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        self._write_security_headers()
        if status == 405:
            self.send_header("Allow", "GET, HEAD")
        self.end_headers()
        # HEAD: headers only (RFC 9110); body length still advertised.
        if method != "HEAD":
            self.wfile.write(body_bytes)

    def _write_security_headers(self) -> None:
        """Browser hardening shared by every response, including early 403s."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        # Coverage DB is rebuilt out-of-band; never let the browser cache a
        # stale JSON/HTML snapshot across a ``rebrew build-db`` run.
        self.send_header("Cache-Control", "no-store")
        # The app is inline-JS/CSS only and fetches same-origin JSON — this
        # keeps any future escaping of API data from loading external
        # resources or phoning home.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self'; form-action 'none'; base-uri 'none'",
        )

    def do_GET(self) -> None:  # (http.server API)
        self._respond("GET")

    def do_HEAD(self) -> None:
        self._respond("HEAD")

    def do_POST(self) -> None:
        self._respond("POST")

    def do_PUT(self) -> None:
        self._respond("PUT")

    def do_DELETE(self) -> None:
        self._respond("DELETE")

    def do_PATCH(self) -> None:
        self._respond("PATCH")

    def do_OPTIONS(self) -> None:
        self._respond("OPTIONS")

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet default logging
        # markup=False: the logged request line is remote-controlled text; a
        # path like "/[bold]x" must not be interpreted as Rich markup (log
        # tampering / terminal escape injection).
        console.print(f"  {self.address_string()} {fmt % args}", markup=False)


app = typer.Typer(
    help="Serve a read-only web dashboard over the coverage database.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Usage:[/bold]\n\n"
        "  rebrew build-db · · · · · · · · Build db/coverage.db first\n\n"
        "  rebrew dashboard · · · · · · · Serve on http://127.0.0.1:8000\n\n"
        "  rebrew dashboard --port 9000 · Custom port\n\n"
        "[bold]Endpoints:[/bold]\n\n"
        "  / · · · · · · · · · · · · HTML app (targets, summary, function search)\n\n"
        "  /api/targets · · · · · · List targets\n\n"
        "  /api/summary?target= · · Coverage stats (target required)\n\n"
        "  /api/functions?target= · Function rows (status/module/q/limit)\n\n"
        "  /api/sections?target= · · Per-section cell stats\n\n"
        "  /api/globals?target= · · Global data rows\n\n"
        "  /api/history?target= · · Status-change history\n\n"
        "[dim]Read-only: DB opened mode=ro. Target-scoped routes need ?target= "
        "(400 if missing, 404 if unknown). Non-GET/HEAD → 405.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port"),
    root: Path | None = typer.Option(None, "--root", help="Project root directory"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Serve the coverage database as a read-only web dashboard."""
    root_dir = root.resolve() if root else Path.cwd().resolve()
    db_dir = resolve_db_dir(root_dir, json_output=json_output)
    db_path = db_dir / "coverage.db"
    if not db_path.exists():
        error_exit(
            f"No coverage database at {db_path}. Run 'rebrew build-db' first.",
            json_mode=json_output,
        )

    # Fail fast on an unreadable/incompatible database.
    try:
        Dashboard(db_path).targets()
    except sqlite3.Error as exc:
        error_exit(f"Cannot open database {db_path}: {exc}", json_mode=json_output)

    if json_output:
        json_print({"url": f"http://{host}:{port}", "db": str(db_path)})

    server = ThreadingHTTPServer((host, port), _Handler)
    _Handler.dashboard = Dashboard(db_path)
    _Handler.allowed_hosts = allowed_hosts_for(host, port)
    console.print(
        f"[green]Rebrew dashboard on http://{host}:{port}[/] — "
        f"[dim]serving {db_path} (Ctrl+C to stop)[/dim]"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("[dim]Dashboard stopped.[/dim]")
    finally:
        server.server_close()


def main_entry() -> None:
    """Run the Typer CLI application (standalone single-command form)."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
