"""Concurrent decompme upload dedup."""

import threading
lazy from pathlib import Path

import rebrew.decompme as decompme


def _payload() -> dict:
    return {
        "data": {
            "compiler": "msvc6.0",
            "platform": "win32",
            "source_code": "int f(void){return 0;}",
        },
        "files": {"target_obj": ("f.o", b"\x01", "application/octet-stream")},
    }


def test_concurrent_check_upload_record_uploads_once(tmp_path: Path) -> None:
    digest = decompme.scratch_digest(_payload(), "https://decomp.me")
    uploads: list[str] = []

    def _worker() -> None:
        with decompme._uploads_transaction(tmp_path):
            if decompme.recorded_upload(tmp_path, digest, "https://decomp.me") is None:
                slug = f"slug{len(uploads) + 1}"
                uploads.append(slug)
                decompme.record_upload(tmp_path, digest, slug, "tok", "https://decomp.me")

    threads = [threading.Thread(target=_worker) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert uploads == ["slug1"]
    entry = decompme.recorded_upload(tmp_path, digest, "https://decomp.me")
    assert entry is not None and entry["slug"] == "slug1"
