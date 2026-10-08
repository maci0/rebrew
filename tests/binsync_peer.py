"""binsync_peer.py: act as a BinSync user on a rebrew state repo, with BinSync's own Client.

Run by ``tests/test_binsync_roundtrip.py`` under the interpreter named by
``REBREW_BINSYNC_PYTHON`` (one with ``binsync`` installed; rebrew's own
environment never needs it).  Prints one JSON document on stdout.

usage: binsync_peer.py load STATE_DIR BINARY_MD5 USER
       binsync_peer.py edit STATE_DIR BINARY_MD5 USER SOURCE_USER EDITS_JSON

``load`` opens the repo as USER and reports every user's state as BinSync
parses it.  ``edit`` copies SOURCE_USER's state, applies EDITS_JSON, and
commits it to ``binsync/<USER>`` through the Client's commit path (the one
its background worker uses), the way a Ghidra user's BinSync would.
"""

import json
import sys
from pathlib import Path
from typing import Any

from binsync.core.client import Client
from binsync.core.state import State
from declib.artifacts import Comment


def _client(state_dir: str, md5: str, user: str) -> Client:
    return Client(
        master_user=user,
        repo_root=state_dir,
        binary_hash=md5,
        push_on_update=False,
        pull_on_update=False,
        commit_on_update=False,
        ignore_lock=True,
    )


def _summary(state: State) -> dict[str, Any]:
    return {
        "user": state.user,
        "functions": {
            f"0x{addr:x}": {"name": func.name, "type": func.header.type if func.header else None}
            for addr, func in state.functions.items()
        },
        "global_vars": {f"0x{addr:x}": g.name for addr, g in state.global_vars.items()},
        "structs": {
            name: {str(off): m.name for off, m in (struct.members or {}).items()}
            for name, struct in state.structs.items()
        },
        "comments": {f"0x{addr:x}": c.comment for addr, c in state.comments.items()},
    }


def load(state_dir: str, md5: str, user: str) -> dict[str, Any]:
    client = _client(state_dir, md5, user)
    try:
        users = sorted(u.name for u in client.users(fetch_cache=False))
        states = {name: _summary(client.get_state(user=name, fetch_cache=False)) for name in users}
    finally:
        client.shutdown()
    return {"users": users, "states": states}


def edit(
    state_dir: str, md5: str, user: str, source_user: str, edits: dict[str, Any]
) -> dict[str, Any]:
    client = _client(state_dir, md5, user)
    try:
        state = client.get_state(user=source_user, fetch_cache=False)
        state.user = user
        for addr, change in edits.get("functions", {}).items():
            func = state.functions[int(addr, 16)]
            if "name" in change:
                func.name = change["name"]
            if "type" in change:
                func.header.type = change["type"]
        for addr, name in edits.get("globals", {}).items():
            state.global_vars[int(addr, 16)].name = name
        for struct_name, change in edits.get("struct_members", {}).items():
            state.structs[struct_name].members[int(change["offset"])].name = change["name"]
        for addr, change in edits.get("comments", {}).items():
            state.comments[int(addr, 16)] = Comment(
                int(addr, 16), change["comment"], func_addr=int(change["func_addr"], 16)
            )
        client._commit_state(state, msg="binsync peer edit")
        head = client.repo.head.commit.hexsha
    finally:
        client.shutdown()
    return {"head": head}


def main() -> None:
    command, state_dir, md5, user = sys.argv[1:5]
    if command == "load":
        result = load(state_dir, md5, user)
    elif command == "edit":
        result = edit(state_dir, md5, user, sys.argv[5], json.loads(Path(sys.argv[6]).read_text()))
    else:
        raise SystemExit(f"unknown command {command!r}")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
