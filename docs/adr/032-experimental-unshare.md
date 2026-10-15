# ADR-032: Explicit local execution and experimental rootless namespaces

- **Status**: Accepted
- **Date**: 2026-10-16

## Context

Docker frontend/daemon startup adds overhead to small translation units. Local
experiments can reuse toolchain image filesystems while creating namespaces
directly. This changes execution and isolation assumptions, so selection must be
explicit and comparison evidence must identify the backend.

## Decision

Add `[compiler] execution_backend = "docker" | "podman" | "unshare"`, inherited
by targets with ordinary compiler override precedence. An omitted setting keeps
`REBREW_CONTAINER_RUNTIME`, normally Docker. Keep `runner` for compiler loaders.
The remote recompile service remains a separate backend; unshare conflicts with it.

Ship unshare as an experimental opt-in for unprivileged Linux x86_64 and pinned
32-bit MSVC/Wine images. Build the packaged C helper lazily using system json-c.
Export admitted local image IDs once and run each compiler in new user/PID and
private auxiliary namespaces with a disposable overlay. Retain no host Wine
fallback. Reject unsupported profiles and OCI requests. Include helper/profile
content in object and verification cache identity. Verify preflights before
writing comparison verdicts.

## Consequences

Normal runs, failures and interruptions remove private overlays; PID namespace
teardown kills detached descendants. Parent-death signals cover lost launchers.
Unrecoverable process/host kills can leave disk scratch for the existing stale
sweep. Exported image/helper caches persist intentionally.

This helper is not a full OCI runtime or a Docker security peer: it provides no
seccomp policy or cgroup resource limits. Persistent Wine workers and linked
comparison remain unsupported. Image build/pull use the existing frontend knob.
