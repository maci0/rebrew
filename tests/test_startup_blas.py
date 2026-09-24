"""Startup BLAS thread cap (rebrew/__init__.py) — env semantics and CPU band.

NumPy's OpenBLAS pool burned 1.7-2.1 CPU-seconds spinning up on every
``import rebrew.main``; capping the pool at import cut it to ~0.19.
The gate is process CPU time (getrusage), not wall clock, so it holds on
a loaded machine.
"""

import os
import subprocess
import sys

import pytest

_CAP_VARS = ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS")


def _run(code: str, env_overrides: dict[str, str] | None = None) -> str:
    """Run *code* in a fresh interpreter with the cap vars removed first."""
    env = {k: v for k, v in os.environ.items() if k not in _CAP_VARS}
    if env_overrides:
        env.update(env_overrides)
    out = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return out.stdout.strip()


class TestCapEnvSemantics:
    def test_defaults_applied_when_unset(self) -> None:
        got = _run(
            "import rebrew, os; "
            "print(os.environ['OPENBLAS_NUM_THREADS'], os.environ['OMP_NUM_THREADS'])"
        )
        assert got == "1 1"

    @pytest.mark.parametrize("value", ["1", "4", "8"])
    def test_user_override_stays_authoritative(self, value: str) -> None:
        overrides = {"OPENBLAS_NUM_THREADS": value, "OMP_NUM_THREADS": value}
        got = _run(
            "import rebrew, os; "
            "print(os.environ['OPENBLAS_NUM_THREADS'], os.environ['OMP_NUM_THREADS'])",
            overrides,
        )
        assert got == f"{value} {value}"


class TestStartupCpuBand:
    def test_import_rebrew_main_stays_under_one_cpu_second(self) -> None:
        """CLI startup must not burn the OpenBLAS spin (~1.9 CPU-seconds).

        Band, not exact: capped runs measure ~0.19 s, uncapped ~1.9 s, so
        0.8 s separates them with margins both ways on any load level.
        """
        got = _run(
            "import resource; import rebrew.main; "
            "print(f'{resource.getrusage(resource.RUSAGE_SELF).ru_utime:.3f}')"
        )
        cpu_seconds = float(got)
        assert cpu_seconds < 0.8, (
            f"import rebrew.main used {cpu_seconds} CPU-seconds — the OpenBLAS "
            "thread pool is spinning again (cap missing or bypassed)"
        )
        assert cpu_seconds > 0.02, (
            f"import rebrew.main reported {cpu_seconds} CPU-seconds — the measurement did not run"
        )


class TestDeferredHeavyImports:
    def test_app_import_leaves_numpy_httpx_lief_angr_out(self) -> None:
        """Component activation must not import the heavy leaves.

        numpy (~60 ms) and httpx (~46 ms) are deferred to first use
        (compile/GA, MCP/decomp.me paths); lief lands only on a real
        binary parse and angr only behind the prove extra.  Work counter —
        no clock involved.
        """
        got = _run(
            "import rebrew.main, sys; "
            "print(','.join(m for m in ('numpy', 'httpx', 'lief', 'angr') if m in sys.modules))"
        )
        assert got == "", f"import rebrew.main pulled heavy modules: {got}"
