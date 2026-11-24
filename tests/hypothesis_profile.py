"""Pytest plugin: the suite's hypothesis settings, with wall time taken out of every verdict.

The suite runs on shared, loaded hosts, where hypothesis's per-example ``deadline`` and its
``too_slow`` health check (input generation timed against wall clock) pass or fail by the
neighbours' load, not by the code.  Example counts stay what each test sets.
"""

from hypothesis import HealthCheck, settings

settings.register_profile("rebrew", deadline=None, suppress_health_check=[HealthCheck.too_slow])
settings.load_profile("rebrew")
