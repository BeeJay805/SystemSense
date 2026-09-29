"""Bounded interpretation of CPU sampled during an exact owner action."""

from __future__ import annotations


def describe_owner_cpu(peak_logical_cores: float | None) -> str:
    """Compare process activity with idle waiting, without attributing a handler."""

    if peak_logical_cores is None:
        return "Owner CPU overlap was unavailable; active work and waiting are unresolved."
    if peak_logical_cores >= 0.5:
        return (
            "Substantial owner CPU favors active process work over an idle wait "
            "during this GET; it does not identify the request handler's work."
        )
    if peak_logical_cores <= 0.1:
        return (
            "Near-idle owner CPU weakens process CPU saturation during this GET "
            "and is consistent with waiting; it does not identify the wait."
        )
    return (
        "Intermediate owner CPU does not clearly distinguish active work "
        "from waiting during this GET."
    )
