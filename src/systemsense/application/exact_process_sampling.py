"""Shared eligibility for identity-bound exact-process pressure sampling."""

from __future__ import annotations

import re

from systemsense.evidence.targets import exact_executable_name


def exact_process_streaming_name(objective: str) -> str | None:
    """Return the exact executable only for supported pressure-measurement questions.

    Pure present-time liveness remains inventory-only; PDF performance objectives
    retain their separate broad/manual frontier.
    """
    name = exact_executable_name(objective)
    if name is None or _is_pdf_performance_objective(objective):
        return None
    if _is_named_process_liveness_objective(objective) and not re.search(
        r"\b(why|cause|reason|because|happened|doing|behaving)\b",
        objective,
        re.IGNORECASE,
    ):
        return None
    return name


def _is_pdf_performance_objective(objective: str) -> bool:
    text = objective.casefold()
    return bool(
        re.search(r"\bpdf\b", text)
        and re.search(r"\b(slow(?:ly)?|hang|freeze|stutter|lag|latency|unresponsive)\b", text)
    )


def _is_named_process_liveness_objective(objective: str) -> bool:
    text = objective.casefold()
    if re.search(r"\b(cpu|processor)\b", text):
        return False
    if not re.search(r"\b(running|stopped|stop|exited|exit|present|gone)\b", text):
        return False
    return not re.search(r"\b(slow|lag|memory|disk)\b", text)
