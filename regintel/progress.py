"""Job progress with ETA for document processing.

The worker writes stage markers (``Jobs.set_progress``); this module keeps per-step
timing inside the marker (``progress.timing``) and turns it into an estimate on read.

A *step* is one (stage, framework, document version). Steps that count work report
``done``/``total``/``unit`` (sections in ``extract``, candidates in ``candidate_review``).
Rates are measured from the step's own samples; a finished job's per-unit rates are kept
in its timing history and serve as reference rates for later jobs. An ETA is only given
when the remaining work is known; otherwise ``eta_seconds`` is null with a reason code.
"""
from __future__ import annotations

import statistics
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

HISTORY_LIMIT = 60

# reason codes when an ETA cannot be given
QUEUED = "QUEUED"                            # waiting behind other jobs
NOT_COUNTED = "NOT_COUNTED"                  # the current stage does not count units (retrieve, sync, ...)
INSUFFICIENT_SAMPLES = "INSUFFICIENT_SAMPLES"  # fewer than two counter samples in this step and no reference rate
MORE_WORK_UNKNOWN = "MORE_WORK_UNKNOWN"      # further versions/frameworks follow whose size is not known yet
NO_REFERENCE_RATE = "NO_REFERENCE_RATE"      # the next stage's size is projected but no completed job gives its rate
FINAL_STAGES = "FINAL_STAGES"                # only short, uncounted stages remain (publish, mappings, readiness)
ETA_REASONS = (QUEUED, NOT_COUNTED, INSUFFICIENT_SAMPLES, MORE_WORK_UNKNOWN, NO_REFERENCE_RATE, FINAL_STAGES)

COUNTED_STAGES = ("extract", "candidate_review", "propose_missing_rules")
FINAL = ("publish", "pipeline", "mappings", "readiness")
TERMINAL = ("SUCCEEDED", "PARTIAL", "FAILED", "INTERRUPTED")


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _seconds(a: datetime | None, b: datetime | None) -> float | None:
    return None if a is None or b is None else max(0.0, (b - a).total_seconds())


def _step_key(stage: str, info: dict[str, Any]) -> list[Any]:
    return [stage, info.get("framework_id"), info.get("version_id")]


def _fraction(value: Any) -> tuple[int, int] | None:
    """'3/7' -> (3, 7)."""
    if isinstance(value, str) and "/" in value:
        left, right = value.split("/", 1)
        if left.isdigit() and right.isdigit():
            return int(left), int(right)
    return None


def advance(previous: dict[str, Any] | None, stage: str, info: dict[str, Any], now: datetime) -> dict[str, Any]:
    """The next durable progress marker: ``{stage, at, **info, timing}``."""
    timing = dict((previous or {}).get("timing") or {})
    history = list(timing.get("history") or [])
    key = _step_key(stage, info)
    counted = isinstance(info.get("done"), int) and isinstance(info.get("total"), int)
    if timing.get("step") != key:
        closed = _close(previous, timing)
        if closed:
            history = (history + [closed])[-HISTORY_LIMIT:]
        timing = {"step": key, "step_started_at": _iso(now), "anchor": None}
    if counted and timing.get("anchor") is None:
        timing["anchor"] = {"done": info["done"], "at": _iso(now)}
    timing["history"] = history
    timing.setdefault("job_started_at", (previous or {}).get("timing", {}).get("job_started_at") or _iso(now))
    return {"stage": stage, "at": _iso(now), **info, "timing": timing}


def _rate(marker: dict[str, Any] | None, timing: dict[str, Any]) -> float | None:
    """Seconds per unit measured between the step's first and latest counter samples."""
    anchor = timing.get("anchor")
    if not marker or not anchor or not isinstance(marker.get("done"), int):
        return None
    units = marker["done"] - anchor["done"]
    spent = _seconds(_parse(anchor["at"]), _parse(marker.get("at")))
    if units <= 0 or not spent:
        return None
    return spent / units


def _close(previous: dict[str, Any] | None, timing: dict[str, Any]) -> dict[str, Any] | None:
    if not previous or not timing.get("step") or not isinstance(previous.get("total"), int):
        return None
    return {"stage": previous.get("stage"), "framework_id": previous.get("framework_id"),
            "version_id": previous.get("version_id"), "unit": previous.get("unit"),
            "done": previous.get("done"), "total": previous.get("total"),
            "seconds": _seconds(_parse(timing.get("step_started_at")), _parse(previous.get("at"))),
            "seconds_per_unit": _rate(previous, timing)}


def reference_rates(finished_progress: Iterable[dict[str, Any] | None]) -> dict[str, float]:
    """Median seconds per unit by stage from finished jobs' timing history (and their last open step)."""
    samples: dict[str, list[float]] = {}
    for marker in finished_progress:
        if not marker:
            continue
        timing = marker.get("timing") or {}
        steps = list(timing.get("history") or [])
        last = _close(marker, timing)
        if last:
            steps.append(last)
        for step in steps:
            rate = step.get("seconds_per_unit")
            if rate and step.get("stage") in COUNTED_STAGES:
                samples.setdefault(step["stage"], []).append(rate)
    return {stage: statistics.median(values) for stage, values in samples.items()}


def estimate(job: dict[str, Any], *, now: datetime | None = None, queue_position: int | None = None,
             rates: dict[str, float] | None = None) -> dict[str, Any]:
    """Progress view of one job row: current step with its ETA, and a job ETA when determinable."""
    now = now or datetime.now(timezone.utc)
    rates = rates or {}
    marker = job.get("progress") or {}
    timing = marker.get("timing") or {}
    status = job.get("status")
    started, finished = _parse(job.get("started_at")), _parse(job.get("finished_at"))
    updated = _parse(marker.get("at"))
    out: dict[str, Any] = {
        "job_id": job.get("id"), "status": status, "action": (job.get("payload") or {}).get("action"),
        "created_at": job.get("created_at"), "started_at": job.get("started_at"), "finished_at": job.get("finished_at"),
        "elapsed_seconds": _round(_seconds(started, finished or now)),
        "stage": marker.get("stage"), "framework_id": marker.get("framework_id"),
        "framework": marker.get("framework"), "version": marker.get("version"),
        "updated_at": marker.get("at"),
        "seconds_since_update": _round(_seconds(updated, now)) if status == "RUNNING" else None,
        "queue_position": queue_position if status == "QUEUED" else None,
        "step": None,
        "eta": {"seconds": None, "at": None, "scope": "job", "basis": None, "reason": None, "percent": None},
        "completed_steps": [_public_step(s) for s in timing.get("history") or []],
        "orchestration_stage": marker.get("orchestration_stage"),
        # rule generation (DJANGO_CONTRACT §5.4): the requirement being worked on, its sub-step, outcomes so far
        "rule_generation": ({k: marker.get(k) for k in ("substep", "current", "outcomes", "rules_activated",
                                                         "rules_validated", "seconds_per_requirement", "recent")}
                            | {"done": marker.get("done"), "total": marker.get("total")}
                            if marker.get("stage") == "propose_missing_rules" else None),
    }
    if status in TERMINAL:
        out["eta"].update(seconds=0, at=job.get("finished_at"), percent=100.0, basis="finished")
        return out
    if status == "QUEUED":
        out["eta"]["reason"] = QUEUED
        return out

    stage = marker.get("stage")
    counted = isinstance(marker.get("done"), int) and isinstance(marker.get("total"), int)
    since = _seconds(updated, now) or 0.0
    step_eta = None
    if counted:
        done, total = marker["done"], marker["total"]
        rate, basis = _rate(marker, timing), "measured"
        if rate is None and stage in rates:
            rate, basis = rates[stage], "reference"
        step = {"stage": stage, "unit": marker.get("unit"), "done": done, "total": total,
                "percent": _round(100.0 * done / total if total else 100.0),
                "started_at": timing.get("step_started_at"),
                "elapsed_seconds": _round(_seconds(_parse(timing.get("step_started_at")), now)),
                "seconds_per_unit": _round(rate), "basis": basis if rate is not None else None,
                "eta_seconds": None, "eta_at": None, "reason": None}
        if rate is not None:
            step_eta = max(0.0, (total - done) * rate - since)
            step.update(eta_seconds=_round(step_eta), eta_at=_iso(now + timedelta(seconds=step_eta)))
        else:
            step["reason"] = INSUFFICIENT_SAMPLES
        out["step"] = step

    out["eta"].update(_job_eta(job, marker, step_eta, out["step"], rates))
    eta_seconds = out["eta"]["seconds"]
    if eta_seconds is not None:
        out["eta"]["at"] = _iso(now + timedelta(seconds=eta_seconds))
        elapsed = out["elapsed_seconds"] or 0.0
        out["eta"]["percent"] = _round(100.0 * elapsed / (elapsed + eta_seconds) if elapsed + eta_seconds else 100.0)
    return out


def _last_of(value: Any) -> bool:
    """'n/m' with n == m, or absent (single framework / single version)."""
    frac = _fraction(value)
    return frac is None or frac[0] >= frac[1]


def _job_eta(job, marker, step_eta, step, rates) -> dict[str, Any]:
    stage = marker.get("stage")
    action = (job.get("payload") or {}).get("action")
    last_framework = _last_of(marker.get("framework"))
    if stage in FINAL:
        return {"reason": FINAL_STAGES}
    if stage not in COUNTED_STAGES or step is None:
        return {"reason": NOT_COUNTED}
    if step_eta is None:
        return {"reason": step["reason"]}
    if action == "extract":  # one version, no review stage
        return {"seconds": _round(step_eta), "basis": step["basis"]}
    if not last_framework:
        return {"reason": MORE_WORK_UNKNOWN}
    if stage == "propose_missing_rules":
        # rule generation is the last model-bound stage; mapping-gap and readiness recompute take seconds
        return {"seconds": _round(step_eta), "basis": step["basis"]}
    if stage == "candidate_review":
        # publish / mappings / readiness follow and are not counted (seconds, not minutes)
        return {"seconds": _round(step_eta), "basis": step["basis"]}
    # extract: the review stage follows; its size is projected from the draft yield so far
    if not _last_of(marker.get("version")):
        return {"reason": MORE_WORK_UNKNOWN}
    review_rate = rates.get("candidate_review")
    if review_rate is None:
        return {"reason": NO_REFERENCE_RATE}
    done, total = step["done"], step["total"]
    drafted = marker.get("drafted") or 0
    projected = drafted * total / done if done else 0.0
    return {"seconds": _round(step_eta + projected * review_rate), "basis": "projected",
            "projected_candidates": round(projected)}


def _public_step(step: dict[str, Any]) -> dict[str, Any]:
    return {k: (_round(v) if k in ("seconds", "seconds_per_unit") else v) for k, v in step.items()}


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 1)
