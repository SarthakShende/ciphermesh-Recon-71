"""Verification stage records.

The plan records all nine stages for every attempt, including stages that
never ran, rather than stopping at the first failure. That is a deliberate
trade: a single failing event costs nine rows instead of one, and in exchange
"it failed at UNKNOWN_DEVICE and never reached the signature check" is
distinguishable from "the signature check failed". Those are different
problems for whoever is on call.

A row per stage means a partial write is possible if the process dies
mid-record, so :meth:`VerificationRepository.record_attempt` writes all stages
of one attempt in a single transaction. Either the attempt is fully recorded
or it is absent, and an absent attempt is visible as a gap in the stage
sequence rather than as a silent half-verification.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..constants import VerificationStatus
from ..logging_setup import get_logger

LOG = get_logger(__name__)

#: The nine pipeline stages, in evaluation order. The ordinal is the contract;
#: the name is for humans reading a log or the API. Adding a stage means a new
#: migration is not required (stage is a plain integer) but every recorded
#: attempt keeps its original numbering, which is the point.
STAGE_NAMES: tuple[str, ...] = (
    "SCHEMA_VALID",       # 0
    "DEVICE_RESOLVED",    # 1
    "SIGNATURE_VERIFIED", # 2
    "HASH_MATCHED",       # 3
    "SEQUENCE_ACCEPTED",  # 4
    "TIMESTAMP_ACCEPTED", # 5
    "DEVICE_NOT_REVOKED", # 6
    "NOT_DUPLICATE",      # 7
    "STORED",             # 8
)

STAGE_COUNT = len(STAGE_NAMES)

OUTCOME_PASS = "PASS"
OUTCOME_FAIL = "FAIL"
OUTCOME_SKIPPED = "SKIPPED"

__all__ = [
    "OUTCOME_FAIL",
    "OUTCOME_PASS",
    "OUTCOME_SKIPPED",
    "STAGE_COUNT",
    "STAGE_NAMES",
    "StageResult",
    "VerificationAttempt",
    "VerificationRepository",
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True, slots=True)
class StageResult:
    stage: int
    outcome: str
    detail: str | None = None
    duration_us: int | None = None

    def __post_init__(self) -> None:
        if not 0 <= self.stage < STAGE_COUNT:
            raise ValueError(f"stage {self.stage} outside 0..{STAGE_COUNT - 1}")
        if self.outcome not in (OUTCOME_PASS, OUTCOME_FAIL, OUTCOME_SKIPPED):
            raise ValueError(f"invalid stage outcome {self.outcome!r}")


@dataclass(frozen=True, slots=True)
class VerificationAttempt:
    """One complete pass through the pipeline for one event."""

    event_id: str
    status: VerificationStatus
    stages: tuple[StageResult, ...]
    attempt: int = 1

    def __post_init__(self) -> None:
        ordinals = [s.stage for s in self.stages]
        if ordinals != sorted(ordinals):
            raise ValueError("stage results must be in pipeline order")

    @property
    def first_failure(self) -> StageResult | None:
        for stage in self.stages:
            if stage.outcome == OUTCOME_FAIL:
                return stage
        return None

    @property
    def failure_stage_name(self) -> str | None:
        stage = self.first_failure
        return STAGE_NAMES[stage.stage] if stage else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "attempt": self.attempt,
            "status": self.status.value,
            "failure_stage": self.failure_stage_name,
            "stages": [
                {
                    "stage": s.stage,
                    "name": STAGE_NAMES[s.stage],
                    "outcome": s.outcome,
                    "detail": s.detail,
                    "duration_us": s.duration_us,
                }
                for s in self.stages
            ],
        }


def all_stages(
    *, fail_at: int | None = None, durations: dict[int, int] | None = None
) -> tuple[StageResult, ...]:
    """Build a full nine-stage record.

    Stages after ``fail_at`` are SKIPPED rather than absent, so the record is
    always the same length and a reader never has to guess whether a missing
    stage means "passed", "failed", or "this code version does not have it".
    """
    return tuple(
        StageResult(
            stage=i,
            outcome=(
                OUTCOME_SKIPPED
                if fail_at is not None and i > fail_at
                else OUTCOME_FAIL
                if i == fail_at
                else OUTCOME_PASS
            ),
            duration_us=(durations or {}).get(i),
        )
        for i in range(STAGE_COUNT)
    )


#: Which :class:`VerificationStatus` each pipeline stage reports on failure.
#: A stage that fails produces its own status, so the stored status always
#: explains the stage that produced it.
_STAGE_STATUS: dict[str, VerificationStatus] = {
    "SCHEMA_VALID": VerificationStatus.SCHEMA_INVALID,
    "DEVICE_RESOLVED": VerificationStatus.UNKNOWN_DEVICE,
    "SIGNATURE_VERIFIED": VerificationStatus.INVALID_SIGNATURE,
    "HASH_MATCHED": VerificationStatus.HASH_MISMATCH,
    "SEQUENCE_ACCEPTED": VerificationStatus.SEQUENCE_REPLAY,
    "TIMESTAMP_ACCEPTED": VerificationStatus.STALE_EVENT,
    "DEVICE_NOT_REVOKED": VerificationStatus.DEVICE_REVOKED,
    "NOT_DUPLICATE": VerificationStatus.REPLAY_REJECTED,
}


def _status_for_failure(failure: StageResult | None) -> VerificationStatus:
    if failure is None:
        return VerificationStatus.VERIFIED
    return _STAGE_STATUS.get(STAGE_NAMES[failure.stage], VerificationStatus.SCHEMA_INVALID)


class VerificationRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def record_attempt(self, attempt: VerificationAttempt) -> int:
        """Write every stage of one attempt.

        The caller is responsible for the surrounding transaction. All nine
        rows land together so a crash cannot leave a partial verification on
        disk that looks like a real one.
        """
        recorded_at = _now()
        self._conn.executemany(
            "INSERT INTO event_verifications (event_id, attempt, stage, stage_name, "
            "outcome, detail, duration_us, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    attempt.event_id,
                    attempt.attempt,
                    result.stage,
                    STAGE_NAMES[result.stage],
                    result.outcome,
                    result.detail,
                    result.duration_us,
                    recorded_at,
                )
                for result in attempt.stages
            ],
        )
        return attempt.attempt

    def attempts_for(self, event_id: str) -> list[VerificationAttempt]:
        """Every recorded attempt for an event, oldest first."""
        grouped: dict[int, list[StageResult]] = {}
        rows = self._conn.execute(
            "SELECT attempt, stage, outcome, detail, duration_us "
            "FROM event_verifications WHERE event_id = ? ORDER BY attempt, stage",
            (event_id,),
        )
        for row in rows:
            grouped.setdefault(int(row["attempt"]), []).append(
                StageResult(
                    stage=int(row["stage"]),
                    outcome=row["outcome"],
                    detail=row["detail"],
                    duration_us=row["duration_us"],
                )
            )

        attempts = []
        for number, stages in sorted(grouped.items()):
            ordered = tuple(stages)
            failure = next((s for s in ordered if s.outcome == OUTCOME_FAIL), None)
            attempts.append(
                VerificationAttempt(
                    event_id=event_id,
                    status=_status_for_failure(failure),
                    stages=ordered,
                    attempt=number,
                )
            )
        return attempts

    def stage_summary(self, event_id: str) -> dict[str, Any]:
        """Compact view for the API: which stage rejected, and why."""
        attempts = self.attempts_for(event_id)
        if not attempts:
            return {"event_id": event_id, "attempts": []}
        latest = attempts[-1]
        return latest.to_dict()

    def total_attempts(self) -> int:
        return int(self._conn.execute("SELECT COUNT(DISTINCT event_id) FROM event_verifications").fetchone()[0])

    def rejection_counts(self) -> dict[str, int]:
        """How many events were rejected at each stage.

        A sudden spike at SCHEMA_VALID means a peer upgraded incompatibly; at
        SIGNATURE_VERIFIED it means someone is guessing keys. Operators need
        that distinction, so the stage is what is counted.
        """
        rows = self._conn.execute(
            "SELECT stage_name, COUNT(DISTINCT event_id) AS n "
            "FROM event_verifications WHERE outcome = ? GROUP BY stage_name",
            (OUTCOME_FAIL,),
        )
        return {r["stage_name"]: int(r["n"]) for r in rows}

    def prune_orphans(self) -> int:
        """Remove stage records whose event no longer exists.

        ``ON DELETE CASCADE`` handles this on any database created by the
        current schema, so this exists only to clean up rows written before
        the constraint existed, or by a restore that dropped it. Returns 0 in
        the normal case.
        """
        cursor = self._conn.execute(
            "DELETE FROM event_verifications WHERE event_id NOT IN "
            "(SELECT event_id FROM events)"
        )
        return cursor.rowcount or 0
