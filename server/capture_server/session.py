"""Session tracking: in-memory store with idle-timeout auto-finalization."""
import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class SessionState:
    id: str
    started_at: datetime
    last_seen: datetime
    conn_ids: list = field(default_factory=list)
    conn_summaries: list = field(default_factory=list)
    report: Optional[dict] = None
    finalized: bool = False
    finalized_reason: Optional[str] = None


class SessionStore:
    def __init__(self, out_dir: Path, idle_timeout: int) -> None:
        self._sessions: dict[str, SessionState] = {}
        self.out_dir = out_dir
        self.idle_timeout = idle_timeout
        self._timers: dict[str, asyncio.TimerHandle] = {}

    # ------------------------------------------------------------------
    # Public API (synchronous — safe in single-threaded asyncio)
    # ------------------------------------------------------------------

    def new_session(self) -> SessionState:
        sid = str(uuid.uuid4())
        return self.get_or_create(sid)

    def get_or_create(self, session_id: str) -> SessionState:
        if session_id not in self._sessions:
            now = datetime.now(timezone.utc)
            self._sessions[session_id] = SessionState(
                id=session_id,
                started_at=now,
                last_seen=now,
            )
            self._reset_timer(session_id)
        return self._sessions[session_id]

    def touch(self, session_id: str) -> None:
        if session_id in self._sessions:
            self._sessions[session_id].last_seen = datetime.now(timezone.utc)
            self._reset_timer(session_id)

    def add_conn(self, session_id: str, conn_id: str) -> None:
        state = self.get_or_create(session_id)
        if conn_id not in state.conn_ids:
            state.conn_ids.append(conn_id)
        self.touch(session_id)

    def add_conn_summary(self, session_id: str, summary: dict) -> None:
        state = self.get_or_create(session_id)
        state.conn_summaries.append(summary)

    def set_report(self, session_id: str, report: dict) -> None:
        state = self.get_or_create(session_id)
        state.report = report

    def finalize(self, session_id: str, reason: str) -> None:
        state = self._sessions.get(session_id)
        if not state or state.finalized:
            return
        state.finalized = True
        state.finalized_reason = reason
        self._cancel_timer(session_id)
        self._flush(session_id)
        logger.info("Session %s finalized (%s)", session_id, reason)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _flush(self, session_id: str) -> None:
        state = self._sessions.get(session_id)
        if not state:
            return
        session_dir = self.out_dir / session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        doc = {
            "session_id": session_id,
            "started_at": state.started_at.isoformat(),
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "finalized_reason": state.finalized_reason,
            "connections": state.conn_summaries,
            "report_present": state.report is not None,
        }
        (session_dir / "session.json").write_text(json.dumps(doc, indent=2))
        if state.report:
            (session_dir / "report.json").write_text(
                json.dumps(state.report, indent=2)
            )

    def _reset_timer(self, session_id: str) -> None:
        self._cancel_timer(session_id)
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            return
        handle = loop.call_later(
            self.idle_timeout, self._on_idle_timeout, session_id
        )
        self._timers[session_id] = handle

    def _cancel_timer(self, session_id: str) -> None:
        handle = self._timers.pop(session_id, None)
        if handle:
            handle.cancel()

    def _on_idle_timeout(self, session_id: str) -> None:
        logger.info("Session %s idle-timeout", session_id)
        self.finalize(session_id, "timeout")
