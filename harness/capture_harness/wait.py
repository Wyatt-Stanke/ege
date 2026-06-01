"""Poll for session.json to appear after the browser session completes."""
import time
from pathlib import Path


def wait_for_session(captures_dir: Path, session_id: str, timeout_s: int) -> bool:
    """Return True when session.json exists, False if timeout elapses."""
    target = captures_dir / session_id / "session.json"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if target.exists():
            # Brief wait to ensure the file is fully flushed
            # (server writes atomically via tmp+rename, but be safe).
            time.sleep(0.2)
            return True
        time.sleep(0.5)
    return False
