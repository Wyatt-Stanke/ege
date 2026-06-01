"""Main harness flow: launch browser → wait for session → record metadata."""
import json
import logging
import os
import platform
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .wait import wait_for_session
from .xvfb import Xvfb

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class _NullContext:
    """No-op context manager used when Xvfb is not requested."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def _trust_cert_macos(cert_pem: str) -> None:
    """Add cert to the macOS system keychain so Safari trusts it."""
    logger.info("Trusting cert in macOS system keychain: %s", cert_pem)
    subprocess.run(
        [
            "sudo", "security", "add-trusted-cert",
            "-d", "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain",
            cert_pem,
        ],
        check=True,
    )


def _driver_version(caps: dict, browser: str) -> str:
    if browser in ("chrome", "chromium"):
        raw = caps.get("chrome", {}).get("chromedriverVersion", "")
        return raw.split(" ")[0] if raw else "unknown"
    if browser == "firefox":
        return caps.get("moz:geckodriverVersion", "unknown")
    if browser == "edge":
        raw = caps.get("msedge", {}).get("msedgedriverVersion", "")
        return raw.split(" ")[0] if raw else "unknown"
    return "unknown"


def run_harness(
    browser: str,
    base_url: str,
    captures_dir: Path,
    timeout_s: int,
    headless: bool,
    use_xvfb: bool,
    binary: str | None,
    cert_pem: str | None,
    keep_profile: bool,
    ci_mode: bool,
) -> str:
    """
    Full harness flow.

    Returns the session UUID on success.
    Raises RuntimeError on timeout or driver failure.
    Stdout receives *nothing* from this function — the UUID is returned to
    cli.py which prints it, keeping stderr/stdout cleanly separated.
    """
    if sys.platform == "linux" and not use_xvfb and not headless and not os.environ.get("DISPLAY"):
        raise RuntimeError(
            "No display available on Linux. "
            "Pass --xvfb, --headless, or set the DISPLAY environment variable."
        )

    # Pre-mint the session UUID so we know what path to watch
    session_id = str(uuid.uuid4())
    start_url = f"{base_url.rstrip('/')}/?sid={session_id}"

    started_at = _now_iso()
    exit_reason = "driver_error"
    ended_at = started_at
    browser_version = "unknown"
    drv_version = "unknown"
    harness_mode = "headless_new" if headless else ("headed_xvfb" if use_xvfb else "headed")

    # macOS Safari: trust cert before launching the browser
    if browser == "safari" and cert_pem and sys.platform == "darwin":
        _trust_cert_macos(cert_pem)

    from .browsers import get_browser_driver
    drv_factory = get_browser_driver(
        browser, binary=binary, headless=headless, keep_profile=keep_profile
    )

    ctx: _NullContext | Xvfb = Xvfb() if use_xvfb else _NullContext()
    driver = None

    try:
        with ctx:
            logger.info("Building WebDriver for %s", browser)
            driver = drv_factory.build_driver()

            caps = driver.capabilities
            browser_version = caps.get("browserVersion", caps.get("version", "unknown"))
            drv_version = _driver_version(caps, browser)

            logger.info("Browser: %s %s  driver: %s", browser, browser_version, drv_version)
            logger.info("Navigating to %s", start_url)
            driver.get(start_url)

            logger.info("Waiting for session.json (timeout=%ds)…", timeout_s)
            completed = wait_for_session(captures_dir, session_id, timeout_s)

            if completed:
                exit_reason = "session_complete"
                logger.info("Session complete: %s", session_id)
            else:
                exit_reason = "timeout"
                logger.error(
                    "Timeout waiting for %s",
                    captures_dir / session_id / "session.json",
                )
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass
        drv_factory.cleanup()
        ended_at = _now_iso()

    # Write harness.json into the session directory
    sess_dir = captures_dir / session_id
    sess_dir.mkdir(parents=True, exist_ok=True)
    harness_info = {
        "schema_version": 1,
        "session_id": session_id,
        "browser": browser,
        "browser_version": browser_version,
        "browser_binary": drv_factory.binary or "",
        "driver_version": drv_version,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "harness_mode": harness_mode,
        "started_at": started_at,
        "ended_at": ended_at,
        "exit_reason": exit_reason,
    }
    (sess_dir / "harness.json").write_text(json.dumps(harness_info, indent=2))
    logger.info("Wrote harness.json for session %s", session_id)

    if exit_reason == "timeout":
        raise RuntimeError(
            f"Timed out waiting for {captures_dir / session_id / 'session.json'}"
        )
    if exit_reason == "driver_error":
        raise RuntimeError(
            f"Browser driver failed before session could complete (browser={browser})."
        )

    if ci_mode:
        logger.info("CI mode: killing server by requesting /die")
        import requests
        try:
            requests.get(f"{base_url.rstrip('/')}/die")
        except Exception:
            pass

    return session_id
