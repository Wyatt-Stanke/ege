"""CLI entry point: python -m capture_harness"""
import argparse
import logging
import sys
from pathlib import Path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="capture_harness",
        description="Drive a real browser at the TLS capture server.",
    )
    parser.add_argument(
        "--browser", required=True,
        choices=["chrome", "firefox", "edge", "safari"],
        help="Browser to drive.",
    )
    parser.add_argument(
        "--url", default="https://capture.localhost:8443/",
        help="Capture server start URL (default: https://capture.localhost:8443/).",
    )
    parser.add_argument(
        "--captures-dir", default="./captures", metavar="DIR",
        help="Directory where the capture server writes sessions (default: ./captures).",
    )
    parser.add_argument(
        "--timeout", type=int, default=120,
        help="Seconds to wait for session.json to appear (default: 120).",
    )
    parser.add_argument(
        "--xvfb", action="store_true",
        help="Wrap a headed browser in Xvfb (Linux only).",
    )
    parser.add_argument(
        "--headless", action="store_true",
        help="Run headless: --headless=new for Chrome/Edge, -headless for Firefox.",
    )
    parser.add_argument(
        "--browser-version", default=None, metavar="VERSION",
        help="Browser version to capture (e.g. '130', '130.0.6723.69', 'beta', 'dev'). "
             "In CI, the matching browser must already be installed (e.g. via "
             "browser-actions/setup-chrome). The harness passes this to Selenium Manager "
             "so the correct driver version is paired.",
    )
    parser.add_argument(
        "--binary", default=None,
        help="Override browser binary path.",
    )
    parser.add_argument(
        "--cert-pem", default=None, metavar="PATH",
        help="Path to server cert to trust in macOS keychain (Safari only).",
    )
    parser.add_argument(
        "--keep-profile", action="store_true",
        help="Keep temp profile directory on exit (useful for debugging).",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        help="Logging level (default: INFO).",
    )
    parser.add_argument(
        "--ci-mode",
        action="store_true",
        help="Kill server when done.",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if args.xvfb and args.headless:
        print("Error: --xvfb and --headless are mutually exclusive.", file=sys.stderr)
        return 2

    from .harness import run_harness

    try:
        session_id = run_harness(
            browser=args.browser,
            base_url=args.url,
            captures_dir=Path(args.captures_dir),
            timeout_s=args.timeout,
            headless=args.headless,
            use_xvfb=args.xvfb,
            binary=args.binary,
            browser_version=args.browser_version,
            cert_pem=args.cert_pem,
            keep_profile=args.keep_profile,
            ci_mode=args.ci_mode,
        )
        # Print session UUID to stdout — nothing else
        print(session_id)
        return 0
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        logging.getLogger(__name__).exception("Unexpected error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
