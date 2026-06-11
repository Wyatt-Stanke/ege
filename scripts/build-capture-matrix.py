import json
import os


DEFAULT_MATRIX = [
    {"os": "ubuntu-24.04", "browser": "chrome", "mode": "xvfb", "browser_version": "stable"},
    {"os": "ubuntu-24.04", "browser": "firefox", "mode": "headless", "browser_version": "stable"},
    {"os": "macos-15", "browser": "chrome", "mode": "headless", "browser_version": "stable"},
    {"os": "macos-15", "browser": "firefox", "mode": "headless", "browser_version": "stable"},
    {"os": "macos-15", "browser": "safari", "mode": "headed", "browser_version": "stable"},
    {"os": "windows-2025", "browser": "chrome", "mode": "headless", "browser_version": "stable"},
    {"os": "windows-2025", "browser": "firefox", "mode": "headless", "browser_version": "stable"},
    {"os": "windows-2025", "browser": "edge", "mode": "headless", "browser_version": "stable"},
]

MODE_DEFAULTS = {
    ("ubuntu-24.04", "chrome"): "xvfb",
    ("ubuntu-24.04", "firefox"): "headless",
    ("macos-15", "safari"): "headed",
}

BROWSER_DEFAULTS = {
    "chrome": {"os": "ubuntu-24.04", "mode": "xvfb"},
    "firefox": {"os": "ubuntu-24.04", "mode": "headless"},
    "edge": {"os": "windows-2025", "mode": "headless"},
    "safari": {"os": "macos-15", "mode": "headed"},
}


def read_csv(name: str) -> list[str]:
    return [item.strip() for item in os.environ.get(name, "").split(",") if item.strip()]


def write_output(name: str, value: str) -> None:
    print(f"{name}={value}")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output_file:
        output_file.write(f"{name}={value}\n")


def main() -> None:
    browser = os.environ.get("INPUT_BROWSER", "").strip()
    browser_version = os.environ.get("INPUT_BROWSER_VERSION", "stable").strip() or "stable"
    override_mode = os.environ.get("INPUT_MODE", "").strip()

    if not browser:
        write_output("matrix", json.dumps({"include": DEFAULT_MATRIX}))
        return

    versions = [version.strip() for version in browser_version.split(",") if version.strip()]
    target_oses = read_csv("INPUT_OS")
    if not target_oses:
        target_oses = [BROWSER_DEFAULTS.get(browser, {"os": "ubuntu-24.04"})["os"]]

    include_entries = []
    for target_os in target_oses:
        resolved_mode = override_mode or MODE_DEFAULTS.get((target_os, browser), "headless")
        for version in versions:
            include_entries.append(
                {
                    "os": target_os,
                    "browser": browser,
                    "mode": resolved_mode,
                    "browser_version": version,
                }
            )

    write_output("matrix", json.dumps({"include": include_entries}))


if __name__ == "__main__":
    main()
