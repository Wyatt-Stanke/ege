"""Microsoft Edge driver factory (Chromium-based)."""
import sys

from selenium import webdriver
from selenium.webdriver.edge.options import Options

from .base import BrowserDriver

_CANDIDATES: dict[str, list[str]] = {
    "linux": [
        "/usr/bin/microsoft-edge",
        "/usr/bin/microsoft-edge-stable",
    ],
    "darwin": [
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ],
    "win32": [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ],
}


class EdgeDriver(BrowserDriver):
    def build_driver(self) -> webdriver.Edge:
        opts = Options()

        binary = self.binary or self._find_binary(_CANDIDATES.get(sys.platform, []))
        if binary:
            opts.binary_location = binary
            self.binary = binary

        profile_dir = self._make_profile()
        opts.add_argument(f"--user-data-dir={profile_dir}")
        opts.add_argument("--ignore-certificate-errors")
        opts.add_argument("--no-first-run")
        opts.add_argument("--no-default-browser-check")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.set_capability("acceptInsecureCerts", True)

        if self.browser_version:
            opts.browser_version = self.browser_version

        if self.headless:
            opts.add_argument("--headless=new")

        return webdriver.Edge(options=opts)
