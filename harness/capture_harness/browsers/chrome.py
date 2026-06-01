"""Chrome / Chromium driver factory."""
import sys

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from .base import BrowserDriver

_CANDIDATES: dict[str, list[str]] = {
    "linux": [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
    ],
    "darwin": [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ],
    "win32": [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ],
}


class ChromeDriver(BrowserDriver):
    def build_driver(self) -> webdriver.Chrome:
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
        # Required for running in sandboxed CI environments
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        # Ensure the network service runs in-process (more predictable TLS stack)
        opts.add_argument("--disable-features=NetworkServiceInProcess")
        opts.set_capability("acceptInsecureCerts", True)

        # Tell Selenium Manager which chromedriver version to pair with.
        # When a specific binary is supplied the version is already pinned, but
        # this also handles the no-binary case where SM downloads both.
        if self.browser_version:
            opts.browser_version = self.browser_version

        if self.headless:
            # --headless=new uses the production Chrome binary (not headless_shell)
            opts.add_argument("--headless=new")

        return webdriver.Chrome(options=opts)
