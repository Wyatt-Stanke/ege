"""Firefox driver factory."""
import sys

from selenium import webdriver
from selenium.webdriver.firefox.options import Options

from .base import BrowserDriver

_CANDIDATES: dict[str, list[str]] = {
    "linux": [
        "/usr/bin/firefox",
        "/usr/bin/firefox-esr",
    ],
    "darwin": [
        "/Applications/Firefox.app/Contents/MacOS/firefox",
        "/Applications/Firefox Developer Edition.app/Contents/MacOS/firefox",
    ],
    "win32": [
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
        r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
    ],
}


class FirefoxDriver(BrowserDriver):
    def build_driver(self) -> webdriver.Firefox:
        opts = Options()

        binary = self.binary or self._find_binary(_CANDIDATES.get(sys.platform, []))
        if binary:
            opts.binary_location = binary
            self.binary = binary

        profile_dir = self._make_profile()
        opts.add_argument("--no-remote")
        opts.add_argument("--profile")
        opts.add_argument(profile_dir)
        # acceptInsecureCerts is enough for Firefox — no extra flags needed
        opts.set_capability("acceptInsecureCerts", True)

        if self.browser_version:
            opts.browser_version = self.browser_version

        if self.headless:
            # Firefox -headless uses the same binary as headed
            opts.add_argument("-headless")

        return webdriver.Firefox(options=opts)
