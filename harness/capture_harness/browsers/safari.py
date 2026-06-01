"""Safari driver factory (macOS only)."""
import sys

from selenium import webdriver
from selenium.webdriver.safari.options import Options

from .base import BrowserDriver


class SafariDriver(BrowserDriver):
    def build_driver(self) -> webdriver.Safari:
        if sys.platform != "darwin":
            raise RuntimeError("Safari is only supported on macOS.")

        opts = Options()
        return webdriver.Safari(options=opts)
