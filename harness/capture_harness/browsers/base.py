"""Abstract base for per-browser driver factories."""
import os
import shutil
import tempfile
from abc import ABC, abstractmethod


class BrowserDriver(ABC):
    def __init__(self, binary: str | None, headless: bool, keep_profile: bool):
        self.binary = binary
        self.headless = headless
        self.keep_profile = keep_profile
        self._profile_dir: str | None = None

    def _make_profile(self) -> str:
        self._profile_dir = tempfile.mkdtemp(prefix="capture_harness_")
        return self._profile_dir

    def cleanup(self) -> None:
        if not self.keep_profile and self._profile_dir:
            shutil.rmtree(self._profile_dir, ignore_errors=True)
            self._profile_dir = None

    @abstractmethod
    def build_driver(self):
        """Build and return a selenium WebDriver instance."""
        ...

    @staticmethod
    def _find_binary(candidates: list[str]) -> str | None:
        """Return the first candidate that exists and is executable."""
        for c in candidates:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        # Fall back to PATH lookup for plain names
        for c in candidates:
            found = shutil.which(c)
            if found:
                return found
        return None
