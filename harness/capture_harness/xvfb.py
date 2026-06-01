"""Xvfb context manager for Linux headed mode."""
import os
import subprocess
import time


class Xvfb:
    def __init__(self, display: int = 99, width: int = 1280, height: int = 800):
        self.display = display
        self.width = width
        self.height = height
        self.proc: subprocess.Popen | None = None

    def __enter__(self):
        self.proc = subprocess.Popen(
            [
                "Xvfb", f":{self.display}",
                "-screen", "0", f"{self.width}x{self.height}x24",
                "-nolisten", "tcp",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.environ["DISPLAY"] = f":{self.display}"
        time.sleep(0.3)  # let Xvfb come up
        return self

    def __exit__(self, *args):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
