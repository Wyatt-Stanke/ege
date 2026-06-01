from .base import BrowserDriver


def get_browser_driver(
    browser: str,
    binary: str | None = None,
    headless: bool = False,
    keep_profile: bool = False,
) -> BrowserDriver:
    kwargs = dict(binary=binary, headless=headless, keep_profile=keep_profile)
    if browser == "chrome":
        from .chrome import ChromeDriver
        return ChromeDriver(**kwargs)
    if browser == "firefox":
        from .firefox import FirefoxDriver
        return FirefoxDriver(**kwargs)
    if browser == "edge":
        from .edge import EdgeDriver
        return EdgeDriver(**kwargs)
    if browser == "safari":
        from .safari import SafariDriver
        return SafariDriver(**kwargs)
    raise ValueError(f"Unknown browser: {browser!r}")
