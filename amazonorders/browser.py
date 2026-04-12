"""
Camoufox-based browser login for Amazon.

Uses a stealthy Firefox build to complete the Amazon login flow (including any
WAF / ACIC challenges, which run natively as JS), then transfers the resulting
cookies into the ``requests`` session so the rest of the library works normally.

Install requirements::

    pip install amazon-orders[browser]
    python -m camoufox fetch
"""
import contextlib
import io
import logging
import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from amazonorders.session import AmazonSession

logger = logging.getLogger(__name__)

# Playwright selectors — support both old (/ap/signin) and new (/ax/claim) login flows
_SEL_EMAIL = "#ap_email, #ap_email_login"
_SEL_CONTINUE = "#continue"
_SEL_PASSWORD = "#ap_password, input[name='password']:not(.aok-hidden)"
_SEL_SIGNIN = "#signInSubmit, #continue"
_SEL_OTP = "#auth-mfa-otpcode, input[name='otpCode'], input[name='code']"
_SEL_OTP_SUBMIT = "#auth-signin-button"
_SEL_SKIP = "#auth-account-fixup-skip-link, #ap-account-fixup-skip-link"


def browser_login(amazon_session: "AmazonSession") -> None:
    """
    Use a headless Camoufox browser to complete the Amazon login flow, then
    transfer the resulting cookies into *amazon_session*.

    Handles email/password entry, WAF/ACIC challenges (JS runs natively),
    OTP/TOTP (when ``otp_secret_key`` is set), and trusted-device prompts.

    When ``debug`` is enabled on the session, each page transition is saved as an
    HTML file in the configured ``output_dir`` (same as the requests-based flow).

    :param amazon_session: Credentials and config are read from this object.
        Cookies are written back into ``amazon_session.session`` and persisted.
    :raises ImportError: If ``cloverlabs-camoufox`` is not installed.
    :raises AmazonOrdersAuthError: If login fails or times out.
    """
    try:
        from camoufox.sync_api import Camoufox
    except ImportError as exc:
        raise ImportError(
            "cloverlabs-camoufox is required for browser login. "
            "Install with: pip install amazon-orders[browser]  "
            "then run: python -m camoufox fetch"
        ) from exc

    from amazonorders.exception import AmazonOrdersAuthError
    from urllib.parse import urlencode

    config = amazon_session.config
    username = amazon_session.username
    password = amazon_session.password
    otp_secret_key = amazon_session.otp_secret_key
    debug = amazon_session.debug
    headless = not debug

    sign_in_url = (config.constants.SIGN_IN_URL
                   + "?" + urlencode(config.constants.SIGN_IN_QUERY_PARAMS))

    config_dir = os.path.dirname(config.cookie_jar_path)
    browser_state_path = os.path.join(config_dir, "browser_state.json")

    logger.debug("Starting Camoufox browser login (headless=%s)", headless)

    # Map sys.platform to the OS strings Camoufox expects
    _platform_map = {"linux": "linux", "darwin": "macos", "win32": "windows"}
    camoufox_os = _platform_map.get(sys.platform, "linux")

    # Camoufox prints "Skipping unknown patch ..." to stdout; suppress it
    with contextlib.redirect_stdout(io.StringIO()):
        cm = Camoufox(headless=headless, os=camoufox_os, locale="en-US")
    with cm as browser:
        ctx_kwargs = {}
        if os.path.exists(browser_state_path):
            logger.debug("Browser: restoring saved state from %s", browser_state_path)
            ctx_kwargs["storage_state"] = browser_state_path

        context = browser.new_context(**ctx_kwargs)
        page = context.new_page()
        try:
            logger.debug("Browser: navigating to sign-in page")
            page.goto(sign_in_url, wait_until="domcontentloaded", timeout=30000)
            logger.debug("Browser: landed on %s", page.url)
            _save_debug_page(page, config, "browser_signin", debug)

            # Wait for email field — supports both /ap/signin and /ax/claim flows.
            # Long timeout accommodates WAF/ACIC JS challenges that auto-resolve.
            page.wait_for_selector(_SEL_EMAIL, timeout=60000)
            page.fill(_SEL_EMAIL, username)
            page.click(_SEL_CONTINUE)

            page.wait_for_selector(_SEL_PASSWORD, timeout=15000)
            _save_debug_page(page, config, "browser_password", debug)
            page.fill(_SEL_PASSWORD, password)
            page.click(_SEL_SIGNIN)

            _wait_for_auth(page, otp_secret_key, config, debug)

            context.storage_state(path=browser_state_path)
            logger.debug("Browser: saved state to %s", browser_state_path)

        except AmazonOrdersAuthError:
            _save_debug_page(page, config, "browser_error", debug)
            raise
        except Exception as exc:
            _save_debug_page(page, config, "browser_error", debug)
            raise AmazonOrdersAuthError(
                f"Browser login error on page {page.url!r}: {exc}"
            ) from exc
        finally:
            _transfer_cookies(context.cookies(), amazon_session)

    logger.debug("Browser login complete; verifying session")
    response = amazon_session.get(config.constants.BASE_URL, persist_cookies=True)
    if ("Hello, sign in" in response.response.text
            and "nav-item-signout" not in response.response.text
            and not amazon_session.auth_cookies_stored()):
        raise AmazonOrdersAuthError(
            "Browser login appeared to succeed but the session is not authenticated."
        )
    amazon_session.is_authenticated = True


def _wait_for_auth(page, otp_secret_key, config, debug: bool, timeout: int = 30) -> None:
    """Poll the page until Amazon completes authentication or we time out.

    :param timeout: Maximum seconds to wait before raising an error.
    """
    import time
    from amazonorders.exception import AmazonOrdersAuthError

    base_url = config.constants.BASE_URL.rstrip("/")
    last_url = ""
    otp_submitted = False
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        page.wait_for_timeout(500)
        elapsed = int(timeout - (deadline - time.monotonic()))
        url = page.url.split("?")[0].rstrip("/")

        if url != last_url:
            logger.debug("Browser: [%ds] url=%s", elapsed, page.url)
            last_url = url
            _save_debug_page(page, config, "browser_auth_poll", debug)
            if otp_submitted and "/ap/mfa" not in url and "/ap/cvf/" not in url:
                otp_submitted = False

        if _is_authenticated(url, base_url):
            logger.debug("Browser: authenticated (url=%s)", url)
            return

        if ("/ap/mfa" in url or "/ap/cvf/" in url) and not otp_submitted:
            logger.debug("Browser: OTP prompt — submitting")
            _fill_otp(page, otp_secret_key)
            otp_submitted = True
            continue

        if "accountFixup" in url or "auth-account-fixup" in page.url:
            logger.debug("Browser: account fixup — skipping")
            try:
                page.click(_SEL_SKIP, timeout=2000)
            except Exception:
                pass
            continue

        if "/ax/aaut/" in url:
            logger.debug("Browser: WAF/ACIC challenge — waiting for JS")
            continue

        if "/ap/signin" in url and "ap_password" not in page.content():
            raise AmazonOrdersAuthError(
                "Browser login: stuck on sign-in page. Check username/password."
            )

    # Always save the page on timeout for debugging
    debug_path = _save_debug_page(page, config, "browser_timeout", debug, force=True)

    raise AmazonOrdersAuthError(
        f"Browser login timed out after {timeout}s. "
        f"Final URL: {page.url} — debug page saved to {debug_path}"
    )


def _fill_otp(page, otp_secret_key) -> None:
    """Generate and submit a TOTP code."""
    from amazonorders.exception import AmazonOrdersAuthError
    import pyotp

    if not otp_secret_key:
        raise AmazonOrdersAuthError(
            "Amazon requested an OTP but no otp_secret_key was provided. "
            "Set AMAZON_OTP_SECRET_KEY or pass otp_secret_key= to AmazonSession."
        )

    otp = pyotp.TOTP(otp_secret_key.replace(" ", "")).now()
    logger.debug("Browser: submitting OTP")
    try:
        page.fill(_SEL_OTP, otp, timeout=5000)
        page.click(_SEL_OTP_SUBMIT, timeout=5000)
        page.wait_for_timeout(2000)
    except Exception as exc:
        raise AmazonOrdersAuthError("Browser login: could not fill OTP input.") from exc


def _is_authenticated(url: str, base_url: str) -> bool:
    """Return True if the URL indicates a post-login page."""
    return (
        url == base_url
        or (
            "amazon.com" in url
            and "/ap/" not in url
            and "/ax/" not in url
            and "signin" not in url
        )
    )


def _save_debug_page(page, config, name: str, debug: bool = False, force: bool = False) -> str:
    """
    Save the current page HTML to the output directory when debug is enabled.
    Returns the path written (or where it would have been written).
    """
    output_dir = config.output_dir
    path = os.path.join(output_dir, f"{name}.html")
    if not force and not debug:
        return path

    try:
        # Avoid overwriting — append an index
        i = 0
        while os.path.exists(path):
            i += 1
            path = os.path.join(output_dir, f"{name}_{i}.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(page.content())
        logger.debug("Browser: page saved to %s", path)
    except Exception:
        pass
    return path


def _transfer_cookies(camoufox_cookies: list, amazon_session: "AmazonSession") -> None:
    """Copy Camoufox/Playwright cookies into the requests Session."""
    transferred = 0
    for cookie in camoufox_cookies:
        domain = cookie.get("domain", "")
        if "amazon" in domain:
            amazon_session.session.cookies.set(
                cookie["name"],
                cookie["value"],
                domain=domain,
                path=cookie.get("path", "/"),
            )
            transferred += 1
    logger.debug("Browser: transferred %d amazon cookies to session", transferred)
