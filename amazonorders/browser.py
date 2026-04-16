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
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from amazonorders.session import AmazonSession

logger = logging.getLogger(__name__)

# Playwright selectors — support both old (/ap/signin) and new (/ax/claim) login flows
_SEL_EMAIL = "#ap_email_login, input[name='email']:not([type='hidden'])"
_SEL_PASSWORD = "#ap_password, input[name='password']:not(.aok-hidden)"
_SEL_OTP = "#auth-mfa-otpcode, input[name='otpCode'], input[name='code']"
_SEL_SKIP = "#auth-account-fixup-skip-link, #ap-account-fixup-skip-link"

_CLAIM_ERROR_SELECTORS = (
    "#empty-claim-alert",
    "#invalid-phone-alert",
    "#invalid-email-alert",
    "#error-alert",
    "#passkey-error-alert",
)
_PASSWORD_ERROR_SELECTORS = (
    "#auth-error-message-box",
    "#auth-password-missing-alert",
    "#auth-email-missing-alert",
)
_GLOBAL_ERROR_SELECTORS = ("#auth-error-message-box",)
_FORM_SUBMIT_TIMEOUT = 30


class BrowserState(Enum):
    CLAIM = "claim"
    PASSWORD = "password"
    MFA = "mfa"
    FIXUP = "fixup"
    CHALLENGE = "challenge"
    AUTHENTICATED = "authenticated"
    UNKNOWN = "unknown"


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

    from urllib.parse import urlencode

    config = amazon_session.config
    sign_in_url = (
        config.constants.SIGN_IN_URL + "?" + urlencode(config.constants.SIGN_IN_QUERY_PARAMS)
    )
    config_dir = os.path.dirname(config.cookie_jar_path)
    browser_state_path = os.path.join(config_dir, "browser_state.json")

    logger.debug("Starting Camoufox browser login")

    # Map sys.platform to the OS strings Camoufox expects.
    camoufox_os = {"linux": "linux", "darwin": "macos", "win32": "windows"}.get(sys.platform, "linux")

    # Camoufox prints "Skipping unknown patch ..." to stdout; suppress it.
    with contextlib.redirect_stdout(io.StringIO()):
        cm = Camoufox(headless=True, os=camoufox_os, locale="en-US")

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
            _save_debug_page(page, config, "browser_signin", amazon_session.debug)

            _run_login_flow(page, amazon_session)

            context.storage_state(path=browser_state_path)
            logger.debug("Browser: saved state to %s", browser_state_path)
        except Exception:
            _save_debug_page(page, config, "browser_error", amazon_session.debug)
            raise
        finally:
            _transfer_cookies(context.cookies(), amazon_session)

    logger.debug("Browser login complete; verifying session")
    response = amazon_session.get(config.constants.BASE_URL, persist_cookies=True)
    if (
        "Hello, sign in" in response.response.text
        and "nav-item-signout" not in response.response.text
        and not amazon_session.auth_cookies_stored()
    ):
        from amazonorders.exception import AmazonOrdersAuthError

        raise AmazonOrdersAuthError(
            "Browser login appeared to succeed but the session is not authenticated."
        )
    amazon_session.is_authenticated = True


def _run_login_flow(  # noqa: PLR0912
    page,
    amazon_session: "AmazonSession",
    timeout: int = 90,
) -> None:
    """Drive the login state machine until Amazon authenticates the session."""
    import time
    from amazonorders.exception import AmazonOrdersAuthError

    config = amazon_session.config
    base_url = config.constants.BASE_URL.rstrip("/")
    last_state = None
    last_url = ""
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        state = _detect_state(page, base_url)
        url = page.url
        if state is not last_state or url != last_url:
            logger.debug("Browser: state=%s url=%s", state.value, url)
            last_state = state
            last_url = url
            if state not in {BrowserState.AUTHENTICATED, BrowserState.UNKNOWN}:
                _save_debug_page(page, config, f"browser_{state.value}", amazon_session.debug)

        error = _visible_error_text(page, _GLOBAL_ERROR_SELECTORS)
        if error:
            raise AmazonOrdersAuthError(f"Error from Amazon: {error}")

        if state is BrowserState.AUTHENTICATED:
            logger.debug("Browser: authenticated (url=%s)", page.url.split("?")[0].rstrip("/"))
            return
        if state is BrowserState.CLAIM:
            _handle_claim_page(page, amazon_session, base_url)
            continue
        if state is BrowserState.PASSWORD:
            _handle_password_page(page, amazon_session, base_url)
            continue
        if state is BrowserState.MFA:
            _handle_mfa_page(page, amazon_session, base_url)
            continue
        if state is BrowserState.FIXUP:
            _handle_fixup_page(page, amazon_session.config, amazon_session.debug, base_url)
            continue
        if state is BrowserState.CHALLENGE:
            _handle_challenge_page(page, amazon_session.config, amazon_session.debug, base_url)
            continue

        page.wait_for_timeout(500)

    debug_path = _save_debug_page(page, amazon_session.config, "browser_timeout", amazon_session.debug, force=True)
    raise AmazonOrdersAuthError(
        f"Browser login timed out after {timeout}s. Final URL: {page.url} — "
        f"debug page saved to {debug_path}"
    )


def _detect_state(page, base_url: str) -> BrowserState:
    """Classify the current Amazon auth page into a high-level state."""
    url = page.url.split("?")[0].rstrip("/")

    if _is_authenticated(url, base_url):
        return BrowserState.AUTHENTICATED
    if _page_has_password_input(page):
        return BrowserState.PASSWORD
    if "/ap/mfa" in url or "/ap/cvf/" in url or _is_visible(page, _SEL_OTP):
        return BrowserState.MFA
    if "accountFixup" in page.url or "auth-account-fixup" in page.url or _is_visible(page, _SEL_SKIP):
        return BrowserState.FIXUP
    if "/ax/aaut/" in url:
        return BrowserState.CHALLENGE
    if _is_visible(page, _SEL_EMAIL):
        return BrowserState.CLAIM
    return BrowserState.UNKNOWN


def _handle_claim_page(page, amazon_session: "AmazonSession", base_url: str) -> None:
    """Submit the email/claim step and wait for the next state."""
    claim_input = _first_locator(page, _SEL_EMAIL)
    claim_input.wait_for(state="visible", timeout=60000)
    claim_input.fill(amazon_session.username)
    _submit_input_form(
        claim_input,
        page,
        BrowserState.CLAIM,
        amazon_session.config,
        amazon_session.debug,
        base_url,
        _CLAIM_ERROR_SELECTORS,
    )


def _handle_password_page(page, amazon_session: "AmazonSession", base_url: str) -> None:
    """Submit the password step and wait for the next state."""
    _save_debug_page(page, amazon_session.config, "browser_password", amazon_session.debug)
    password_input = _first_locator(page, _SEL_PASSWORD)
    password_input.fill(amazon_session.password)
    _submit_input_form(
        password_input,
        page,
        BrowserState.PASSWORD,
        amazon_session.config,
        amazon_session.debug,
        base_url,
        _PASSWORD_ERROR_SELECTORS,
    )


def _handle_mfa_page(page, amazon_session: "AmazonSession", base_url: str) -> None:
    """Generate and submit a TOTP code, then wait for Amazon's next step."""
    otp_input = _first_locator(page, _SEL_OTP)
    otp_input.fill(_generate_otp(amazon_session.otp_secret_key), timeout=5000)
    _submit_input_form(
        otp_input,
        page,
        BrowserState.MFA,
        amazon_session.config,
        amazon_session.debug,
        base_url,
        _PASSWORD_ERROR_SELECTORS,
    )


def _handle_fixup_page(page, config, debug: bool, base_url: str) -> None:
    """Skip trusted-device/account-fixup prompts when Amazon offers them."""
    try:
        _first_locator(page, _SEL_SKIP).click(timeout=2000, no_wait_after=True)
    except Exception:
        pass
    _wait_for_state_change(page, BrowserState.FIXUP, config, debug, base_url)


def _handle_challenge_page(page, config, debug: bool, base_url: str) -> None:
    """Wait for Amazon's JS-driven WAF or ACIC challenge to complete."""
    _wait_for_state_change(page, BrowserState.CHALLENGE, config, debug, base_url, timeout=60)


def _wait_for_state_change(
    page,
    current_state: BrowserState,
    config,
    debug: bool,
    base_url: str,
    timeout: int = 30,
    error_selectors: tuple[str, ...] = (),
    raise_on_timeout: bool = True,
) -> BrowserState:
    """Wait for Amazon to leave the current state or surface a visible error."""
    import time
    from amazonorders.exception import AmazonOrdersAuthError

    last_url = page.url
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        error = _visible_error_text(page, error_selectors)
        if error:
            raise AmazonOrdersAuthError(
                f"Browser login: {current_state.value} step failed: {error}"
            )

        next_state = _detect_state(page, base_url)
        if next_state is not current_state:
            logger.debug("Browser: %s -> %s", current_state.value, next_state.value)
            return next_state

        if page.url != last_url:
            last_url = page.url
            logger.debug("Browser: %s still in progress at %s", current_state.value, page.url)
            _save_debug_page(page, config, f"browser_{current_state.value}_poll", debug)

        page.wait_for_timeout(500)

    if not raise_on_timeout:
        return current_state

    debug_path = _save_debug_page(page, config, f"browser_{current_state.value}_timeout", debug, force=True)
    raise AmazonOrdersAuthError(
        f"Browser login timed out during {current_state.value} step. "
        f"Final URL: {page.url} — debug page saved to {debug_path}"
    )


def _page_has_password_input(page) -> bool:
    """Return True when the current page has entered the password step."""
    try:
        return page.locator(_SEL_PASSWORD).count() > 0
    except Exception:
        return False


def _first_locator(page, selector: str):
    """Return the first locator match for the selector."""
    return page.locator(selector).first


def _is_visible(page, selector: str) -> bool:
    """Safely check whether any matching element is visible."""
    try:
        locator = page.locator(selector)
        return any(locator.nth(i).is_visible() for i in range(locator.count()))
    except Exception:
        return False


def _visible_error_text(page, selectors: tuple[str, ...]) -> str | None:
    """Return the first visible inline Amazon error message, if any."""
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.is_visible():
                text = locator.inner_text().strip()
                return " ".join(text.split()) or selector
        except Exception:
            continue
    return None


def _submit_input_form(
    input_locator,
    page,
    current_state: BrowserState,
    config,
    debug: bool,
    base_url: str,
    error_selectors: tuple[str, ...],
):
    """Submit the form associated with the input."""
    from amazonorders.exception import AmazonOrdersAuthError

    logger.debug("Browser: submitting %s form", current_state.value)
    try:
        input_locator.evaluate(
            """
            (input) => {
                const form = input.form;
                if (!form) {
                    throw new Error("Input is not associated with a form");
                }
                if (typeof form.requestSubmit === "function") {
                    form.requestSubmit();
                    return;
                }
                form.submit();
            }
            """
        )
    except Exception as exc:
        raise AmazonOrdersAuthError(
            f"Browser login: could not submit the {current_state.value} form."
        ) from exc

    return _wait_for_state_change(
        page,
        current_state,
        config,
        debug,
        base_url,
        timeout=_FORM_SUBMIT_TIMEOUT,
        error_selectors=error_selectors,
    )


def _generate_otp(otp_secret_key) -> str:
    """Generate a TOTP code for the current MFA challenge."""
    from amazonorders.exception import AmazonOrdersAuthError
    import pyotp

    if not otp_secret_key:
        raise AmazonOrdersAuthError(
            "Amazon requested an OTP but no otp_secret_key was provided. "
            "Set AMAZON_OTP_SECRET_KEY or pass otp_secret_key= to AmazonSession."
        )

    logger.debug("Browser: generating OTP")
    return pyotp.TOTP(otp_secret_key.replace(" ", "")).now()


def _is_authenticated(url: str, base_url: str) -> bool:
    """Return True if the URL indicates a post-login page."""
    return url == base_url or (
        "amazon.com" in url and "/ap/" not in url and "/ax/" not in url and "signin" not in url
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
