import unittest
from unittest.mock import MagicMock, patch

from amazonorders.browser import (
    BrowserState,
    _detect_state,
    _handle_claim_page,
    _is_visible,
    _submit_input_form,
)
from amazonorders.exception import AmazonOrdersAuthError


class _FakeMatch:
    def __init__(self, visible: bool):
        self._visible = visible

    def is_visible(self):
        return self._visible


class _FakeLocator:
    def __init__(self, matches):
        self._matches = [_FakeMatch(visible) for visible in matches]
        self.first = self

    def count(self):
        return len(self._matches)

    def nth(self, index: int):
        return self._matches[index]


class _FakePage:
    def __init__(self, url: str, selectors: dict[str, list[bool]]):
        self.url = url
        self._selectors = selectors

    def locator(self, selector: str):
        return _FakeLocator(self._selectors.get(selector, []))


class TestBrowser(unittest.TestCase):
    def test_is_visible_checks_all_matches(self):
        page = _FakePage(
            "https://www.amazon.com/ap/signin",
            {"input[name='password']": [False, True]},
        )

        self.assertTrue(_is_visible(page, "input[name='password']"))

    def test_detect_state_prefers_password_over_hidden_email_hint(self):
        page = _FakePage(
            "https://www.amazon.com/ax/claim",
            {
                "#ap_password, input[name='password']:not(.aok-hidden)": [True],
                "#ap_email_login, input[name='email']:not([type='hidden'])": [False],
            },
        )

        self.assertEqual(
            BrowserState.PASSWORD,
            _detect_state(page, "https://www.amazon.com"),
        )

    def test_detect_state_prefers_password_when_present_but_not_visible(self):
        page = _FakePage(
            "https://www.amazon.com/ap/signin",
            {
                "#ap_password, input[name='password']:not(.aok-hidden)": [False],
                "#ap_email_login, input[name='email']:not([type='hidden'])": [True],
            },
        )

        self.assertEqual(
            BrowserState.PASSWORD,
            _detect_state(page, "https://www.amazon.com"),
        )

    def test_handle_claim_page_submits_claim_form_with_enter(self):
        page = MagicMock()
        claim_locator = MagicMock()
        page.locator.return_value = claim_locator
        claim_locator.first = claim_locator
        amazon_session = MagicMock()
        amazon_session.username = "some-username@gmail.com"
        amazon_session.config = MagicMock()
        amazon_session.debug = True

        with patch("amazonorders.browser._submit_input_form") as submit_input_form:
            _handle_claim_page(page, amazon_session, "https://www.amazon.com")

        page.locator.assert_called_once_with(
            "#ap_email_login, input[name='email']:not([type='hidden'])",
        )
        claim_locator.wait_for.assert_called_once_with(
            state="visible",
            timeout=60000,
        )
        claim_locator.fill.assert_called_once_with(
            "some-username@gmail.com",
        )
        submit_input_form.assert_called_once()

    def test_submit_input_form_uses_enter_when_state_changes(self):
        page = MagicMock()
        input_locator = MagicMock()

        with patch("amazonorders.browser._wait_for_state_change") as wait_for_state_change:
            wait_for_state_change.return_value = BrowserState.PASSWORD
            result = _submit_input_form(
                input_locator,
                page,
                BrowserState.CLAIM,
                MagicMock(),
                True,
                "https://www.amazon.com",
                ("#error",),
            )

        input_locator.evaluate.assert_called_once()
        self.assertEqual(BrowserState.PASSWORD, result)

    def test_submit_input_form_raises_when_form_submit_fails(self):
        page = MagicMock()
        input_locator = MagicMock()
        input_locator.evaluate.side_effect = RuntimeError("boom")

        with patch("amazonorders.browser._wait_for_state_change") as wait_for_state_change:
            wait_for_state_change.return_value = BrowserState.CLAIM
            with self.assertRaisesRegex(AmazonOrdersAuthError, "could not submit the claim form"):
                _submit_input_form(
                    input_locator,
                    page,
                    BrowserState.CLAIM,
                    MagicMock(),
                    True,
                    "https://www.amazon.com",
                    ("#error",),
                )

        input_locator.evaluate.assert_called_once()

    def test_submit_input_form_waits_once_with_default_timeout(self):
        page = MagicMock()
        input_locator = MagicMock()
        config = MagicMock()

        with patch("amazonorders.browser._wait_for_state_change") as wait_for_state_change:
            wait_for_state_change.return_value = BrowserState.PASSWORD
            _submit_input_form(
                input_locator,
                page,
                BrowserState.CLAIM,
                config,
                True,
                "https://www.amazon.com",
                ("#error",),
            )

        wait_for_state_change.assert_called_once()
        self.assertEqual(30, wait_for_state_change.call_args.kwargs["timeout"])
        self.assertNotIn("raise_on_timeout", wait_for_state_change.call_args.kwargs)

    def test_handle_claim_page_passes_claim_error_selectors(self):
        page = MagicMock()
        claim_locator = MagicMock()
        page.locator.return_value = claim_locator
        claim_locator.first = claim_locator
        amazon_session = MagicMock()
        amazon_session.username = "some-username@gmail.com"
        amazon_session.config = MagicMock()
        amazon_session.debug = True

        with patch("amazonorders.browser._submit_input_form") as submit_input_form:
            _handle_claim_page(page, amazon_session, "https://www.amazon.com")

        self.assertEqual(claim_locator, submit_input_form.call_args.args[0])
        self.assertEqual(BrowserState.CLAIM, submit_input_form.call_args.args[2])
        self.assertEqual(
            (
                "#empty-claim-alert",
                "#invalid-phone-alert",
                "#invalid-email-alert",
                "#error-alert",
                "#passkey-error-alert",
            ),
            submit_input_form.call_args.args[6],
        )
