import os
import logging
import base64
import zlib
import requests
from uuid import uuid4
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional
from urllib.parse import urlparse
from playwright.sync_api import TimeoutError, Page, BrowserContext, CDPSession
from playwright.sync_api._generated import Playwright


logger = logging.getLogger(__name__)


class RequestsBrowser:

    @staticmethod
    def chrome_session() -> requests.Session:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": "no-cache",
            "dnt": "1",
            "Pragma": "no-cache",
            "sec-ch-ua": '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "macOS",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
            "Upgrade-Insecure-Requests": "1"
        })
        return session


class PlaywrightHelper:

    @staticmethod
    def navigate(page: Page, url: str, browser_config: dict = {}):
        logger.info(f"Page loads url: {url}")
        page.goto(url)
        PlaywrightHelper.wait_for_page_load(page, browser_config)

    @staticmethod
    def sleep(page: Page, seconds: int):
        logger.info(f"Sleeping {seconds} seconds")
        page.wait_for_timeout(seconds*1000)

    @staticmethod
    def reload(page: Page, browser_config: dict = {}):
        logger.info(f"Page reload")
        page.reload()
        PlaywrightHelper.wait_for_page_load(page, browser_config)

    @staticmethod
    def restore(page: Page, url: str, browser_config: dict = {}):
        if page.url != url:
            logger.info(f"Page restores url: {url}")
            PlaywrightHelper.navigate(page, url, browser_config)
        else:
            logger.info(f"Page already on url: {url}")

    @staticmethod
    def wait_for_page_load(page: Page, browser_config: dict = {}):
        sleep_after_onload = browser_config.get("sleep_after_onload", 5)
        wait_for_networkidle = browser_config.get("wait_for_networkidle", True)
        timeout_networkidle = browser_config.get("timeout_networkidle", 10)
        sleep_after_networkidle = browser_config.get("sleep_after_networkidle", 2)
        logger.info("Waiting for page to load")
        logger.info(f"Sleeping {sleep_after_onload}s after onload")
        page.wait_for_timeout(sleep_after_onload*1000)
        if wait_for_networkidle:
            try:
                logger.info(f"Waiting {timeout_networkidle}s for networkidle")
                page.wait_for_load_state("networkidle", timeout=timeout_networkidle*1000)
                logger.info(f"Page is on networkidle, sleeping for {sleep_after_networkidle}s")
                page.wait_for_timeout(sleep_after_networkidle*1000)
            except TimeoutError:
                logger.info(f"Timeout after {timeout_networkidle}s while waiting for networkidle")
        logger.info(f"Page loaded")

    @staticmethod
    def hostname(page: Page) -> str:
        url = urlparse(page.url)
        return url.netloc

    @staticmethod
    def pathname(page: Page) -> str:
        url = urlparse(page.url)
        return url.path

    @staticmethod
    def get_content_type(page: Page) -> str:
        ct = page.evaluate("document.contentType")
        if type(ct) == str:
            return ct
        else:
            return ""

    @staticmethod
    def get_content_analyzable(page: Page) -> Tuple[bool, str]:
        if page.url == "about:blank":
            return False, "page is about:blank"
        ct = page.evaluate("document.contentType")
        if type(ct) != str:
            return False, "could not determine content type of page"
        if "html" not in ct.lower():
            return False, "content type of page is not html"
        return True, ""

    @staticmethod
    def set_about_blank(page: Page, sleep: int = 0):
        logger.info(f"Page loads about:blank and sleeps {sleep}s")
        page.goto("about:blank")
        page.wait_for_timeout(sleep*1000)

    @staticmethod
    def take_screenshot(page: Page) -> str:
        logger.info(f"Taking b64encoded and compressed screenshot of page")
        s = base64.b64encode(zlib.compress(page.screenshot(), 9)).decode()
        logger.info(f"Took b64encoded and compressed screenshot of page")
        return s

    @staticmethod
    def take_har(har_file: str) -> str:
        try:
            with open(har_file, "rb") as f:
                return base64.b64encode(zlib.compress(f.read(), 9)).decode()
        except FileNotFoundError:
            return ""

    @staticmethod
    def take_storage_state(context: BrowserContext) -> dict:
        logger.info(f"Taking storage state of browser context")
        return context.storage_state()

    @staticmethod
    def close_all_other_pages(page: Page):
        logger.info("Closing all pages except current page")
        for i, p in enumerate(page.context.pages):
            if p != page:
                logger.info(f"Closing page {i}")
                p.close()
                logger.info(f"Page {i} closed")

    @staticmethod
    def blank_and_close_all_other_pages(page: Page):
        logger.info("Blanking and closing all pages except current page")
        for i, p in enumerate(page.context.pages):
            if p != page:
                logger.info(f"Blanking page {i}")
                p.goto("about:blank", timeout=30_000)
                logger.info(f"Closing page {i}")
                p.close()
                logger.info(f"Page {i} closed")

    @staticmethod
    def close_context(context: BrowserContext):
        logger.info("Closing browser context")
        empty_page = context.new_page()
        for p in context.pages:
            if p != empty_page:
                logger.info("Blanking page")
                p.goto("about:blank", timeout=30_000)
                logger.info("Closing page")
                p.close()
                logger.info("Page closed")
        logger.info(f"Closing browser context")
        context.close()
        logger.info(f"Browser context closed")


class CDPSessionManager:
    """
    Manages CDP (Chrome DevTools Protocol) sessions for advanced browser control
    """

    def __init__(self, context: BrowserContext, page: Page):
        self.context = context
        self.page = page
        self.cdp_session: Optional[CDPSession] = None
        self.authenticator_id: Optional[str] = None
        self.webauthn_events: List[Dict[str, Any]] = []

    def create_session(self) -> CDPSession:
        """Create a new CDP session"""
        logger.info("Creating CDP session")
        self.cdp_session = self.context.new_cdp_session(self.page)
        logger.info("CDP session created")
        return self.cdp_session

    def enable_webauthn(self):
        """Enable WebAuthn domain in CDP"""
        if not self.cdp_session:
            self.create_session()
        
        logger.info("Enabling WebAuthn in CDP")
        self.cdp_session.send("WebAuthn.enable")
        
        # Set up event listeners
        self.cdp_session.on("WebAuthn.credentialAdded", self._on_credential_added)
        self.cdp_session.on("WebAuthn.credentialAsserted", self._on_credential_asserted)
        
        logger.info("WebAuthn enabled in CDP")

    def add_virtual_authenticator(
        self,
        protocol: str = "ctap2",
        transport: str = "internal",
        has_resident_key: bool = True,
        has_user_verification: bool = True,
        is_user_verified: bool = True,
        automatic_presence_simulation: bool = True,
        is_user_consenting: bool = True
    ) -> str:
        """
        Add a virtual authenticator using CDP
        
        Args:
            protocol: 'ctap2' (modern FIDO2) or 'u2f' (legacy)
            transport: 'internal' (platform/passkey), 'usb', 'ble', 'nfc'
            has_resident_key: Supports resident/discoverable credentials
            has_user_verification: Supports user verification (biometric/PIN)
            is_user_verified: Automatically verify user
            automatic_presence_simulation: Automatically simulate user presence
            is_user_consenting: Automatically consent to operations
        """
        if not self.cdp_session:
            self.enable_webauthn()
        
        logger.info(f"Adding virtual authenticator: protocol={protocol}, transport={transport}")
        
        options = {
            "protocol": protocol,
            "transport": transport,
            "hasResidentKey": has_resident_key,
            "hasUserVerification": has_user_verification,
            "isUserVerified": is_user_verified,
            "automaticPresenceSimulation": automatic_presence_simulation,
            "isUserConsenting": is_user_consenting
        }
        
        result = self.cdp_session.send("WebAuthn.addVirtualAuthenticator", {"options": options})
        self.authenticator_id = result["authenticatorId"]
        
        logger.info(f"Virtual authenticator added: {self.authenticator_id}")
        return self.authenticator_id

    def remove_virtual_authenticator(self):
        """Remove the virtual authenticator"""
        if self.authenticator_id and self.cdp_session:
            logger.info(f"Removing virtual authenticator: {self.authenticator_id}")
            self.cdp_session.send("WebAuthn.removeVirtualAuthenticator", {
                "authenticatorId": self.authenticator_id
            })
            self.authenticator_id = None
            logger.info("Virtual authenticator removed")

    def disable_webauthn(self):
        """Disable WebAuthn domain in CDP"""
        if self.cdp_session:
            logger.info("Disabling WebAuthn in CDP")
            self.cdp_session.send("WebAuthn.disable")
            logger.info("WebAuthn disabled in CDP")

    def get_credentials(self) -> List[Dict[str, Any]]:
        """Get all credentials from the virtual authenticator"""
        if not self.authenticator_id:
            return []
        
        logger.info("Getting credentials from virtual authenticator")
        result = self.cdp_session.send("WebAuthn.getCredentials", {
            "authenticatorId": self.authenticator_id
        })
        
        credentials = result.get("credentials", [])
        logger.info(f"Retrieved {len(credentials)} credentials")
        return credentials

    def _on_credential_added(self, event: Dict[str, Any]):
        """Handle credentialAdded event"""
        logger.info(f"WebAuthn credential added: {event}")
        self.webauthn_events.append({
            "type": "credentialAdded",
            "event": event,
            "timestamp": self.page.evaluate("Date.now()")
        })

    def _on_credential_asserted(self, event: Dict[str, Any]):
        """Handle credentialAsserted event"""
        logger.info(f"WebAuthn credential asserted: {event}")
        self.webauthn_events.append({
            "type": "credentialAsserted",
            "event": event,
            "timestamp": self.page.evaluate("Date.now()")
        })

    def get_events(self) -> List[Dict[str, Any]]:
        """Get all captured WebAuthn events"""
        return self.webauthn_events

    def clear_events(self):
        """Clear captured WebAuthn events"""
        self.webauthn_events = []

    def close(self):
        """Clean up CDP session"""
        if self.authenticator_id:
            self.remove_virtual_authenticator()
        if self.cdp_session:
            self.disable_webauthn()
            self.cdp_session.detach()
            self.cdp_session = None


class PlaywrightBrowser:

    @staticmethod
    def instance(
        playwright: Playwright,
        browser_config: dict,
        user_data_dir: str,
        har_file: Optional[str] = None
    ) -> Tuple[BrowserContext, Page]:
        headless_value = browser_config.get("headless", True)
        logger.info(f"Browser config headless value: {headless_value} (type: {type(headless_value)})")
        return PlaywrightBrowser.browser(
            playwright,
            user_data_dir=user_data_dir,
            har_file=har_file,
            browser_name=browser_config.get("name", "CHROMIUM"),
            user_agent=browser_config.get("user_agent", ""),
            locale=browser_config.get("locale", "en-US"),
            headless=headless_value,
            screen_width=browser_config.get("width", 1920),
            screen_height=browser_config.get("height", 1080),
            viewport_width=browser_config.get("width", 1920),
            viewport_height=browser_config.get("height", 1080),
            extensions=browser_config.get("extensions", []),
            scripts=browser_config.get("scripts", []),
            timeout_default=browser_config.get("timeout_default", 30),
            timeout_navigation=browser_config.get("timeout_navigation", 30)
        )

    @staticmethod
    def browser(
        playwright: Playwright,
        user_data_dir: str = f"/tmp/playwright-{uuid4()}",
        har_file: Optional[str] = None,
        browser_name: str = "CHROMIUM",
        user_agent: str = "",
        locale: str = "en-US",
        headless: bool = False,
        screen_width: int = 1920,
        screen_height: int = 1080,
        viewport_width: int = 1920,
        viewport_height: int = 1080,
        extensions: List[str] = [],
        scripts: List[str] = [],
        timeout_default: float = 30.0,
        timeout_navigation: float = 30.0
    ) -> Tuple[BrowserContext, Page]:
        logger.info(f"Setup playwright for browser: {browser_name}")
        logger.info(f"Headless parameter received: {headless} (type: {type(headless)})")

        # browser
        if browser_name == "CHROMIUM":
            browser = playwright.chromium
        elif browser_name == "FIREFOX":
            browser = playwright.firefox
        elif browser_name == "WEBKIT":
            browser = playwright.webkit
        else:
            raise Exception(f"Browser {browser_name} is not supported")

        # config (browser-independent)
        kwargs = {}
        kwargs["accept_downloads"] = False
        kwargs["ignore_https_errors"] = True
        kwargs["bypass_csp"] = True
        kwargs["locale"] = locale
        kwargs["screen"] = {"width": screen_width, "height": screen_height}
        kwargs["viewport"] = {"width": viewport_width, "height": viewport_height}
        if user_agent:
            kwargs["user_agent"] = user_agent
        if har_file:
            kwargs["record_har_path"] = har_file

        # config (browser-dependent)
        if browser_name == "CHROMIUM":
            bargs = []
            bargs.append("--disable-blink-features=AutomationControlled")
            logger.info(f"Chromium headless check: headless={headless}, bool(headless)={bool(headless)}")
            if headless:
                logger.info("Setting headless=True for Chromium")
                kwargs["headless"] = True
                bargs.append("--headless=new")
            else:
                logger.info("Setting headless=False for Chromium")
                kwargs["headless"] = False
            kwargs["args"] = bargs
            logger.info(f"Final kwargs for Chromium: headless={kwargs.get('headless')}, args={bargs}")
        elif browser_name == "FIREFOX":
            kwargs["headless"] = headless
        elif browser_name == "WEBKIT":
            kwargs["headless"] = headless

        # context
        context = browser.launch_persistent_context(user_data_dir, **kwargs)

        # timeouts
        context.set_default_timeout(timeout_default*1000)
        context.set_default_navigation_timeout(timeout_navigation*1000)

        # permissions
        if browser_name == "CHROMIUM" or browser_name == "FIREFOX":
            context.grant_permissions(["notifications", "geolocation"])

        # api overwrites
        context.add_init_script(script="""
            window.alert = ()=>{};
            window.confirm = ()=>{};
            window.prompt = ()=>{};
            window.print = ()=>{};
        """)

        # page
        if context.pages:
            page = context.pages[0]
        else:
            page = context.new_page()

        return (context, page)

