import logging
import time
import traceback
from copy import deepcopy
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, Error, TimeoutError
from common.modules.browser.browser import PlaywrightBrowser, PlaywrightHelper
from common.modules.helper.tmp import TmpHelper
from common.modules.helper.url import URLHelper
from common.modules.loginpagedetection.paths import Paths
from common.modules.loginpagedetection.sitemap import Sitemap
from common.modules.loginpagedetection.robots import Robots
from common.modules.loginpagedetection.searxng import Searxng
from common.modules.loginpagedetection.crawling import Crawling
from modules.detectors.webauthn_param_detector import WebAuthnParamDetector


logger = logging.getLogger(__name__)


class WebAuthnParamAnalyzer:

    def __init__(self, domain: str, config: dict):
        self.domain = domain
        self.config = config

        self.browser_config = config.get("browser_config", config.get("browser", {}))
        self.artifacts_config = config.get("artifacts_config", {
            "store_webauthn_screenshot": True,
            "store_webauthn_har": True
        })
        self.login_page_url_regexes = config.get("login_page_config", {}).get("login_page_url_regexes", [
            {"regex": "/(log|sign)[_\\-\\s]*(in|up|on)(/.*|\\?.*|\\#.*|\\s*)$", "priority": 99}
        ])
        self.login_page_strategy_scope = config.get("login_page_config", {}).get("login_page_strategy_scope", [
            "PATHS", "CRAWLING", "HOMEPAGE"
        ])
        self.webauthn_detection_config = config.get("webauthn_detection_config", {
            "wait_time": 5,
            "allow_click": False,
            "max_interactions": 3
        })

        self.result = {}
        self.result["resolved"] = {}
        self.result["timings"] = {}
        self.result["login_page_candidates"] = []
        self.result["webauthn_detected"] = False
        self.result["create_options"] = None
        self.result["get_options"] = None
        self.result["cdp_events"] = []


    def start(self) -> dict:
        logger.info(f"Starting WebAuthn parameter analysis for domain: {self.domain}")

        ttotal = time.time()

        # resolve
        t = time.time()
        self.resolve()
        self.result["timings"]["resolve_duration_seconds"] = time.time() - t

        # login page detection
        if self.result["resolved"]["reachable"]:
            t = time.time()
            self.login_page_detection()
            self.result["timings"]["login_page_detection_duration_seconds"] = time.time() - t

        # webauthn parameter detection
        if self.result["resolved"]["reachable"] and self.result["login_page_candidates"]:
            t = time.time()
            self.webauthn_parameter_detection()
            self.result["timings"]["webauthn_detection_duration_seconds"] = time.time() - t

        self.result["timings"]["total_duration_seconds"] = time.time() - ttotal

        return self.result


    def resolve(self):
        logger.info(f"Starting resolve for domain: {self.domain}")

        with TmpHelper.tmp_dir() as pdir, sync_playwright() as pw:
            context, page = PlaywrightBrowser.instance(pw, self.browser_config, pdir)

            try:
                logger.info(f"Resolving https://{self.domain}")
                r = page.goto(f"https://{self.domain}")
                s, u = r.status if r else None, page.url
                if not s or s < 200 or s >= 400: # status code 2xx or 3xx
                    logger.info(f"Invalid status code while resolving domain {self.domain} with https: {s}")
                else:
                    logger.info(f"Successfully resolved domain {self.domain} with https: {u}")
                    self.result["resolved"] = {"reachable": True, "domain": urlparse(u).netloc, "url": u}
                    return
            except TimeoutError as e:
                logger.info(f"Timeout while resolving domain {self.domain} with https")
                logger.debug(e)
            except Error as e:
                logger.info(f"Error while resolving domain {self.domain} with https")
                logger.debug(e)

            try:
                logger.info(f"Resolving http://{self.domain}")
                r = page.goto(f"http://{self.domain}")
                s, u = r.status if r else None, page.url
                if not s or s < 200 or s >= 400: # status code 2xx or 3xx
                    logger.info(f"Invalid status code while resolving domain {self.domain} with http: {s}")
                    self.result["resolved"] = {"reachable": False, "error_msg": f"Status code {s}"}
                else:
                    logger.info(f"Successfully resolved domain {self.domain} with http: {u}")
                    self.result["resolved"] = {"reachable": True, "domain": urlparse(u).netloc, "url": u}
            except TimeoutError as e:
                logger.info(f"Timeout while resolving domain {self.domain} with http")
                logger.debug(e)
                self.result["resolved"] = {"reachable": False, "error_msg": "Timeout", "error": traceback.format_exc()}
            except Error as e:
                logger.info(f"Error while resolving domain {self.domain} with http")
                logger.debug(e)
                self.result["resolved"] = {"reachable": False, "error_msg": f"{e}", "error": traceback.format_exc()}


    def login_page_detection(self):
        logger.info(f"Starting login page detection for domain: {self.domain}")

        for lps in self.login_page_strategy_scope:

            # strategy: homepage (resolved url)
            if lps == "HOMEPAGE":
                t = time.time()
                lpc = self.result["resolved"]["url"]
                self.result["login_page_candidates"].append({
                    "login_page_candidate": URLHelper.normalize(lpc),
                    "login_page_strategy": "HOMEPAGE",
                    "login_page_priority": URLHelper.prio_of_url(lpc, self.login_page_url_regexes)
                })
                self.result["timings"]["login_page_detection_homepage_duration_seconds"] = time.time() - t

            # strategy: manual
            elif lps == "MANUAL":
                t = time.time()
                manual_candidates = self.config.get("login_page_config", {}).get("manual_strategy_config", {}).get("login_page_candidates", [])
                for lpc in manual_candidates:
                    self.result["login_page_candidates"].append({
                        "login_page_candidate": URLHelper.normalize(lpc),
                        "login_page_strategy": "MANUAL",
                        "login_page_priority": URLHelper.prio_of_url(lpc, self.login_page_url_regexes)
                    })
                self.result["timings"]["login_page_detection_manual_duration_seconds"] = time.time() - t

            # strategy: paths
            elif lps == "PATHS":
                t = time.time()
                Paths(self.config, self.result).start()
                self.result["timings"]["login_page_detection_paths_duration_seconds"] = time.time() - t

            # strategy: sitemap
            elif lps == "SITEMAP":
                t = time.time()
                Sitemap(self.config, self.result).start()
                self.result["timings"]["login_page_detection_sitemap_duration_seconds"] = time.time() - t

            # strategy: robots
            elif lps == "ROBOTS":
                t = time.time()
                Robots(self.config, self.result).start()
                self.result["timings"]["login_page_detection_robots_duration_seconds"] = time.time() - t

            # strategy: metasearch (via searxng)
            elif lps == "METASEARCH":
                t = time.time()
                Searxng(self.config, self.result).start()
                self.result["timings"]["login_page_detection_metasearch_duration_seconds"] = time.time() - t

            # strategy: crawling
            elif lps == "CRAWLING":
                t = time.time()
                Crawling(self.config, self.result).start()
                self.result["timings"]["login_page_detection_crawling_duration_seconds"] = time.time() - t

        # sort login page candidates by priority
        self.result["login_page_candidates"] = sorted(
            self.result["login_page_candidates"], 
            key=lambda x: x.get("login_page_priority", {}).get("priority", 0), 
            reverse=True
        )

        logger.info(f"Found {len(self.result['login_page_candidates'])} login page candidates for domain: {self.domain}")


    def webauthn_parameter_detection(self):
        logger.info(f"Starting WebAuthn parameter detection for domain: {self.domain}")

        # Try each login page candidate until WebAuthn is detected
        for lpc in self.result["login_page_candidates"]:
            login_page_url = lpc["login_page_candidate"]
            logger.info(f"Analyzing login page: {login_page_url}")

            try:
                with TmpHelper.tmp_dir() as pdir, TmpHelper.tmp_file() as har, sync_playwright() as pw:
                    # Create browser with CDP support and HAR capture
                    har_file = har if self.artifacts_config.get("store_webauthn_har") else None
                    context, page = PlaywrightBrowser.instance(pw, self.browser_config, pdir, har_file=har_file)
                    
                    # Navigate to login page
                    logger.info(f"Navigating to: {login_page_url}")
                    PlaywrightHelper.navigate(page, login_page_url, self.browser_config)
                    
                    # Initialize WebAuthn detector (first-party only, passive-first)
                    detector_result = {}
                    detection_config = {
                        "wait_time": int(self.webauthn_detection_config.get("wait_time", 3)),
                        "allow_click": bool(self.webauthn_detection_config.get("allow_click", False))
                    }
                    detector = WebAuthnParamDetector(
                        page,
                        detector_result,
                        self.browser_config,
                        detection_config=detection_config,
                        site_domain=self.result["resolved"].get("domain")
                    )
                    
                    # Inject instrumentation before any further navigation/interaction
                    detector.inject_instrumentation()
                    
                    # Set up virtual authenticator
                    auth_id = detector.setup_virtual_authenticator()
                    logger.info(f"Virtual authenticator set up: {auth_id}")
                    
                    # Attempt to capture passively first; only interact if configured
                    triggered, trigger_details = detector.attempt_trigger_webauthn(login_page_url)
                    
                    # Extract captured parameters
                    captures = detector.extract_captured_params()
                    cdp_events = detector.get_cdp_events()
                    
                    # Process results
                    create_options = None
                    get_options = None
                    
                    for capture in captures:
                        if capture.get('type') == 'create' and capture.get('extracted_params'):
                            create_options = capture['extracted_params']
                        elif capture.get('type') == 'get' and capture.get('extracted_params'):
                            get_options = capture['extracted_params']
                    
                    # Clean up
                    detector.cleanup()
                    
                    # If WebAuthn detected, save results
                    # Filter to first-party captures only (same rpId/domain if available)
                    def is_first_party(c):
                        try:
                            url = c.get('url') or ''
                            from urllib.parse import urlparse as _urlparse
                            uhost = _urlparse(url).netloc
                            sdomain = self.result["resolved"].get("domain")
                            return (sdomain and uhost.endswith(sdomain)) or True  # keep if cannot determine
                        except Exception:
                            return True

                    first_party_captures = [c for c in captures if is_first_party(c)]
                    if first_party_captures or cdp_events:
                        logger.info(f"WebAuthn detected on: {login_page_url}")
                        self.result["webauthn_detected"] = True
                        self.result["login_page_url"] = login_page_url
                        self.result["login_page_strategy"] = lpc["login_page_strategy"]
                        self.result["create_options"] = create_options
                        self.result["get_options"] = get_options
                        self.result["cdp_events"] = cdp_events
                        self.result["trigger_details"] = trigger_details
                        
                        # Store artifacts if configured
                        if self.artifacts_config.get("store_webauthn_screenshot"):
                            try:
                                screenshot_path = f"{pdir}/webauthn_screenshot.png"
                                PlaywrightHelper.take_screenshot(page, screenshot_path)
                                with open(screenshot_path, "rb") as f:
                                    import base64
                                    self.result["webauthn_screenshot"] = base64.b64encode(f.read()).decode()
                            except:
                                pass
                        
                        if self.artifacts_config.get("store_webauthn_har") and har_file:
                            try:
                                with open(har_file, "r") as f:
                                    self.result["webauthn_har"] = f.read()
                            except:
                                pass
                        
                        # Stop after first successful detection
                        return

            except Exception as e:
                logger.warning(f"Error detecting WebAuthn on {login_page_url}: {e}")
                logger.exception(e)
                continue

        if not self.result["webauthn_detected"]:
            logger.info(f"No WebAuthn detected on any login page for domain: {self.domain}")
