import logging
import time
import traceback
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
from common.modules.auth_mechanisms import PasskeyMechanism

logger = logging.getLogger(__name__)


class PasskeyAnalyzer:

    def __init__(self, domain: str, config: dict):
        self.domain = domain
        self.config = config
        self.browser_config = config["browser_config"]
        self.artifacts_config = config.get("artifacts_config", {})
        self.login_page_url_regexes = config.get("login_page_config", {}).get("login_page_url_regexes", [])
        self.login_page_strategy_scope = config.get("login_page_config", {}).get("login_page_strategy_scope", ["PATHS", "HOMEPAGE"])
        self.passkey_detection_config = config.get("passkey_detection_config", {})
        
        self.result = {
            "resolved": {},
            "timings": {},
            "login_page_candidates": [],
            "passkey": {
                "detected": False,
                "confidence": "NONE",
                "detection_methods": [],  # Categories: UI_ELEMENT, DOM_STRUCTURE, JS_API, NETWORK, LIBRARY, ENTERPRISE
                "indicators": [],
                "login_page_url": None,
                "login_page_strategy": None,
                "webauthn_api_available": False,
                "implementation": {
                    "captured": False,
                    "trigger_method": None,
                    "create_options": None,
                    "get_options": None,
                    "credentials": [],
                    "cdp_events": [],  # Capped at 50
                    "attestation": None,
                    "extensions": None,
                    "user_verification": None,
                    "authenticator_attachment": None,
                    "resident_key": None,
                    "conditional_mediation": None
                },
                "artifacts": {
                    "screenshot": None,
                    "har": None,
                    "webauthn_calls": []
                },
                "element_info": {
                    "coordinates_x": None,
                    "coordinates_y": None,
                    "width": None,
                    "height": None,
                    "inner_text": None,
                    "outer_html": None
                }
            }
        }

    def start(self) -> dict:
        logger.info(f"Starting passkey analysis for: {self.domain}")
        
        ttotal = time.time()
        
        t = time.time()
        self.resolve()
        self.result["timings"]["resolve_duration_seconds"] = time.time() - t
        
        if self.result["resolved"]["reachable"]:
            t = time.time()
            self.login_page_detection()
            self.result["timings"]["login_page_detection_duration_seconds"] = time.time() - t
            
            t = time.time()
            self.analyze_passkey()
            self.result["timings"]["passkey_analysis_duration_seconds"] = time.time() - t
        
        self.result["timings"]["total_duration_seconds"] = time.time() - ttotal
        
        return self.result

    def resolve(self):
        logger.info(f"Resolving domain: {self.domain}")
        
        with TmpHelper.tmp_dir() as pdir, sync_playwright() as pw:
            context, page = PlaywrightBrowser.instance(pw, self.browser_config, pdir)
            
            try:
                logger.info(f"Trying https://{self.domain}")
                r = page.goto(f"https://{self.domain}")
                s, u = r.status if r else None, page.url
                if s and 200 <= s < 400:
                    logger.info(f"Resolved: {u}")
                    self.result["resolved"] = {"reachable": True, "domain": urlparse(u).netloc, "url": u}
                    return
            except (TimeoutError, Error) as e:
                logger.info(f"HTTPS failed: {e}")
            
            try:
                logger.info(f"Trying http://{self.domain}")
                r = page.goto(f"http://{self.domain}")
                s, u = r.status if r else None, page.url
                if s and 200 <= s < 400:
                    logger.info(f"Resolved: {u}")
                    self.result["resolved"] = {"reachable": True, "domain": urlparse(u).netloc, "url": u}
                else:
                    self.result["resolved"] = {"reachable": False, "error_msg": f"Status {s}"}
            except (TimeoutError, Error) as e:
                logger.info(f"HTTP failed: {e}")
                self.result["resolved"] = {"reachable": False, "error_msg": str(e)}

    def login_page_detection(self):
        logger.info("Starting login page detection")
        
        for lps in self.login_page_strategy_scope:
            if lps == "HOMEPAGE":
                lpc = self.result["resolved"]["url"]
                self.result["login_page_candidates"].append({
                    "login_page_candidate": URLHelper.normalize(lpc),
                    "login_page_strategy": "HOMEPAGE",
                    "login_page_priority": URLHelper.prio_of_url(lpc, self.login_page_url_regexes)
                })
            elif lps == "MANUAL":
                manual_candidates = self.config.get("login_page_config", {}).get("manual_strategy_config", {}).get("login_page_candidates", [])
                for lpc in manual_candidates:
                    self.result["login_page_candidates"].append({
                        "login_page_candidate": URLHelper.normalize(lpc),
                        "login_page_strategy": "MANUAL",
                        "login_page_priority": URLHelper.prio_of_url(lpc, self.login_page_url_regexes)
                    })
            elif lps == "PATHS":
                Paths(self.config, self.result).start()
            elif lps == "CRAWLING":
                Crawling(self.config, self.result).start()
            elif lps == "SITEMAP":
                Sitemap(self.config, self.result).start()
            elif lps == "ROBOTS":
                Robots(self.config, self.result).start()
            elif lps == "METASEARCH":
                Searxng(self.config, self.result).start()
        
        self.result["login_page_candidates"] = sorted(
            self.result["login_page_candidates"],
            key=lambda x: x.get("login_page_priority", {}).get("priority", 0),
            reverse=True
        )

    def analyze_passkey(self):
        logger.info("Starting passkey mechanism analysis")
        
        with TmpHelper.tmp_dir() as pdir, TmpHelper.tmp_file() as har, sync_playwright() as pw:
            har_file = har if self.artifacts_config.get("store_passkey_har") else None
            context, page = PlaywrightBrowser.instance(pw, self.browser_config, pdir, har_file=har_file)
            
            passkey_detector = PasskeyMechanism(page, self.config, self.result["resolved"].get("domain"))
            
            for lpc in self.result["login_page_candidates"]:
                lpc_url = lpc["login_page_candidate"]
                logger.info(f"Analyzing passkey on: {lpc_url}")
                
                try:
                    PlaywrightHelper.navigate(page, lpc_url, self.browser_config)
                    PlaywrightHelper.sleep(page, 3)
                    
                    detection_result = passkey_detector.detect_full(lpc_url)
                    
                    if detection_result["detected"]:
                        logger.info(f"Passkey detected on: {lpc_url}")
                        
                        # Update passkey detection info
                        self.result["passkey"]["detected"] = True
                        self.result["passkey"]["detection_methods"] = detection_result.get("detection_methods", [])
                        self.result["passkey"]["confidence"] = detection_result.get("confidence", "NONE")
                        self.result["passkey"]["indicators"] = detection_result.get("indicators", [])
                        self.result["passkey"]["login_page_url"] = lpc_url
                        self.result["passkey"]["login_page_strategy"] = lpc["login_page_strategy"]
                        self.result["passkey"]["webauthn_api_available"] = detection_result.get("webauthn_api_available", False)
                        
                        # Update element info
                        self.result["passkey"]["element_info"] = {
                            "coordinates_x": detection_result.get("element_coordinates_x"),
                            "coordinates_y": detection_result.get("element_coordinates_y"),
                            "width": detection_result.get("element_width"),
                            "height": detection_result.get("element_height"),
                            "inner_text": detection_result.get("element_inner_text"),
                            "outer_html": detection_result.get("element_outer_html")
                        }
                        
                        # Capture implementation parameters using virtual authenticator
                        impl_result = passkey_detector.capture_implementation_params(lpc_url)
                        
                        if impl_result.get("captured"):
                            self.result["passkey"]["implementation"]["captured"] = True
                            self.result["passkey"]["implementation"]["trigger_method"] = impl_result.get("trigger_method")
                            self.result["passkey"]["implementation"]["create_options"] = impl_result.get("create_options")
                            self.result["passkey"]["implementation"]["get_options"] = impl_result.get("get_options")
                            self.result["passkey"]["implementation"]["credentials"] = impl_result.get("credentials", [])
                            # Cap CDP events at 50
                            self.result["passkey"]["implementation"]["cdp_events"] = impl_result.get("cdp_events", [])[:50]
                            
                            # Extract specific implementation details from options
                            create_opts = impl_result.get("create_options") or {}
                            get_opts = impl_result.get("get_options") or {}
                            
                            # Extract attestation
                            if create_opts.get("attestation"):
                                self.result["passkey"]["implementation"]["attestation"] = create_opts["attestation"]
                            
                            # Extract extensions
                            if create_opts.get("extensions") or get_opts.get("extensions"):
                                self.result["passkey"]["implementation"]["extensions"] = create_opts.get("extensions") or get_opts.get("extensions")
                            
                            # Extract authenticator selection
                            auth_sel = create_opts.get("authenticatorSelection") or {}
                            if auth_sel.get("userVerification"):
                                self.result["passkey"]["implementation"]["user_verification"] = auth_sel["userVerification"]
                            if auth_sel.get("authenticatorAttachment"):
                                self.result["passkey"]["implementation"]["authenticator_attachment"] = auth_sel["authenticatorAttachment"]
                            if auth_sel.get("residentKey"):
                                self.result["passkey"]["implementation"]["resident_key"] = auth_sel["residentKey"]
                            
                            # Check for conditional mediation
                            if get_opts.get("mediation") == "conditional":
                                self.result["passkey"]["implementation"]["conditional_mediation"] = True
                        
                        # Store artifacts
                        if self.artifacts_config.get("store_passkey_screenshot"):
                            try:
                                screenshot = PlaywrightHelper.take_screenshot(page)
                                self.result["passkey"]["artifacts"]["screenshot"] = screenshot
                            except Exception as e:
                                logger.debug(f"Error taking screenshot: {e}")
                        
                        if self.artifacts_config.get("store_passkey_har") and har_file:
                            try:
                                self.result["passkey"]["artifacts"]["har"] = PlaywrightHelper.take_har(har)
                            except Exception as e:
                                logger.debug(f"Error storing HAR: {e}")
                        
                        return
                    
                except (TimeoutError, Error) as e:
                    logger.warning(f"Error analyzing {lpc_url}: {e}")
                    continue
            
            if not self.result["passkey"]["detected"]:
                logger.info("No passkey detected on any login page")


