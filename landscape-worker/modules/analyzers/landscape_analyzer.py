import logging
import time
import traceback
from copy import deepcopy
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, Error, TimeoutError
from common.modules.browser.browser import PlaywrightBrowser, PlaywrightHelper
from common.modules.helper.tmp import TmpHelper
from common.modules.helper.detection import DetectionHelper
from common.modules.helper.url import URLHelper
from common.modules.loginpagedetection.paths import Paths
from common.modules.loginpagedetection.sitemap import Sitemap
from common.modules.loginpagedetection.robots import Robots
from common.modules.loginpagedetection.searxng import Searxng
from common.modules.loginpagedetection.crawling import Crawling
import sys
sys.path.insert(0, '/app')
sys.path.insert(0, '/app/landscape-worker')

from common.modules.auth_mechanisms import PasskeyMechanism, MFAMechanism, PasswordMechanism
from common.modules.idps import SSODetector
from common.modules.detectors.metadata import MetadataDetector
from common.modules.detectors.lastpass_icon import LastpassIconDetector
from config.idp_rules import IdpRules

logger = logging.getLogger(__name__)


class LandscapeAnalyzer:

    def __init__(self, domain: str, config: dict):
        self.domain = domain
        self.config = config
        self.browser_config = config.get("browser_config", {})
        self.artifacts_config = config.get("artifacts_config", {})
        login_page_config = config.get("login_page_config", {})
        self.login_page_url_regexes = login_page_config.get("login_page_url_regexes", [])
        self.login_page_strategy_scope = login_page_config.get("login_page_strategy_scope", ["PATHS", "HOMEPAGE"])

        self.result = {
            "resolved": {},
            "timings": {},
            "login_page_candidates": [],
            "authentication_mechanisms": {
                "passkey": [],
                "mfa": [],
                "password": []
            },
            "identity_providers": []
        }
        # Internal tracking for LastPass detection (not included in final result)
        self._lastpass_icons = []

    def start(self) -> dict:
        logger.info(f"Starting landscape analysis for: {self.domain}")

        ttotal = time.time()

        t = time.time()
        self.resolve()
        self.result["timings"]["resolve_duration_seconds"] = time.time() - t

        if self.result["resolved"]["reachable"]:
            t = time.time()
            self.login_page_detection()
            self.result["timings"]["login_page_detection_duration_seconds"] = time.time() - t

            t = time.time()
            self.analyze_authentication()
            self.result["timings"]["authentication_analysis_duration_seconds"] = time.time() - t

            t = time.time()
            self.detect_metadata()
            self.result["timings"]["metadata_detection_duration_seconds"] = time.time() - t

        self.result["timings"]["total_duration_seconds"] = time.time() - ttotal

        # Remove internal tracking fields before returning
        if hasattr(self, "_lastpass_icons"):
            del self._lastpass_icons

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

    def analyze_authentication(self):
        logger.info("Starting authentication mechanism analysis")
        
        # First pass: detect authentication mechanisms on each login page
        with TmpHelper.tmp_dir() as pdir, sync_playwright() as pw:
            context, page = PlaywrightBrowser.instance(pw, self.browser_config, pdir)

            passkey_detector = PasskeyMechanism(page, self.config, self.result["resolved"].get("domain"))
            mfa_detector = MFAMechanism(page)
            password_detector = PasswordMechanism(page)
            
            for lpc_url, lpc_idxs in DetectionHelper.get_lpcs_with_idxs(self.result["login_page_candidates"]):
                logger.info(f"Analyzing authentication mechanisms on: {lpc_url}")

                try:
                    PlaywrightHelper.navigate(page, lpc_url, self.browser_config)
                    # Wait for page to be fully loaded (like passkey-crawler)
                    try:
                        page.wait_for_load_state("networkidle", timeout=10000)
                    except:
                        pass
                    PlaywrightHelper.sleep(page, 5)  # Increased wait time like passkey-crawler
                    
                    # Check if page is analyzable before proceeding
                    analyzable, reason = PlaywrightHelper.get_content_analyzable(page)
                    if not analyzable:
                        logger.warning(f"Page not analyzable: {reason}")
                        for i in lpc_idxs:
                            self.result["login_page_candidates"][i]["resolved"] = {
                                "reachable": True,
                                "url": page.url,
                                "title": page.title(),
                                "analyzable": False,
                                "reason": reason
                            }
                        continue
                    
                    for i in lpc_idxs:
                        self.result["login_page_candidates"][i]["resolved"] = {
                            "reachable": True,
                            "url": page.url,
                            "title": page.title()
                        }

                    # Detect authentication mechanisms on main page first
                    password_result = None
                    lastpass_found = False
                    
                    # Additional wait for dynamic content (especially for Google, Zoom, etc.)
                    try:
                        # Wait for any input fields to appear
                        page.wait_for_selector('input[type="password"], input[type="email"], input[type="text"]', timeout=10000, state="attached")
                    except:
                        pass
                    
                    # Passkey detection
                    try:
                        passkey_result = passkey_detector.detect_full(lpc_url)
                        logger.info(f"Passkey detection result for {lpc_url}: detected={passkey_result.get('detected')}, webauthn_api={passkey_result.get('webauthn_api_available')}")
                        if passkey_result.get("detected"):
                            passkey_result["login_page_url"] = lpc_url
                            self.result["authentication_mechanisms"]["passkey"].append(passkey_result)
                    except Exception as e:
                        logger.warning(f"Error in passkey detection for {lpc_url}: {e}")
                        logger.debug(traceback.format_exc())
                    
                    # MFA detection
                    try:
                        mfa_result = mfa_detector.detect(lpc_url)
                        logger.info(f"MFA detection result for {lpc_url}: detected={mfa_result.get('detected')}, signals={len(mfa_result.get('indicators', []))}")
                        if mfa_result.get("detected"):
                            mfa_result["login_page_url"] = lpc_url
                            self.result["authentication_mechanisms"]["mfa"].append(mfa_result)
                    except Exception as e:
                        logger.warning(f"Error in MFA detection for {lpc_url}: {e}")
                        logger.debug(traceback.format_exc())
                    
                    # Password detection
                    try:
                        password_result = password_detector.detect(lpc_url)
                        logger.info(f"Password detection result for {lpc_url}: detected={password_result.get('detected')}, has_username={password_result.get('has_username')}, has_password={password_result.get('has_password')}, has_submit={password_result.get('has_submit')}")
                    except Exception as e:
                        logger.warning(f"Error in password detection for {lpc_url}: {e}")
                        logger.debug(traceback.format_exc())
                        password_result = None
                    
                    # LastPass icon detection (check all frames) - always run
                    for j, frame in enumerate(page.frames):
                        try:
                            valid, error = PlaywrightHelper.get_content_analyzable(frame)
                            if valid:
                                # Use temporary result dict for LastPass detection
                                temp_result = {"recognized_lastpass_icons": self._lastpass_icons}
                                LastpassIconDetector(self.config, temp_result).start(lpc_url, j, frame)
                                # Check if LastPass icons were found for this URL
                                lastpass_icons_for_url = [
                                    icon for icon in self._lastpass_icons 
                                    if icon.get("login_page_url") == lpc_url
                                ]
                                if lastpass_icons_for_url:
                                    lastpass_found = True
                        except Exception as e:
                            logger.warning(f"Error detecting LastPass icons in frame {j}: {e}")
                    
                    # Add LastPass detection to password result
                    if lastpass_found:
                        if password_result is None:
                            password_result = {
                                "mechanism": "password",
                                "detected": False,
                                "has_username": False,
                                "has_password": False,
                                "has_submit": False,
                                "confidence": "NONE",
                                "login_page_url": lpc_url
                            }
                        password_result["lastpass_detected"] = True
                        password_result["lastpass_icons"] = [
                            icon for icon in self._lastpass_icons 
                            if icon.get("login_page_url") == lpc_url
                        ]
                    
                    # Add password result if detected or LastPass found
                    if password_result and (password_result.get("detected") or lastpass_found):
                        password_result["login_page_url"] = lpc_url
                        if not password_result.get("detected") and lastpass_found:
                            # If only LastPass found, still mark as password detected
                            password_result["detected"] = True
                            password_result["confidence"] = "MEDIUM"
                        self.result["authentication_mechanisms"]["password"].append(password_result)

                except Exception as e:
                    error_msg = str(e)
                    logger.warning(f"Error analyzing {lpc_url}: {error_msg}")
                    logger.debug(traceback.format_exc())
                    for i in lpc_idxs:
                        self.result["login_page_candidates"][i]["resolved"] = {
                            "reachable": False,
                            "error": error_msg
                        }
        
        # Second pass: detect IDPs - open separate browser session for each IDP (like passkey-crawler)
        idp_scope = self.config.get("idp_config", {}).get("idp_scope", [])
        config_with_domain = {**self.config, "domain": self.domain}

        # Get reachable login page candidates
        reachable_lpcs = [
            lpc["login_page_candidate"] for lpc in self.result["login_page_candidates"]
            if lpc.get("resolved", {}).get("reachable", False)
        ]
        
        for lpc_url in reachable_lpcs:
            logger.info(f"Detecting IDPs on: {lpc_url}")
            
            for idp_name in idp_scope:
                if idp_name not in IdpRules:
                    continue
                
                logger.info(f"Detecting {idp_name} on {lpc_url}")
                
                # Open separate browser session for each IDP (like passkey-crawler)
                with TmpHelper.tmp_dir() as pdir, sync_playwright() as pw:
                    context, page = PlaywrightBrowser.instance(pw, self.browser_config, pdir)
                    
                    try:
                        PlaywrightHelper.navigate(page, lpc_url, self.browser_config)
                        PlaywrightHelper.sleep(page, 3)
                        
                        # Check if page is analyzable
                        analyzable, reason = PlaywrightHelper.get_content_analyzable(page)
                        if not analyzable:
                            logger.warning(f"Page not analyzable for {idp_name}: {reason}")
                            continue

                        # Detect this IDP
                        sso_detector = SSODetector(page, config_with_domain, IdpRules)
                        detection = sso_detector._detect_idp_detailed(lpc_url, idp_name, IdpRules[idp_name])
                        
                        if detection:
                            logger.info(f"Found {idp_name} on {lpc_url}")
                            self.result["identity_providers"].append(detection)
                        else:
                            logger.debug(f"No {idp_name} found on {lpc_url}")
                    
                    except Exception as e:
                        logger.warning(f"Error detecting {idp_name} on {lpc_url}: {e}")
                        logger.debug(traceback.format_exc())
                    finally:
                        try:
                            PlaywrightHelper.close_context(context)
                        except:
                            pass
    
    def detect_metadata(self):
        logger.info("Starting metadata detection")
        MetadataDetector(self.config, self.result).start()
