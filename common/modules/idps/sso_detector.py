import logging
import time
import uuid
from typing import List, Dict, Any, Optional
from playwright.sync_api import Page, Frame, TimeoutError, Error
from common.modules.locators.css import CSSLocator
from common.modules.helper.locator import LocatorHelper
from common.modules.helper.detection import DetectionHelper
from common.modules.helper.sso_interceptor import SSOInterceptorHelper
from common.modules.browser.browser import PlaywrightHelper
from common.modules.helper.url import URLHelper

logger = logging.getLogger(__name__)


class SSODetector:
    
    def __init__(self, page: Page, config: dict, idp_patterns: dict):
        self.page = page
        self.config = config
        self.idp_patterns = idp_patterns
        self.browser_config = config.get("browser_config", {})
        self.artifacts_config = config.get("artifacts_config", {})
        keyword_recognition_config = config.get("keyword_recognition_config", {})
        self.keywords = keyword_recognition_config.get("keywords", [])
        self.max_elements_to_click = keyword_recognition_config.get("max_elements_to_click", 3)
        
        # Default keywords if none provided
        if not self.keywords:
            self.keywords = [
                "login with %s",
                "sign in with %s",
                "continue with %s",
                "use %s"
            ]
        
    def detect_all(self, url: str, idp_scope: List[str]) -> List[Dict[str, Any]]:
        logger.info(f"Detecting SSO providers on: {url}")
        
        detected_idps = []
        
        for idp_name in idp_scope:
            if idp_name not in self.idp_patterns:
                continue
                
            idp_config = self.idp_patterns[idp_name]
            
            detection = self._detect_idp_detailed(url, idp_name, idp_config)
            if detection:
                detected_idps.append(detection)
        
        return detected_idps
    
    def _detect_idp_detailed(self, url: str, idp_name: str, idp_config: dict) -> Optional[Dict[str, Any]]:
        logger.info(f"Detecting {idp_name} on: {url}")
        
        t_start = time.time()
        
        idp_keywords = idp_config.get("keywords", [])
        if not idp_keywords:
            return None
        
        # Generate keyword patterns by replacing %s with the IDP keyword
        keyword_patterns = [kw.replace("%s", idp_keywords[0].lower()) for kw in self.keywords if kw]
        
        # Ensure we have at least the IDP keyword itself
        search_keywords = [idp_keywords[0].lower()]
        if not keyword_patterns:
            keyword_patterns = search_keywords
        
        css_locator = CSSLocator(keywords=search_keywords, high_validity_patterns=keyword_patterns)
        
        element_candidates = css_locator.locate(self.page, high_validity=True)
        
        if not element_candidates:
            element_candidates = css_locator.locate(self.page, high_validity=False)
        
        # Also try direct text search for IDP name in buttons/links
        if not element_candidates:
            try:
                direct_search = self.page.evaluate(f'''
                    () => {{
                        const idpName = "{idp_keywords[0].toLowerCase()}";
                        const buttons = Array.from(document.querySelectorAll(
                            'button, a, [role="button"], input[type="button"], input[type="submit"]'
                        ));
                        const matches = buttons.filter(el => {{
                            const text = (el.innerText || el.value || el.getAttribute("aria-label") || "").toLowerCase();
                            return text.includes(idpName) && 
                                   (text.includes("sign") || text.includes("login") || text.includes("continue") || text.includes("use"));
                        }});
                        return matches.length > 0;
                    }}
                ''')
                if not direct_search:
                    logger.info(f"No {idp_name} elements found")
                    return None
                # If found via direct search, try to get element info
                element_info = self.page.evaluate(f'''
                    () => {{
                        const idpName = "{idp_keywords[0].toLowerCase()}";
                        const buttons = Array.from(document.querySelectorAll(
                            'button, a, [role="button"], input[type="button"], input[type="submit"]'
                        ));
                        const match = buttons.find(el => {{
                            const text = (el.innerText || el.value || el.getAttribute("aria-label") || "").toLowerCase();
                            return text.includes(idpName) && 
                                   (text.includes("sign") || text.includes("login") || text.includes("continue") || text.includes("use"));
                        }});
                        if (!match) return null;
                        const rect = match.getBoundingClientRect();
                        return {{
                            x: rect.x,
                            y: rect.y,
                            width: rect.width,
                            height: rect.height,
                            inner_text: match.innerText || match.value || match.getAttribute("aria-label") || "",
                            outer_html: match.outerHTML
                        }};
                    }}
                ''')
                if element_info:
                    element_candidates = [element_info]
            except Exception as e:
                logger.warning(f"Error in direct IDP search: {e}")
        
        if not element_candidates:
            logger.info(f"No {idp_name} elements found")
            return None
        
        logger.info(f"Found {len(element_candidates)} {idp_name} element candidates")
        
        for i, element_info in enumerate(element_candidates[:self.max_elements_to_click]):
            logger.info(f"Processing {idp_name} element candidate {i+1} of {len(element_candidates)}")
            
            detection_result = self._process_element_candidate(
                url, idp_name, idp_config, element_info, i+1, len(element_candidates)
            )
            
            if detection_result:
                detection_result["keyword_recognition_duration_seconds"] = time.time() - t_start
                return detection_result
        
        return None
    
    def _process_element_candidate(
        self, 
        url: str, 
        idp_name: str, 
        idp_config: dict,
        element_info: dict,
        hit_number: int,
        total_candidates: int
    ) -> Optional[Dict[str, Any]]:
        
        x = element_info.get("x", 0) + element_info.get("width", 0) / 2
        y = element_info.get("y", 0) + element_info.get("height", 0) / 2
        
        element_tree, element_tree_markup = DetectionHelper.get_coordinate_metadata(self.page, x, y)
        
        # Filter out false positives (social media links that aren't login buttons)
        inner_text_lower = (element_info.get("inner_text") or "").lower()
        outer_html_lower = (element_info.get("outer_html") or "").lower()
        
        # Skip if it's clearly a social media link (has target="_blank" or rel="noopener")
        # But allow if it has login/sign in context
        is_social_link = "target=\"_blank\"" in outer_html_lower or "rel=\"noopener\"" in outer_html_lower or "rel='noopener'" in outer_html_lower
        has_login_context = any(word in inner_text_lower for word in ["sign", "login", "continue", "use", "with"])
        
        if is_social_link and not has_login_context:
            logger.info(f"Skipping {idp_name} element - appears to be social media link, not login button")
            return None
        
        result = {
            "idp_name": idp_name,
            "login_page_url": url,
            "element_coordinates_x": element_info.get("x"),
            "element_coordinates_y": element_info.get("y"),
            "element_width": element_info.get("width"),
            "element_height": element_info.get("height"),
            "element_inner_text": element_info.get("inner_text", ""),
            "element_outer_html": element_info.get("outer_html", ""),
            "element_tree": element_tree,
            "recognition_strategy": "KEYWORD",
            "keyword_recognition_locator_mode": "CSS",
            "keyword_recognition_candidates": total_candidates,
            "keyword_recognition_hit_number_clicks": hit_number,
            "keyword_recognition_hit_keyword": element_info.get("inner_text", "")[:100] if element_info.get("inner_text") else "",
            "element_validity": "HIGH" if element_info.get("inner_text") else "MEDIUM"
        }
        
        if self.artifacts_config.get("store_sso_button_detection_screenshot"):
            try:
                screenshot = PlaywrightHelper.take_screenshot(self.page)
                result["keyword_recognition_screenshot"] = screenshot
            except Exception as e:
                logger.warning(f"Error taking keyword recognition screenshot: {e}")
        
        if element_tree_markup:
            try:
                import json
                import base64
                import zlib
                markup_data = json.dumps(element_tree_markup)
                result["element_tree_markup"] = {
                    "type": "reference",
                    "data": {
                        "bucket_name": "element-tree-markup",
                        "object_name": f"/{self.config.get('domain', 'unknown')}/{uuid.uuid4()}.json",
                        "extension": "json"
                    }
                }
            except Exception as e:
                logger.warning(f"Error storing element tree markup: {e}")
        
        idp_frame = "TOPMOST"
        idp_frame_index = 0
        idp_frame_url = self.page.url
        idp_frame_name = ""
        idp_frame_title = self.page.title()
        idp_frames_length = len(self.page.frames)
        
        idp_login_request = None
        idp_integration = None
        
        try:
            sso_interceptor = SSOInterceptorHelper(self.page.context, idp_name)
            sso_interceptor.start_intercept()
            
            pre_click_url = self.page.url
            
            try:
                with self.page.expect_popup(timeout=2000) as page_info:
                    logger.info(f"Clicking on {idp_name} element and waiting for popup")
                    self.page.mouse.click(x, y)
                logger.info("Popup opened after clicking, waiting for popup to load")
                idp_frame = "POPUP"
                popup_page = page_info.value
                PlaywrightHelper.wait_for_page_load(popup_page, self.browser_config)
                idp_frame_url = popup_page.url
                idp_frame_title = popup_page.title()
                
                time.sleep(2)
                
                interceptions = sso_interceptor.get_idp_interceptions()
                idp_login_request = interceptions.get("idp_login_request")
                idp_integration = interceptions.get("idp_integration")
                
                if self.artifacts_config.get("store_idp_screenshot"):
                    try:
                        screenshot = PlaywrightHelper.take_screenshot(popup_page)
                        result["idp_screenshot"] = screenshot
                    except Exception as e:
                        logger.warning(f"Error taking IDP screenshot: {e}")
                
                popup_page.close()
                
            except TimeoutError:
                logger.info("No popup opened, checking for navigation")
                PlaywrightHelper.wait_for_page_load(self.page, self.browser_config)
                time.sleep(2)
                
                if self.page.url != pre_click_url:
                    idp_frame_url = self.page.url
                    idp_frame_title = self.page.title()
                
                interceptions = sso_interceptor.get_idp_interceptions()
                idp_login_request = interceptions.get("idp_login_request")
                idp_integration = interceptions.get("idp_integration")
                
                if self.artifacts_config.get("store_idp_screenshot"):
                    try:
                        screenshot = PlaywrightHelper.take_screenshot(self.page)
                        result["idp_screenshot"] = screenshot
                    except Exception as e:
                        logger.warning(f"Error taking IDP screenshot: {e}")
            
            sso_interceptor.stop_intercept()
            
            if idp_login_request:
                result["idp_login_request"] = idp_login_request
                result["idp_integration"] = idp_integration or "CUSTOM"
            else:
                result["idp_integration"] = "CUSTOM"
            
        except Exception as e:
            logger.warning(f"Error during IDP interaction: {e}")
            result["idp_integration"] = "CUSTOM"
        
        result["idp_frame"] = idp_frame
        result["idp_frame_index"] = idp_frame_index
        result["idp_frame_url"] = idp_frame_url
        result["idp_frame_name"] = idp_frame_name
        result["idp_frame_title"] = idp_frame_title
        result["idp_frames_length"] = idp_frames_length
        
        if self.artifacts_config.get("store_idp_har"):
            try:
                har_file = self.browser_config.get("har_file")
                if har_file:
                    har_data = PlaywrightHelper.take_har(har_file)
                    if har_data:
                        result["idp_har"] = har_data
            except Exception as e:
                logger.warning(f"Error storing IDP HAR: {e}")
        
        return result
