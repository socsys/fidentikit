"""
PasswordMechanism - Password-Based Authentication Detection
Detects username/email and password input fields with support for:
- Traditional single-page login forms
- Multi-step login flows (username first, then password)
- Dynamic JavaScript-rendered forms
"""

import logging
import time
from typing import Dict, Any, Optional
from playwright.sync_api import Page

logger = logging.getLogger(__name__)


class PasswordMechanism:
    """
    Comprehensive password-based authentication detection.
    Supports both traditional forms and multi-step login flows.
    """
    
    def __init__(self, page: Page):
        self.page = page
        self.url = None
        
        # Username/email field selectors
        self.username_selectors = [
            # Explicit email type
            'input[type="email"]',
            # Explicit autocomplete
            'input[autocomplete="username"]',
            'input[autocomplete="email"]',
            # Name-based
            'input[name="username" i]',
            'input[name="email" i]',
            'input[name="user" i]',
            'input[name="login" i]',
            'input[name="loginId" i]',
            'input[name="userId" i]',
            'input[name="userEmail" i]',
            'input[name="account" i]',
            # ID-based
            'input[id*="username" i]',
            'input[id*="email" i]',
            'input[id*="user" i]',
            'input[id*="login" i]',
            # Placeholder-based
            'input[type="text"][placeholder*="email" i]',
            'input[type="text"][placeholder*="username" i]',
            'input[type="text"][placeholder*="user" i]',
            # ARIA-based
            'input[aria-label*="email" i]',
            'input[aria-label*="username" i]',
        ]
        
        # Password field selectors
        self.password_selectors = [
            'input[type="password"]',
            'input[autocomplete="current-password"]',
            'input[autocomplete="new-password"]',
            'input[name="password" i]',
            'input[name="passwd" i]',
            'input[name="pwd" i]',
            'input[id*="password" i]',
        ]
        
        # Submit button selectors
        self.submit_selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button[type="button"]',
            'button:not([type])',
            '[role="button"]',
        ]
        
        # Submit button text patterns
        self.submit_text_patterns = [
            r"sign\s*in",
            r"log\s*in",
            r"login",
            r"continue",
            r"submit",
            r"next",
            r"enter",
            r"go",
        ]
        
        # URL patterns indicating login context
        self.login_url_patterns = [
            r"/login",
            r"/signin",
            r"/sign-in",
            r"/auth",
            r"/account",
            r"/sso",
            r"/session",
        ]

    def detect(self, url: str) -> Dict[str, Any]:
        """
        Detect password-based authentication on the page.
        Returns structured result compatible with landscape analysis.
        """
        self.url = url
        logger.info(f"Detecting password-based authentication on: {url}")
        
        result = {
            "mechanism": "password",
            "detected": False,
            "has_username": False,
            "has_password": False,
            "has_submit": False,
            "login_flow_type": None,  # "single_page", "multi_step", "username_only", "password_only"
            "confidence": "NONE",
            "indicators": [],
            "login_page_url": url,
            "element_coordinates_x": None,
            "element_coordinates_y": None,
            "element_width": None,
            "element_height": None,
            "element_inner_text": None,
            "element_outer_html": None,
            "element_tree": [],
            "element_validity": "NONE"
        }
        
        # Wait for page to be ready
        self._wait_for_page_ready()
        
        # Detect form elements
        form_result = self._detect_form_elements()
        
        result["has_username"] = form_result["has_username"]
        result["has_password"] = form_result["has_password"]
        result["has_submit"] = form_result["has_submit"]
        
        # Update element info if available
        if form_result.get("element_info"):
            self._update_element_info(result, form_result["element_info"])
        
        # Check URL for login context
        is_login_url = self._is_login_url(url)
        
        # Determine detection and confidence
        if form_result["has_username"] and form_result["has_password"]:
            # Traditional single-page login
            result["detected"] = True
            result["login_flow_type"] = "single_page"
            result["indicators"].append("Username and password fields")
            
            if form_result["has_submit"]:
                result["confidence"] = "HIGH"
                result["indicators"].append("Submit button present")
            elif is_login_url:
                result["confidence"] = "HIGH"
                result["indicators"].append("Login URL pattern")
            else:
                result["confidence"] = "MEDIUM"
        
        elif form_result["has_password"]:
            # Password-only (username might be on previous step)
            result["detected"] = True
            result["login_flow_type"] = "password_only"
            result["indicators"].append("Password field (multi-step flow)")
            result["confidence"] = "HIGH" if is_login_url else "MEDIUM"
        
        elif form_result["has_username"]:
            # Username-only (password might be on next step)
            if form_result["has_submit"] or is_login_url:
                result["detected"] = True
                result["login_flow_type"] = "multi_step"
                result["indicators"].append("Username field (multi-step flow)")
                result["confidence"] = "MEDIUM"
        
        logger.info(f"Password detection result: detected={result['detected']}, type={result['login_flow_type']}, confidence={result['confidence']}")
        return result

    def _wait_for_page_ready(self):
        """Wait for page to be ready for detection."""
        try:
            self.page.wait_for_load_state("domcontentloaded", timeout=5000)
        except:
            pass
        
        # Wait for input fields to appear
        try:
            self.page.wait_for_selector('input[type="password"], input[type="email"], input[type="text"]', timeout=5000, state="attached")
        except:
            pass
        
        time.sleep(1)

    def _detect_form_elements(self) -> Dict[str, Any]:
        """Detect username, password, and submit elements."""
        try:
            from common.modules.helper.detection import DetectionHelper
            
            result = self.page.evaluate('''
                (config) => {
                    const { usernameSelectors, passwordSelectors, submitSelectors, submitTextPatterns } = config;
                    
                    const isVisible = (el) => {
                        if (!el) return false;
                        const rect = el.getBoundingClientRect();
                        const style = window.getComputedStyle(el);
                        return rect.width > 0 && rect.height > 0 && 
                               style.display !== 'none' && 
                               style.visibility !== 'hidden' &&
                               style.opacity !== '0';
                    };
                    
                    // Find username/email inputs
                    let usernameInputs = [];
                    for (const selector of usernameSelectors) {
                        try {
                            const elements = Array.from(document.querySelectorAll(selector));
                            usernameInputs.push(...elements.filter(el => isVisible(el)));
                        } catch (e) {}
                    }
                    // Deduplicate
                    usernameInputs = [...new Set(usernameInputs)];
                    
                    // Find password inputs
                    let passwordInputs = [];
                    for (const selector of passwordSelectors) {
                        try {
                            const elements = Array.from(document.querySelectorAll(selector));
                            passwordInputs.push(...elements.filter(el => isVisible(el)));
                        } catch (e) {}
                    }
                    passwordInputs = [...new Set(passwordInputs)];
                    
                    // Find submit buttons
                    let submitButtons = [];
                    for (const selector of submitSelectors) {
                        try {
                            const elements = Array.from(document.querySelectorAll(selector));
                            for (const el of elements) {
                                if (!isVisible(el)) continue;
                                
                                const text = (el.innerText || el.value || el.getAttribute("aria-label") || "").toLowerCase();
                                const type = (el.type || "").toLowerCase();
                                
                                // Check if submit type or matches text pattern
                                if (type === "submit") {
                                    submitButtons.push(el);
                                } else {
                                    for (const pattern of submitTextPatterns) {
                                        if (new RegExp(pattern, 'i').test(text)) {
                                            submitButtons.push(el);
                                            break;
                                        }
                                    }
                                }
                            }
                        } catch (e) {}
                    }
                    submitButtons = [...new Set(submitButtons)];
                    
                    // Get element info for the most relevant input
                    let element_info = null;
                    const primaryInput = passwordInputs[0] || usernameInputs[0];
                    
                    if (primaryInput) {
                        const rect = primaryInput.getBoundingClientRect();
                        element_info = {
                            x: rect.x,
                            y: rect.y,
                            width: rect.width,
                            height: rect.height,
                            inner_text: primaryInput.value || primaryInput.placeholder || '',
                            outer_html: primaryInput.outerHTML.substring(0, 500)
                        };
                    }
                    
                    return {
                        has_username: usernameInputs.length > 0,
                        has_password: passwordInputs.length > 0,
                        has_submit: submitButtons.length > 0,
                        username_count: usernameInputs.length,
                        password_count: passwordInputs.length,
                        submit_count: submitButtons.length,
                        element_info: element_info
                    };
                }
            ''', {
                "usernameSelectors": self.username_selectors,
                "passwordSelectors": self.password_selectors,
                "submitSelectors": self.submit_selectors,
                "submitTextPatterns": self.submit_text_patterns
            })
            
            # Get element tree for coordinates
            if result.get("element_info"):
                el_info = result["element_info"]
                x = el_info["x"] + el_info["width"] / 2
                y = el_info["y"] + el_info["height"] / 2
                try:
                    element_tree, _ = DetectionHelper.get_coordinate_metadata(self.page, x, y)
                    result["element_info"]["element_tree"] = element_tree
                except:
                    result["element_info"]["element_tree"] = []
            
            return result
            
        except Exception as e:
            logger.error(f"Error detecting form elements: {e}")
            return {
                "has_username": False,
                "has_password": False,
                "has_submit": False,
                "element_info": None
            }

    def _is_login_url(self, url: str) -> bool:
        """Check if URL indicates a login page."""
        import re
        url_lower = url.lower()
        
        for pattern in self.login_url_patterns:
            if re.search(pattern, url_lower):
                return True
        
        return False

    def _update_element_info(self, result: Dict, element_info: Dict):
        """Update result with element information."""
        if element_info:
            result["element_coordinates_x"] = element_info.get("x")
            result["element_coordinates_y"] = element_info.get("y")
            result["element_width"] = element_info.get("width")
            result["element_height"] = element_info.get("height")
            result["element_inner_text"] = element_info.get("inner_text")
            result["element_outer_html"] = element_info.get("outer_html")
            result["element_tree"] = element_info.get("element_tree", [])
            result["element_validity"] = "HIGH"
