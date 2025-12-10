import logging
import traceback
from typing import Dict, Any
from playwright.sync_api import Page

logger = logging.getLogger(__name__)


class PasswordMechanism:
    
    def __init__(self, page: Page):
        self.page = page
        self.url = None
        
    def detect(self, url: str) -> Dict[str, Any]:
        self.url = url
        logger.info(f"Detecting password-based authentication on: {url}")
        
        result = {
            "mechanism": "password",
            "detected": False,
            "has_username": False,
            "has_password": False,
            "has_submit": False,
            "confidence": "NONE",
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
        
        form_check = self._check_password_form_detailed()
        
        result["has_username"] = form_check["has_username"]
        result["has_password"] = form_check["has_password"]
        result["has_submit"] = form_check["has_submit"]
        
        if form_check.get("element_info"):
            el_info = form_check["element_info"]
            result["element_coordinates_x"] = el_info.get("x")
            result["element_coordinates_y"] = el_info.get("y")
            result["element_width"] = el_info.get("width")
            result["element_height"] = el_info.get("height")
            result["element_inner_text"] = el_info.get("inner_text")
            result["element_outer_html"] = el_info.get("outer_html")
            result["element_tree"] = el_info.get("element_tree", [])
            result["element_validity"] = "HIGH"
        
        # More lenient detection - if we find password OR username field, consider it detected
        # (some sites show username first, then password on next step)
        if form_check["has_username"] and form_check["has_password"]:
            result["detected"] = True
            result["confidence"] = "HIGH" if form_check["has_submit"] else "MEDIUM"
        elif form_check["has_password"]:
            # Some sites only show password field (username might be on previous step)
            result["detected"] = True
            result["confidence"] = "MEDIUM"
        elif form_check["has_username"]:
            # Some sites show username first, then password on next step
            # Check if this looks like a login page (has submit button or login context)
            if form_check["has_submit"] or "/login" in self.url.lower() or "/signin" in self.url.lower():
                result["detected"] = True
                result["confidence"] = "MEDIUM"
        
        return result
    
    def _check_password_form(self) -> Dict[str, bool]:
        try:
            return self.page.evaluate('''
                () => {
                    const usernameInputs = document.querySelectorAll(
                        'input[type="text"][name*="user" i], input[type="email"], input[autocomplete="username"], input[autocomplete="email"]'
                    );
                    
                    const passwordInputs = document.querySelectorAll('input[type="password"]');
                    
                    const submitButtons = document.querySelectorAll(
                        'button[type="submit"], input[type="submit"]'
                    );
                    
                    return {
                        has_username: usernameInputs.length > 0,
                        has_password: passwordInputs.length > 0,
                        has_submit: submitButtons.length > 0
                    };
                }
            ''')
        except Exception as e:
            logger.error(f"Error checking password form: {e}")
            return {"has_username": False, "has_password": False, "has_submit": False}
    
    def _check_password_form_detailed(self) -> Dict[str, Any]:
        try:
            from common.modules.helper.detection import DetectionHelper
            
            # Wait for page to be ready and for input fields to appear
            try:
                self.page.wait_for_load_state("domcontentloaded", timeout=5000)
            except:
                pass
            
            # Wait for password or email inputs to appear (for dynamic pages)
            try:
                self.page.wait_for_selector('input[type="password"], input[type="email"], input[type="text"]', timeout=10000, state="attached")
            except:
                pass
            
            # Additional wait for dynamic content
            import time
            time.sleep(2)
            
            result = self.page.evaluate('''
                () => {
                    // More comprehensive selectors matching passkey-crawler
                    // Try all possible username/email selectors
                    const allInputs = Array.from(document.querySelectorAll('input'));
                    
                    const usernameInputs = allInputs.filter(input => {
                        const type = (input.type || '').toLowerCase();
                        const name = (input.name || '').toLowerCase();
                        const id = (input.id || '').toLowerCase();
                        const placeholder = (input.placeholder || '').toLowerCase();
                        const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
                        const ariaLabel = (input.getAttribute('aria-label') || '').toLowerCase();
                        
                        const isUsernameField = (
                            type === 'email' ||
                            type === 'text' && (
                                name.includes('user') || name.includes('email') || name.includes('login') ||
                                id.includes('user') || id.includes('email') || id.includes('login') ||
                                placeholder.includes('username') || placeholder.includes('email') ||
                                autocomplete === 'username' || autocomplete === 'email' ||
                                ariaLabel.includes('username') || ariaLabel.includes('email')
                            )
                        );
                        
                        if (!isUsernameField) return false;
                        
                        // Filter out hidden inputs
                        const rect = input.getBoundingClientRect();
                        const style = window.getComputedStyle(input);
                        return rect.width > 0 && rect.height > 0 && 
                               style.display !== 'none' && 
                               style.visibility !== 'hidden' &&
                               style.opacity !== '0';
                    });
                    
                    const passwordInputs = allInputs.filter(input => {
                        const type = (input.type || '').toLowerCase();
                        if (type !== 'password') return false;
                        
                        // Filter out hidden inputs
                        const rect = input.getBoundingClientRect();
                        const style = window.getComputedStyle(input);
                        return rect.width > 0 && rect.height > 0 && 
                               style.display !== 'none' && 
                               style.visibility !== 'hidden' &&
                               style.opacity !== '0';
                    });
                    
                    const submitButtons = Array.from(document.querySelectorAll(
                        'button[type="submit"], ' +
                        'input[type="submit"], ' +
                        'button[type="button"], ' +
                        'button'
                    )).filter(btn => {
                        const text = (btn.innerText || btn.value || btn.getAttribute("aria-label") || "").toLowerCase();
                        const type = (btn.type || '').toLowerCase();
                        return (
                            type === 'submit' ||
                            /sign.?in|log.?in|login|continue|submit|enter|next/i.test(text)
                        );
                    });
                    
                    const has_username = usernameInputs.length > 0;
                    const has_password = passwordInputs.length > 0;
                    const has_submit = submitButtons.length > 0;
                    
                    let element_info = null;
                    if (has_password && passwordInputs.length > 0) {
                        const input = passwordInputs[0];
                        const rect = input.getBoundingClientRect();
                        if (rect.width > 0 && rect.height > 0) {
                            element_info = {
                                x: rect.x,
                                y: rect.y,
                                width: rect.width,
                                height: rect.height,
                                inner_text: input.value || input.placeholder || '',
                                outer_html: input.outerHTML
                            };
                        }
                    } else if (has_username && usernameInputs.length > 0) {
                        // If no password field but username field exists, use that
                        const input = usernameInputs[0];
                        const rect = input.getBoundingClientRect();
                        if (rect.width > 0 && rect.height > 0) {
                            element_info = {
                                x: rect.x,
                                y: rect.y,
                                width: rect.width,
                                height: rect.height,
                                inner_text: input.value || input.placeholder || '',
                                outer_html: input.outerHTML
                            };
                        }
                    }
                    
                    return {
                        has_username: has_username,
                        has_password: has_password,
                        has_submit: has_submit,
                        element_info: element_info
                    };
                }
            ''')
            
            if result.get("element_info"):
                el_info = result["element_info"]
                x = el_info["x"] + el_info["width"] / 2
                y = el_info["y"] + el_info["height"] / 2
                element_tree, _ = DetectionHelper.get_coordinate_metadata(self.page, x, y)
                result["element_info"]["element_tree"] = element_tree
            
            return result
        except Exception as e:
            logger.error(f"Error checking password form: {e}")
            logger.debug(traceback.format_exc())
            return {"has_username": False, "has_password": False, "has_submit": False}


