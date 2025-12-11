"""
PasskeyMechanism - Robust passkey detection implementing 43 heuristics across 5 categories
Based on FidentiKit research paper and Passkeys Handbook.

Categories:
1. UI_ELEMENT: Buttons, links, text with passkey-related content
2. DOM_STRUCTURE: Hidden elements, data attributes, autocomplete="webauthn"
3. JS_API: WebAuthn API calls (navigator.credentials.create/get), PublicKeyCredential
4. NETWORK: WebAuthn-related endpoints, passkey API patterns
5. LIBRARY: Known WebAuthn libraries (simplewebauthn, passwordless.id, webauthn-json, etc.)
"""

import logging
import time
import re
from typing import Dict, Any, List, Tuple, Optional
from playwright.sync_api import Page
from common.modules.browser.browser import PlaywrightHelper, CDPSessionManager

logger = logging.getLogger(__name__)


class PasskeyMechanism:
    """
    Comprehensive passkey detection using 5 categories of heuristics.
    Aligned with FidentiKit research methodology.
    """
    
    # Category definitions for structured output
    CATEGORIES = ["UI_ELEMENT", "DOM_STRUCTURE", "JS_API", "NETWORK", "LIBRARY", "ENTERPRISE"]
    
    # Confidence levels
    CONFIDENCE_LEVELS = ["NONE", "LOW", "MEDIUM", "HIGH"]
    
    def __init__(self, page: Page, config: dict = None, site_domain: str = None):
        self.page = page
        self.config = config or {}
        self.site_domain = site_domain
        self.cdp_manager: Optional[CDPSessionManager] = None
        self.url = None
        
        # ===== CATEGORY 1: UI ELEMENT PATTERNS =====
        # Text patterns for buttons/links (case-insensitive)
        self.ui_button_patterns = [
            r"sign\s*in\s*with\s*(?:a\s*)?passkey",
            r"login\s*with\s*(?:a\s*)?passkey",
            r"continue\s*with\s*(?:a\s*)?passkey",
            r"use\s*(?:a\s*)?passkey",
            r"use\s*your\s*passkey",
            r"passkey\s*(?:sign\s*in|login)",
            r"passkey\s*authentication",
            r"sign\s*in\s*without\s*password",
            r"passwordless\s*(?:sign\s*in|login)",
            r"sign\s*in\s*with\s*(?:a\s*)?security\s*key",
            r"use\s*(?:a\s*)?security\s*key",
            r"biometric\s*(?:sign\s*in|login|authentication)",
            r"sign\s*in\s*with\s*face\s*id",
            r"sign\s*in\s*with\s*touch\s*id",
            r"sign\s*in\s*with\s*windows\s*hello",
            r"sign\s*in\s*with\s*fingerprint",
        ]
        
        # ARIA label patterns
        self.aria_patterns = [
            r"passkey",
            r"security\s*key",
            r"webauthn",
            r"fido",
            r"biometric\s*(?:login|sign\s*in|authentication)",
            r"passwordless",
        ]
        
        # ===== CATEGORY 2: DOM STRUCTURE PATTERNS =====
        self.dom_selectors = [
            # Explicit passkey attributes
            '[data-passkey]',
            '[data-webauthn]',
            '[data-credential]',
            '[data-auth-type="passkey"]',
            '[data-auth-method="passkey"]',
            '[data-authentication-method="passkey"]',
            '[data-login-method="passkey"]',
            # Autocomplete for WebAuthn
            'input[autocomplete="webauthn"]',
            'input[autocomplete*="webauthn"]',
            # TestID patterns
            '[data-testid*="passkey" i]',
            '[data-testid*="security-key" i]',
            '[data-testid*="webauthn" i]',
            '[data-test*="passkey" i]',
            # ID/class patterns
            '[id*="passkey" i]',
            '[id*="webauthn" i]',
            '[class*="passkey" i]',
            '[class*="webauthn" i]',
        ]
        
        # ===== CATEGORY 3: JAVASCRIPT API PATTERNS =====
        self.js_api_patterns = [
            # WebAuthn API calls
            (r"navigator\.credentials\.create\s*\(\s*\{[\s\S]*?publicKey", "credentials.create with publicKey", "HIGH"),
            (r"navigator\.credentials\.get\s*\(\s*\{[\s\S]*?publicKey", "credentials.get with publicKey", "HIGH"),
            (r"navigator\.credentials\.create\s*\(", "credentials.create call", "MEDIUM"),
            (r"navigator\.credentials\.get\s*\(", "credentials.get call", "MEDIUM"),
            # PublicKeyCredential checks
            (r"PublicKeyCredential\.isUserVerifyingPlatformAuthenticatorAvailable", "platform authenticator check", "HIGH"),
            (r"PublicKeyCredential\.isConditionalMediationAvailable", "conditional mediation check", "HIGH"),
            (r"PublicKeyCredential\.isExternalCTAP2SecurityKeySupported", "CTAP2 support check", "MEDIUM"),
            (r"typeof\s+PublicKeyCredential", "PublicKeyCredential type check", "MEDIUM"),
            (r"window\.PublicKeyCredential", "PublicKeyCredential reference", "MEDIUM"),
            # Conditional mediation
            (r"mediation\s*:\s*['\"]conditional['\"]", "conditional mediation option", "HIGH"),
            (r"conditionalMediationAvailable", "conditional mediation variable", "MEDIUM"),
            (r"conditionalCreate", "conditional create flow", "MEDIUM"),
            # WebAuthn options
            (r"authenticatorSelection", "authenticator selection", "MEDIUM"),
            (r"residentKey\s*:\s*['\"](?:required|preferred)['\"]", "resident key requirement", "HIGH"),
            (r"userVerification\s*:\s*['\"](?:required|preferred)['\"]", "user verification requirement", "MEDIUM"),
            (r"attestation\s*:\s*['\"]", "attestation setting", "MEDIUM"),
        ]
        
        # ===== CATEGORY 4: NETWORK PATTERNS =====
        self.network_patterns = [
            r"/webauthn",
            r"/passkey",
            r"/fido2?",
            r"/credential",
            r"/attestation",
            r"/assertion",
            r"\.well-known/webauthn",
            r"\.well-known/passkey",
            r"/api/passkey",
            r"/api/webauthn",
            r"/auth/passkey",
            r"/auth/webauthn",
        ]
        
        # ===== CATEGORY 5: LIBRARY PATTERNS =====
        # Known WebAuthn/Passkey libraries
        self.library_patterns = [
            # SimpleWebAuthn
            (r"@simplewebauthn", "SimpleWebAuthn", "HIGH"),
            (r"simplewebauthn", "SimpleWebAuthn", "HIGH"),
            (r"startAuthentication\s*\(", "SimpleWebAuthn startAuthentication", "HIGH"),
            (r"startRegistration\s*\(", "SimpleWebAuthn startRegistration", "HIGH"),
            # Passwordless.ID
            (r"passwordless\.id", "Passwordless.ID", "HIGH"),
            (r"@passwordless-id", "Passwordless.ID", "HIGH"),
            # WebAuthn-json
            (r"webauthn-json", "webauthn-json", "HIGH"),
            (r"@github/webauthn-json", "GitHub webauthn-json", "HIGH"),
            # Hanko
            (r"@hanko", "Hanko", "HIGH"),
            (r"hanko-elements", "Hanko Elements", "HIGH"),
            (r"hanko\.io", "Hanko.io", "HIGH"),
            # Passage by 1Password
            (r"passage\.1password", "Passage by 1Password", "HIGH"),
            (r"@aspect/passage", "Passage", "HIGH"),
            # Corbado
            (r"corbado", "Corbado", "HIGH"),
            # Auth0
            (r"auth0.*webauthn", "Auth0 WebAuthn", "MEDIUM"),
            # Duo
            (r"duo.*webauthn", "Duo WebAuthn", "MEDIUM"),
            # FIDO libraries
            (r"fido-lib", "FIDO library", "MEDIUM"),
            (r"fido2-lib", "FIDO2 library", "MEDIUM"),
            (r"webauthn-framework", "WebAuthn Framework", "MEDIUM"),
        ]
        
        # ===== ENTERPRISE PATTERNS =====
        # Known enterprise implementations with specific selectors
        self.enterprise_patterns = {
            "microsoft": {
                "domains": ["login.microsoft.com", "login.live.com", "account.microsoft.com", "microsoftonline.com"],
                "selectors": [
                    "[data-testid*='passkey']",
                    "[data-testid*='fido']",
                    "[aria-label*='Windows Hello']",
                    "[aria-label*='security key']",
                    "#idBtn_Back",
                    ".win-button",
                ],
                "text_patterns": ["Windows Hello", "Security Key", "FIDO2", "passkey"]
            },
            "google": {
                "domains": ["accounts.google.com"],
                "selectors": [
                    "[data-challengetype='6']",  # Passkey challenge type
                    "[data-primary-action-label*='passkey']",
                    "[data-action-type='sign-in-passkey']",
                ],
                "text_patterns": ["passkey", "Use your passkey", "Security Key"]
            },
            "apple": {
                "domains": ["appleid.apple.com", "id.apple.com"],
                "selectors": [
                    "[data-testid*='passkey']",
                    "[aria-label*='passkey']",
                ],
                "text_patterns": ["passkey", "Face ID", "Touch ID"]
            },
            "github": {
                "domains": ["github.com"],
                "selectors": [
                    "[data-testid='passkey-signin-button']",
                    "[data-login-passkey]",
                    ".js-webauthn-sign-in",
                ],
                "text_patterns": ["passkey", "security key", "Sign in with passkey"]
            },
            "amazon": {
                "domains": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.co.jp"],
                "selectors": [
                    "[data-action='a-button-passkey']",
                    "#auth-signin-passkey-button",
                ],
                "text_patterns": ["passkey", "Sign in with passkey"]
            },
        }
        
        # ===== KEYWORD PATTERNS (for general text search) =====
        self.keyword_patterns = {
            "high_confidence": [
                r"sign\s*in\s*with\s*passkey",
                r"use\s*a?\s*passkey",
                r"continue\s*with\s*passkey",
                r"passkey\s*authentication",
                r"passkey\s*login",
            ],
            "medium_confidence": [
                r"\bpasskey\b",
                r"\bwebauthn\b",
                r"\bfido2?\b",
                r"security\s*key",
                r"passwordless\s*(?:sign.?in|login)",
            ],
            "low_confidence": [
                r"biometric",
                r"fingerprint\s*(?:sign.?in|login)",
                r"face\s*id",
                r"touch\s*id",
                r"windows\s*hello",
            ]
        }

    def detect_full(self, url: str) -> Dict[str, Any]:
        """
        Comprehensive passkey detection using all 5 categories of heuristics.
        Returns structured result compatible with landscape analysis schema.
        """
        self.url = url
        logger.info(f"Starting comprehensive passkey detection on: {url}")
        
        result = {
            "mechanism": "passkey",
            "detected": False,
            "detection_methods": [],  # List of categories that detected passkey
            "confidence": "NONE",
            "indicators": [],  # Human-readable indicators
            "signals": {  # Detailed signals by category
                "UI_ELEMENT": [],
                "DOM_STRUCTURE": [],
                "JS_API": [],
                "NETWORK": [],
                "LIBRARY": [],
                "ENTERPRISE": [],
            },
            "implementation_params": None,
            "webauthn_api_available": False,
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
        
        # Check if WebAuthn API is available
        try:
            webauthn_available = self._check_webauthn_api()
            result["webauthn_api_available"] = webauthn_available
            logger.info(f"WebAuthn API available: {webauthn_available}")
        except Exception as e:
            logger.warning(f"Error checking WebAuthn API: {e}")
            webauthn_available = False
            result["webauthn_api_available"] = False
        
        # Wait for page to be ready
        try:
            self._wait_for_page_ready()
        except Exception as e:
            logger.warning(f"Error waiting for page ready: {e}")
        
        # Try to reveal hidden options (like "Try another way" buttons)
        try:
            self._try_reveal_options()
        except Exception as e:
            logger.debug(f"Error revealing options: {e}")
        
        # Run all detection categories
        category_results = {}
        
        # Category 1: UI Element Detection (most important for visible passkey buttons)
        logger.info("Running UI element detection...")
        try:
            ui_result = self._detect_ui_elements()
            category_results["UI_ELEMENT"] = ui_result
            logger.info(f"UI detection result: found={ui_result.get('found')}, signals={ui_result.get('signals', [])}")
            if ui_result.get("found"):
                result["signals"]["UI_ELEMENT"] = ui_result.get("signals", [])
                result["detection_methods"].append("UI_ELEMENT")
                if ui_result.get("element_info"):
                    self._update_element_info(result, ui_result["element_info"])
        except Exception as e:
            logger.warning(f"UI element detection failed: {e}")
            category_results["UI_ELEMENT"] = {"found": False, "error": str(e)}
        
        # Category 2: DOM Structure Detection
        logger.debug("Running DOM structure detection...")
        try:
            dom_result = self._detect_dom_structure()
            category_results["DOM_STRUCTURE"] = dom_result
            if dom_result.get("found"):
                result["signals"]["DOM_STRUCTURE"] = dom_result.get("signals", [])
                result["detection_methods"].append("DOM_STRUCTURE")
                if not result["element_coordinates_x"] and dom_result.get("element_info"):
                    self._update_element_info(result, dom_result["element_info"])
        except Exception as e:
            logger.warning(f"DOM structure detection failed: {e}")
            category_results["DOM_STRUCTURE"] = {"found": False, "error": str(e)}
        
        # Category 3: JavaScript API Detection
        logger.debug("Running JavaScript API detection...")
        try:
            js_result = self._detect_js_api()
            category_results["JS_API"] = js_result
            if js_result.get("found"):
                result["signals"]["JS_API"] = js_result.get("signals", [])
                result["detection_methods"].append("JS_API")
        except Exception as e:
            logger.warning(f"JavaScript API detection failed: {e}")
            category_results["JS_API"] = {"found": False, "error": str(e)}
        
        # Category 4: Network Pattern Detection
        logger.debug("Running network pattern detection...")
        try:
            network_result = self._detect_network_patterns()
            category_results["NETWORK"] = network_result
            if network_result.get("found"):
                result["signals"]["NETWORK"] = network_result.get("signals", [])
                result["detection_methods"].append("NETWORK")
        except Exception as e:
            logger.warning(f"Network pattern detection failed: {e}")
            category_results["NETWORK"] = {"found": False, "error": str(e)}
        
        # Category 5: Library Detection
        logger.debug("Running library detection...")
        try:
            library_result = self._detect_libraries()
            category_results["LIBRARY"] = library_result
            if library_result.get("found"):
                result["signals"]["LIBRARY"] = library_result.get("signals", [])
                result["detection_methods"].append("LIBRARY")
        except Exception as e:
            logger.warning(f"Library detection failed: {e}")
            category_results["LIBRARY"] = {"found": False, "error": str(e)}
        
        # Enterprise-specific Detection
        logger.debug("Running enterprise detection...")
        try:
            enterprise_result = self._detect_enterprise()
            category_results["ENTERPRISE"] = enterprise_result
            if enterprise_result.get("found"):
                result["signals"]["ENTERPRISE"] = enterprise_result.get("signals", [])
                result["detection_methods"].append("ENTERPRISE")
        except Exception as e:
            logger.warning(f"Enterprise detection failed: {e}")
            category_results["ENTERPRISE"] = {"found": False, "error": str(e)}
        
        # Determine overall detection and confidence
        result["detected"] = len(result["detection_methods"]) > 0
        result["confidence"] = self._calculate_confidence(category_results)
        
        # Build human-readable indicators from signals
        for category, signals in result["signals"].items():
            for signal in signals[:3]:  # Limit to 3 per category
                result["indicators"].append(f"[{category}] {signal}")
        result["indicators"] = result["indicators"][:10]  # Cap at 10 total
        
        logger.info(f"Passkey detection result: detected={result['detected']}, methods={result['detection_methods']}, confidence={result['confidence']}")
        return result

    def _wait_for_page_ready(self):
        """Wait for page to be ready for detection."""
        try:
            self.page.wait_for_load_state("domcontentloaded", timeout=5000)
        except:
            pass
        try:
            self.page.wait_for_load_state("networkidle", timeout=5000)
        except:
            pass
        time.sleep(1)  # Extra wait for JS-heavy pages

    def _try_reveal_options(self):
        """Try to click buttons that might reveal passkey options."""
        try:
            # Patterns for buttons that reveal more options
            reveal_patterns = [
                r"try\s*another\s*way",
                r"more\s*options",
                r"other\s*(?:sign.?in)?\s*options",
                r"use\s*a\s*different\s*method",
                r"show\s*more",
                r"different\s*way",
                r"other\s*ways?\s*to\s*sign\s*in",
            ]
            
            clicked = self.page.evaluate('''
                (patterns) => {
                    const buttons = Array.from(document.querySelectorAll('button, a, [role="button"], div[role="button"]'));
                    for (const btn of buttons) {
                        const text = (btn.innerText || btn.textContent || btn.value || btn.getAttribute("aria-label") || "").toLowerCase();
                        for (const pattern of patterns) {
                            if (new RegExp(pattern, 'i').test(text)) {
                                const rect = btn.getBoundingClientRect();
                                if (rect.width > 0 && rect.height > 0) {
                                    btn.click();
                                    return true;
                                }
                            }
                        }
                    }
                    return false;
                }
            ''', reveal_patterns)
            
            if clicked:
                logger.debug("Clicked reveal button to show more options")
                time.sleep(2)
                try:
                    self.page.wait_for_selector('button, [role="button"]', timeout=3000, state="attached")
                except:
                    pass
        except Exception as e:
            logger.debug(f"Error in reveal options: {e}")

    def _check_webauthn_api(self) -> bool:
        """Check if WebAuthn API is available."""
        try:
            result = self.page.evaluate('''
                () => {
                    return typeof window.PublicKeyCredential !== 'undefined' && 
                           window.isSecureContext === true;
                }
            ''')
            return result
        except Exception as e:
            logger.debug(f"Error checking WebAuthn API: {e}")
            return False

    def _detect_ui_elements(self) -> Dict[str, Any]:
        """Category 1: UI Element Detection - buttons, links, text."""
        try:
            # Simple keyword-based detection first (no regex, more reliable)
            result = self.page.evaluate('''
                () => {
                    const results = { found: false, confidence: "LOW", signals: [], element_info: null };
                    
                    // Simple keywords to look for (case-insensitive)
                    const simpleKeywords = [
                        'passkey', 'sign in with passkey', 'use passkey', 'use a passkey',
                        'continue with passkey', 'login with passkey', 'passkey login',
                        'security key', 'use security key', 'sign in with security key'
                    ];
                    
                    const isVisible = (el) => {
                        if (!el) return false;
                        try {
                            let current = el;
                            while (current) {
                                const style = window.getComputedStyle(current);
                                if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
                                    return false;
                                }
                                current = current.parentElement;
                            }
                            const rect = el.getBoundingClientRect();
                            return rect.width > 0 && rect.height > 0;
                        } catch (e) {
                            return false;
                        }
                    };
                    
                    // Check all clickable elements
                    const clickables = Array.from(document.querySelectorAll(
                        'button, a, [role="button"], input[type="button"], input[type="submit"], div[onclick], span[onclick]'
                    )).filter(el => isVisible(el));
                    
                    for (const el of clickables) {
                        const text = (el.innerText || el.textContent || el.value || '').toLowerCase().trim();
                        const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
                        const title = (el.getAttribute('title') || '').toLowerCase();
                        const id = (el.id || '').toLowerCase();
                        const className = (el.className || '').toLowerCase();
                        const allText = text + ' ' + ariaLabel + ' ' + title + ' ' + id + ' ' + className;
                        
                        // Check simple keywords
                        for (const keyword of simpleKeywords) {
                            if (allText.includes(keyword)) {
                                const rect = el.getBoundingClientRect();
                                results.found = true;
                                results.confidence = "HIGH";
                                results.signals.push(`Button/link: "${text.substring(0, 50)}"`);
                                if (!results.element_info) {
                                    results.element_info = {
                                        x: rect.x,
                                        y: rect.y,
                                        width: rect.width,
                                        height: rect.height,
                                        inner_text: text.substring(0, 100),
                                        outer_html: el.outerHTML.substring(0, 500)
                                    };
                                }
                                break;
                            }
                        }
                        if (results.found) break;
                    }
                    
                    // If not found by simple keywords, try checking for passkey in any visible text
                    if (!results.found) {
                        const allElements = Array.from(document.querySelectorAll('*')).filter(el => isVisible(el));
                        for (const el of allElements) {
                            const text = (el.innerText || el.textContent || '').toLowerCase();
                            const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
                            
                            if (text.includes('passkey') || ariaLabel.includes('passkey')) {
                                // Check if it's a clickable element or near one
                                const isClickable = el.tagName === 'BUTTON' || el.tagName === 'A' || 
                                                   el.getAttribute('role') === 'button' ||
                                                   el.closest('button, a, [role="button"]');
                                if (isClickable || el.closest('button, a, [role="button"]')) {
                                    const rect = el.getBoundingClientRect();
                                    results.found = true;
                                    results.confidence = "HIGH";
                                    results.signals.push(`Text contains passkey: "${text.substring(0, 50)}"`);
                                    if (!results.element_info && rect.width > 0 && rect.height > 0) {
                                        results.element_info = {
                                            x: rect.x,
                                            y: rect.y,
                                            width: rect.width,
                                            height: rect.height,
                                            inner_text: text.substring(0, 100),
                                            outer_html: el.outerHTML.substring(0, 500)
                                        };
                                    }
                                    break;
                                } else {
                                    // Found passkey text but not in a button - still useful
                                    results.found = true;
                                    results.confidence = "MEDIUM";
                                    results.signals.push(`Passkey text on page: "${text.substring(0, 50)}"`);
                                    break;
                                }
                            }
                        }
                    }
                    
                    // Check ARIA labels for passkey/security key
                    if (!results.found) {
                        const ariaElements = Array.from(document.querySelectorAll('[aria-label]')).filter(el => isVisible(el));
                        for (const el of ariaElements) {
                            const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
                            if (ariaLabel.includes('passkey') || ariaLabel.includes('security key') || 
                                ariaLabel.includes('webauthn') || ariaLabel.includes('biometric')) {
                                const rect = el.getBoundingClientRect();
                                results.found = true;
                                results.confidence = "MEDIUM";
                                results.signals.push(`ARIA label: "${ariaLabel.substring(0, 50)}"`);
                                if (!results.element_info && rect.width > 0 && rect.height > 0) {
                                    results.element_info = {
                                        x: rect.x,
                                        y: rect.y,
                                        width: rect.width,
                                        height: rect.height,
                                        inner_text: (el.innerText || '').substring(0, 100),
                                        outer_html: el.outerHTML.substring(0, 500)
                                    };
                                }
                                break;
                            }
                        }
                    }
                    
                    return results;
                }
            ''')
            
            logger.info(f"UI element detection result: found={result.get('found')}, signals={result.get('signals')}")
            
            if result.get("element_info"):
                from common.modules.helper.detection import DetectionHelper
                el_info = result["element_info"]
                x = el_info["x"] + el_info["width"] / 2
                y = el_info["y"] + el_info["height"] / 2
                try:
                    element_tree, _ = DetectionHelper.get_coordinate_metadata(self.page, x, y)
                    result["element_info"]["element_tree"] = element_tree
                except Exception as e:
                    logger.debug(f"Error getting element tree: {e}")
                    result["element_info"]["element_tree"] = []
            
            return result
        except Exception as e:
            logger.warning(f"Error in UI element detection: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return {"found": False, "error": str(e)}

    def _detect_dom_structure(self) -> Dict[str, Any]:
        """Category 2: DOM Structure Detection - data attributes, autocomplete."""
        try:
            result = self.page.evaluate('''
                (selectors) => {
                    const results = { found: false, confidence: "LOW", signals: [], element_info: null };
                    
                    const isVisible = (el) => {
                        if (!el) return false;
                        const rect = el.getBoundingClientRect();
                        return rect.width >= 0 && rect.height >= 0;  // Include hidden elements
                    };
                    
                    for (const selector of selectors) {
                        try {
                            const elements = Array.from(document.querySelectorAll(selector));
                            if (elements.length > 0) {
                                results.found = true;
                                results.confidence = selector.includes('autocomplete="webauthn"') ? "HIGH" : "MEDIUM";
                                results.signals.push(`DOM: ${selector} (${elements.length} found)`);
                                
                                // Get first visible element for coordinates
                                const visibleEl = elements.find(el => {
                                    const rect = el.getBoundingClientRect();
                                    return rect.width > 0 && rect.height > 0;
                                });
                                
                                if (visibleEl && !results.element_info) {
                                    const rect = visibleEl.getBoundingClientRect();
                                    results.element_info = {
                                        x: rect.x,
                                        y: rect.y,
                                        width: rect.width,
                                        height: rect.height,
                                        inner_text: (visibleEl.innerText || '').substring(0, 100),
                                        outer_html: visibleEl.outerHTML.substring(0, 500)
                                    };
                                }
                            }
                        } catch (e) {
                            // Invalid selector
                        }
                    }
                    
                    return results;
                }
            ''', self.dom_selectors)
            
            return result
        except Exception as e:
            logger.debug(f"Error in DOM structure detection: {e}")
            return {"found": False, "error": str(e)}

    def _detect_js_api(self) -> Dict[str, Any]:
        """Category 3: JavaScript API Detection - WebAuthn API usage in scripts."""
        try:
            result = self.page.evaluate('''
                (patterns) => {
                    const results = { found: false, confidence: "LOW", signals: [] };
                    
                    // Get all inline script content
                    const scripts = Array.from(document.scripts)
                        .map(s => s.textContent || "")
                        .join("\\n");
                    
                    let highConfidence = false;
                    let mediumConfidence = false;
                    
                    for (const [pattern, description, confidence] of patterns) {
                        try {
                            if (new RegExp(pattern, 'i').test(scripts)) {
                                results.found = true;
                                results.signals.push(description);
                                if (confidence === "HIGH") highConfidence = true;
                                else if (confidence === "MEDIUM") mediumConfidence = true;
                            }
                        } catch (e) {}
                    }
                    
                    if (highConfidence) results.confidence = "HIGH";
                    else if (mediumConfidence) results.confidence = "MEDIUM";
                    else if (results.found) results.confidence = "LOW";
                    
                    return results;
                }
            ''', self.js_api_patterns)
            
            return result
        except Exception as e:
            logger.debug(f"Error in JS API detection: {e}")
            return {"found": False, "error": str(e)}

    def _detect_network_patterns(self) -> Dict[str, Any]:
        """Category 4: Network Pattern Detection - WebAuthn-related URLs."""
        try:
            result = self.page.evaluate('''
                (patterns) => {
                    const results = { found: false, confidence: "LOW", signals: [] };
                    
                    // Check current URL
                    const currentUrl = window.location.href.toLowerCase();
                    for (const pattern of patterns) {
                        if (new RegExp(pattern, 'i').test(currentUrl)) {
                            results.found = true;
                            results.confidence = "MEDIUM";
                            results.signals.push(`URL contains: ${pattern}`);
                        }
                    }
                    
                    // Check for fetch/XHR to passkey endpoints in page scripts
                    const scripts = Array.from(document.scripts)
                        .map(s => s.textContent || "")
                        .join("\\n");
                    
                    for (const pattern of patterns) {
                        const urlPattern = new RegExp(`["']([^"']*${pattern}[^"']*)["']`, 'gi');
                        const matches = scripts.match(urlPattern);
                        if (matches && matches.length > 0) {
                            results.found = true;
                            results.confidence = "MEDIUM";
                            results.signals.push(`API endpoint: ${pattern}`);
                        }
                    }
                    
                    return results;
                }
            ''', self.network_patterns)
            
            return result
        except Exception as e:
            logger.debug(f"Error in network pattern detection: {e}")
            return {"found": False, "error": str(e)}

    def _detect_libraries(self) -> Dict[str, Any]:
        """Category 5: Library Detection - Known WebAuthn libraries."""
        try:
            result = self.page.evaluate('''
                (patterns) => {
                    const results = { found: false, confidence: "LOW", signals: [] };
                    
                    // Check inline scripts
                    const scripts = Array.from(document.scripts)
                        .map(s => s.textContent || "")
                        .join("\\n");
                    
                    // Check external script sources
                    const scriptSrcs = Array.from(document.scripts)
                        .map(s => s.src || "")
                        .filter(Boolean)
                        .join("\\n");
                    
                    const allContent = scripts + "\\n" + scriptSrcs;
                    
                    let highConfidence = false;
                    
                    for (const [pattern, name, confidence] of patterns) {
                        try {
                            if (new RegExp(pattern, 'i').test(allContent)) {
                                results.found = true;
                                results.signals.push(`Library: ${name}`);
                                if (confidence === "HIGH") highConfidence = true;
                            }
                        } catch (e) {}
                    }
                    
                    if (highConfidence) results.confidence = "HIGH";
                    else if (results.found) results.confidence = "MEDIUM";
                    
                    return results;
                }
            ''', self.library_patterns)
            
            return result
        except Exception as e:
            logger.debug(f"Error in library detection: {e}")
            return {"found": False, "error": str(e)}

    def _detect_enterprise(self) -> Dict[str, Any]:
        """Enterprise-specific detection for known implementations."""
        try:
            result = self.page.evaluate('''
                (enterprisePatterns) => {
                    const results = { found: false, confidence: "LOW", signals: [] };
                    const currentDomain = window.location.hostname.toLowerCase();
                    
                    const isVisible = (el) => {
                        if (!el) return false;
                        const rect = el.getBoundingClientRect();
                        const style = window.getComputedStyle(el);
                        return rect.width > 0 && rect.height > 0 && 
                               style.display !== 'none' && style.visibility !== 'hidden';
                    };
                    
                    for (const [provider, config] of Object.entries(enterprisePatterns)) {
                        // Check if domain matches
                        const domainMatch = config.domains.some(d => currentDomain.includes(d.toLowerCase()));
                        if (!domainMatch) continue;
                        
                        // Check selectors
                        let selectorMatch = false;
                        for (const selector of config.selectors) {
                            try {
                                const elements = Array.from(document.querySelectorAll(selector));
                                const visibleElements = elements.filter(el => isVisible(el));
                                if (visibleElements.length > 0) {
                                    selectorMatch = true;
                                    break;
                                }
                            } catch (e) {}
                        }
                        
                        // Check text patterns
                        const pageText = (document.body.innerText || '').toLowerCase();
                        const textMatch = config.text_patterns.some(p => 
                            pageText.includes(p.toLowerCase())
                        );
                        
                        if (selectorMatch || textMatch) {
                            results.found = true;
                            results.confidence = "HIGH";
                            results.signals.push(`${provider.toUpperCase()} passkey implementation`);
                        }
                    }
                    
                    return results;
                }
            ''', self.enterprise_patterns)
            
            return result
        except Exception as e:
            logger.debug(f"Error in enterprise detection: {e}")
            return {"found": False, "error": str(e)}

    def _calculate_confidence(self, category_results: Dict[str, Dict]) -> str:
        """Calculate overall confidence based on category results."""
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for category, result in category_results.items():
            conf = result.get("confidence", "NONE")
            if conf == "HIGH":
                high_count += 1
            elif conf == "MEDIUM":
                medium_count += 1
            elif conf == "LOW":
                low_count += 1
        
        # Multiple HIGH signals = HIGH overall
        if high_count >= 1:
            return "HIGH"
        # Multiple MEDIUM signals = HIGH overall
        if medium_count >= 2:
            return "HIGH"
        # One MEDIUM = MEDIUM
        if medium_count >= 1:
            return "MEDIUM"
        # Only LOW signals
        if low_count >= 2:
            return "MEDIUM"
        if low_count >= 1:
            return "LOW"
        
        return "NONE"

    def _update_element_info(self, result: Dict, element_info: Dict):
        """Update result with element information."""
        result["element_coordinates_x"] = element_info.get("x")
        result["element_coordinates_y"] = element_info.get("y")
        result["element_width"] = element_info.get("width")
        result["element_height"] = element_info.get("height")
        result["element_inner_text"] = element_info.get("inner_text")
        result["element_outer_html"] = element_info.get("outer_html")
        result["element_tree"] = element_info.get("element_tree", [])
        result["element_validity"] = "HIGH" if element_info.get("inner_text") else "MEDIUM"

    # ===== VIRTUAL AUTHENTICATOR METHODS =====
    
    def capture_implementation_params(self, url: str) -> Dict[str, Any]:
        """Capture WebAuthn implementation parameters using virtual authenticator."""
        self.url = url
        logger.info(f"Capturing WebAuthn implementation parameters for: {url}")
        
        result = {
            "captured": False,
            "create_options": None,
            "get_options": None,
            "credentials": [],
            "cdp_events": [],
            "trigger_method": None
        }
        
        try:
            self._inject_instrumentation()
            auth_id = self._setup_virtual_authenticator()
            
            if not auth_id:
                logger.warning("Failed to set up virtual authenticator")
                return result
            
            triggered, trigger_details = self._attempt_trigger_webauthn()
            
            if triggered:
                captures = self._extract_captured_params()
                
                for capture in captures:
                    if capture.get('type') == 'create':
                        result["create_options"] = capture.get('extracted_params')
                    elif capture.get('type') == 'get':
                        result["get_options"] = capture.get('extracted_params')
                
                result["credentials"] = self._get_credentials()
                result["cdp_events"] = self._get_cdp_events()[:50]  # Cap at 50 events
                result["trigger_method"] = trigger_details.get("method")
                result["captured"] = True
            
            self._cleanup()
            
        except Exception as e:
            logger.error(f"Error capturing implementation params: {e}")
            result["error"] = str(e)
        
        return result

    def _inject_instrumentation(self):
        """Inject WebAuthn instrumentation script."""
        logger.info("Injecting WebAuthn instrumentation")
        
        from pathlib import Path
        
        script_path = Path(__file__).parent.parent / "browser" / "js" / "webauthn-instrumentation.js"
        
        if script_path.exists():
            with open(script_path, 'r') as f:
                script = f.read()
            
            self.page.context.add_init_script(script)
            try:
                self.page.add_init_script(script)
                self.page.evaluate(script)
            except:
                pass
            logger.info("Instrumentation injected")
        else:
            logger.warning(f"Instrumentation script not found at {script_path}")

    def _setup_virtual_authenticator(self) -> Optional[str]:
        """Set up virtual authenticator via CDP."""
        try:
            self.cdp_manager = CDPSessionManager(self.page.context, self.page)
            self.cdp_manager.enable_webauthn()
            auth_id = self.cdp_manager.add_virtual_authenticator(
                protocol="ctap2",
                transport="internal",
                has_resident_key=True,
                has_user_verification=True,
                is_user_verified=True,
                automatic_presence_simulation=True,
                is_user_consenting=True
            )
            logger.info(f"Virtual authenticator ready: {auth_id}")
            return auth_id
        except Exception as e:
            logger.error(f"Error setting up virtual authenticator: {e}")
            return None

    def _attempt_trigger_webauthn(self) -> Tuple[bool, Dict[str, Any]]:
        """Attempt to trigger WebAuthn flow."""
        logger.info("Attempting to trigger WebAuthn")
        
        details = {"method": "passive"}
        
        try:
            PlaywrightHelper.wait_for_page_load(self.page, self.config.get("browser_config", {}))
            time.sleep(3)
            
            captures = self._extract_captured_params()
            if captures:
                logger.info("WebAuthn triggered passively")
                return True, details
            
            button_clicked = self._try_click_passkey_button()
            if button_clicked:
                details["method"] = "button_click"
                time.sleep(3)
                captures = self._extract_captured_params()
                if captures:
                    logger.info("WebAuthn triggered via button click")
                    return True, details
            
            form_filled = self._try_fill_username()
            if form_filled:
                details["method"] = "form_interaction"
                time.sleep(3)
                captures = self._extract_captured_params()
                if captures:
                    logger.info("WebAuthn triggered via form interaction")
                    return True, details
            
            return False, details
            
        except Exception as e:
            logger.error(f"Error attempting to trigger WebAuthn: {e}")
            return False, {"error": str(e)}

    def _try_click_passkey_button(self) -> bool:
        """Try clicking passkey-related buttons."""
        try:
            result = self.page.evaluate("""
                () => {
                    const buttons = Array.from(document.querySelectorAll(
                        'button, a, [role="button"], input[type="button"]'
                    ));
                    
                    for (const btn of buttons) {
                        const text = (btn.innerText || btn.value || '').toLowerCase();
                        if (/passkey|security.?key|biometric/.test(text)) {
                            const rect = btn.getBoundingClientRect();
                            if (rect.width > 0 && rect.height > 0) {
                                btn.click();
                                return true;
                            }
                        }
                    }
                    return false;
                }
            """)
            return result
        except Exception as e:
            logger.debug(f"Error clicking passkey button: {e}")
            return False

    def _try_fill_username(self) -> bool:
        """Try filling username field to trigger conditional mediation."""
        try:
            result = self.page.evaluate("""
                () => {
                    const inputs = Array.from(document.querySelectorAll(
                        'input[type="text"], input[type="email"], input[autocomplete*="username"]'
                    ));
                    
                    if (inputs.length > 0) {
                        const input = inputs[0];
                        input.focus();
                        input.value = 'test@example.com';
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        return true;
                    }
                    return false;
                }
            """)
            return result
        except Exception as e:
            logger.debug(f"Error filling username: {e}")
            return False

    def _extract_captured_params(self) -> List[Dict[str, Any]]:
        """Extract captured WebAuthn parameters from instrumentation."""
        try:
            captures = self.page.evaluate("window.__webauthn_capture || []")
            if captures:
                logger.info(f"Extracted {len(captures)} WebAuthn captures")
            return captures
        except Exception as e:
            logger.debug(f"Error extracting captured params: {e}")
            return []

    def _get_credentials(self) -> List[Dict[str, Any]]:
        """Get credentials from virtual authenticator."""
        if not self.cdp_manager:
            return []
        
        try:
            credentials = self.cdp_manager.get_credentials()
            if credentials:
                logger.info(f"Retrieved {len(credentials)} credentials")
            return credentials
        except Exception as e:
            logger.debug(f"Error getting credentials: {e}")
            return []

    def _get_cdp_events(self) -> List[Dict[str, Any]]:
        """Get CDP events (capped at 50)."""
        if not self.cdp_manager:
            return []
        
        try:
            events = self.cdp_manager.get_events()
            if events:
                logger.info(f"Retrieved {len(events)} CDP events (capping to 50)")
            return events[:50]
        except Exception as e:
            logger.debug(f"Error getting CDP events: {e}")
            return []

    def _cleanup(self):
        """Clean up resources."""
        logger.debug("Cleaning up passkey mechanism resources")
        if self.cdp_manager:
            try:
                self.cdp_manager.close()
            except:
                pass
            self.cdp_manager = None
