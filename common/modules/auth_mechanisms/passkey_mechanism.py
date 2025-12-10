import logging
import time
import re
from typing import Dict, Any, List, Tuple, Optional
from playwright.sync_api import Page
from common.modules.browser.browser import PlaywrightHelper, CDPSessionManager

logger = logging.getLogger(__name__)


class PasskeyMechanism:
    
    def __init__(self, page: Page, config: dict = None, site_domain: str = None):
        self.page = page
        self.config = config or {}
        self.site_domain = site_domain
        self.cdp_manager: Optional[CDPSessionManager] = None
        self.url = None
        
        # Enterprise-specific patterns (from passkey-crawler, expanded with Apple and improved patterns)
        self.enterprise_patterns = {
            "microsoft": {
                "domains": ["login.microsoft.com", "login.live.com", "account.microsoft.com", "microsoft.com"],
                "elements": [
                    "#idBtn_Back", 
                    ".win-button", 
                    "[data-bind*='winButton']",
                    "[aria-label*='Windows Hello' i]",
                    "[aria-label*='Security Key' i]",
                    "button[data-testid*='passkey' i]",
                    "button[data-testid*='security-key' i]",
                    "[class*='passkey' i]",
                    "[class*='webauthn' i]",
                    "[id*='passkey' i]"
                ],
                "text_patterns": ["Windows Hello", "Security Key", "FIDO2", "passkey", "webauthn"]
            },
            "adobe": {
                "domains": ["account.adobe.com", "auth.services.adobe.com", "adobe.com"],
                "elements": [
                    ".spectrum-Button", 
                    "[data-testid*='security-key' i]", 
                    "[data-testid*='passkey' i]",
                    "button[aria-label*='passkey' i]",
                    "button[aria-label*='security key' i]",
                    "[class*='passkey' i]"
                ],
                "text_patterns": ["Security Key", "Biometric Sign In", "passkey", "webauthn"]
            },
            "google": {
                "domains": ["accounts.google.com", "google.com"],
                "elements": [
                    "[data-primary-action-label]", 
                    ".ZFr60d", 
                    "[data-testid*='passkey' i]",
                    "button[aria-label*='passkey' i]",
                    "button[aria-label*='security key' i]",
                    "[class*='passkey' i]",
                    "[class*='webauthn' i]"
                ],
                "text_patterns": ["Security Key", "2-Step Verification", "passkey", "webauthn"]
            },
            "apple": {
                "domains": ["appleid.apple.com", "id.apple.com", "apple.com"],
                "elements": [
                    "button[aria-label*='passkey' i]",
                    "button[aria-label*='security key' i]",
                    "[data-testid*='passkey' i]",
                    "[data-testid*='security-key' i]",
                    "[class*='passkey' i]",
                    "[class*='webauthn' i]",
                    "button[class*='sign-in' i]",
                    "[id*='passkey' i]",
                    "[id*='webauthn' i]"
                ],
                "text_patterns": ["passkey", "security key", "Touch ID", "Face ID", "biometric", "webauthn"]
            },
            "bestbuy": {
                "domains": ["bestbuy.com", "www.bestbuy.com"],
                "elements": [
                    "button[data-testid*='passkey' i]", 
                    "[aria-label*='passkey' i]", 
                    "[class*='passkey' i]",
                    "button[aria-label*='security key' i]",
                    "[data-testid*='security-key' i]",
                    "[id*='passkey' i]",
                    "button[class*='passkey' i]",
                    "[class*='webauthn' i]"
                ],
                "text_patterns": ["passkey", "security key", "biometric", "webauthn"]
            }
        }
        
    def detect_full(self, url: str) -> Dict[str, Any]:
        self.url = url
        logger.info(f"Starting comprehensive passkey detection on: {url}")
        
        result = {
            "mechanism": "passkey",
            "detected": False,
            "detection_methods": [],
            "confidence": "NONE",
            "indicators": [],
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
        
        webauthn_available = self._check_webauthn_api()
        result["webauthn_api_available"] = webauthn_available
        
        if not webauthn_available:
            logger.info("WebAuthn API not available")
            return result
        
        # Wait for dynamic content and try to interact with page to reveal hidden buttons
        try:
            self.page.wait_for_load_state("domcontentloaded", timeout=5000)
        except:
            pass
        
        # Try clicking on "Try another way" or similar buttons to reveal passkey options (Google, etc.)
        try:
            import time
            # Look for buttons that might reveal more sign-in options
            reveal_button_clicked = self.page.evaluate('''
                () => {
                    const buttons = Array.from(document.querySelectorAll('button, a, [role="button"], div[role="button"]'));
                    const revealBtn = buttons.find(btn => {
                        const text = (btn.innerText || btn.textContent || btn.value || btn.getAttribute("aria-label") || "").toLowerCase();
                        return /try another way|more options|other options|use a different method|show more|different way/i.test(text);
                    });
                    if (revealBtn) {
                        const rect = revealBtn.getBoundingClientRect();
                        if (rect.width > 0 && rect.height > 0) {
                            revealBtn.click();
                            return true;
                        }
                    }
                    return false;
                }
            ''')
            
            if reveal_button_clicked:
                logger.info("Clicked 'Try another way' button to reveal passkey options")
                # Wait for content to appear
                time.sleep(3)
                # Wait for any new buttons to appear
                try:
                    self.page.wait_for_selector('button, [role="button"]', timeout=5000, state="attached")
                except:
                    pass
        except Exception as e:
            logger.debug(f"Error trying to reveal passkey options: {e}")
        
        # Run ALL detection methods and consolidate results into a clean structure
        # detection_methods array will only contain methods that successfully found passkey
        
        # 1. Enterprise detection
        # Enterprise detection checks for known passkey implementations on major platforms:
        # - Microsoft: Windows Hello, Security Key buttons on login.microsoft.com
        # - Google: Security Key options on accounts.google.com  
        # - Apple: Touch ID/Face ID passkey options on appleid.apple.com
        # - Adobe: Security Key buttons on account.adobe.com
        # - BestBuy: Passkey buttons on bestbuy.com
        # It uses domain matching + element selectors + text patterns to detect
        enterprise_result = self._detect_enterprise_implementation()
        if enterprise_result.get("found"):
            result["detected"] = True
            result["detection_methods"].append("ENTERPRISE")
            result["confidence"] = max(result["confidence"], enterprise_result.get("confidence", "LOW"), key=lambda x: ["NONE", "LOW", "MEDIUM", "HIGH"].index(x) if x in ["NONE", "LOW", "MEDIUM", "HIGH"] else 0)
            result["indicators"].extend(enterprise_result.get("key_indicators", []))
            logger.info(f"Enterprise passkey detected: {enterprise_result.get('key_indicators', [])}")
        
        # 2. UI detection
        # Scans the DOM for passkey-related UI elements:
        # - Buttons with "passkey", "security key", "biometric" text
        # - Elements with data-passkey, data-webauthn attributes
        # - Input fields with autocomplete="webauthn"
        # - ARIA labels mentioning passkey/biometric
        ui_result = self._detect_ui_detailed()
        if ui_result.get("found"):
            result["detected"] = True
            result["detection_methods"].append("UI")
            result["confidence"] = max(result["confidence"], ui_result["confidence"], key=lambda x: ["NONE", "LOW", "MEDIUM", "HIGH"].index(x) if x in ["NONE", "LOW", "MEDIUM", "HIGH"] else 0)
            result["indicators"].extend(ui_result.get("indicators", []))
            
            if ui_result.get("element_info"):
                el_info = ui_result["element_info"]
                # Only update coordinates if not already set (enterprise might have set them)
                if result["element_coordinates_x"] is None:
                    result["element_coordinates_x"] = el_info.get("x")
                    result["element_coordinates_y"] = el_info.get("y")
                    result["element_width"] = el_info.get("width")
                    result["element_height"] = el_info.get("height")
                    result["element_inner_text"] = el_info.get("inner_text")
                    result["element_outer_html"] = el_info.get("outer_html")
                    result["element_tree"] = el_info.get("element_tree", [])
                    result["element_validity"] = "HIGH" if el_info.get("inner_text") else "MEDIUM"
        
        # 3. JS detection
        # Analyzes JavaScript code for WebAuthn API usage:
        # - navigator.credentials.create/get calls
        # - PublicKeyCredential references
        # - isUserVerifyingPlatformAuthenticatorAvailable checks
        # - isConditionalMediationAvailable checks
        js_result = self._detect_javascript()
        if js_result.get("found"):
            result["detected"] = True
            result["detection_methods"].append("JS")
            result["confidence"] = max(result["confidence"], js_result["confidence"], key=lambda x: ["NONE", "LOW", "MEDIUM", "HIGH"].index(x) if x in ["NONE", "LOW", "MEDIUM", "HIGH"] else 0)
            result["indicators"].extend(js_result.get("indicators", []))
        
        # 4. Keyword detection
        # Scans visible page text and titles for passkey-related keywords:
        # - "passkey", "security key", "biometric", "webauthn"
        # - "sign in with passkey", "use passkey", etc.
        # Higher confidence if found in authentication context
        keyword_result = self._detect_passkey_keywords()
        if keyword_result.get("found"):
            result["detected"] = True
            result["detection_methods"].append("KEYWORD")
            result["confidence"] = max(result["confidence"], keyword_result.get("confidence", "LOW"), key=lambda x: ["NONE", "LOW", "MEDIUM", "HIGH"].index(x) if x in ["NONE", "LOW", "MEDIUM", "HIGH"] else 0)
            result["indicators"].extend(keyword_result.get("key_indicators", []))
        
        # Remove duplicates from indicators and limit to top 10
        result["indicators"] = list(dict.fromkeys(result["indicators"]))[:10]
        
        logger.info(f"Passkey detection final result: detected={result['detected']}, methods={result['detection_methods']}, confidence={result['confidence']}")
        return result
    
    def capture_implementation_params(self, url: str) -> Dict[str, Any]:
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
                result["cdp_events"] = self._get_cdp_events()
                result["trigger_method"] = trigger_details.get("method")
                result["captured"] = True
            
            self._cleanup()
            
        except Exception as e:
            logger.error(f"Error capturing implementation params: {e}")
            result["error"] = str(e)
        
        return result
    
    def _check_webauthn_api(self) -> bool:
        try:
            # Wait a bit for page to fully load
            self.page.wait_for_load_state("networkidle", timeout=5000)
        except:
            pass
        
        try:
            result = self.page.evaluate('''
                () => {
                    return typeof window.PublicKeyCredential !== 'undefined' && 
                           window.isSecureContext === true;
                }
            ''')
            logger.debug(f"WebAuthn API check result: {result}")
            return result
        except Exception as e:
            logger.error(f"Error checking WebAuthn API: {e}")
            return False
    
    def _detect_enterprise_implementation(self) -> Dict[str, Any]:
        """Detect enterprise-specific passkey implementations (Adobe, Google, Microsoft, Apple, BestBuy)"""
        try:
            result = self.page.evaluate('''
            (enterprisePatterns) => {
                const results = {
                    found: false,
                    confidence: "LOW",
                    key_indicators: [],
                    found_in: "ENTERPRISE"
                };

                const currentDomain = window.location.hostname.toLowerCase();
                const currentUrl = window.location.href.toLowerCase();
                
                // Helper to check if element is visible
                const isVisible = (el) => {
                    if (!el) return false;
                    const style = window.getComputedStyle(el);
                    const rect = el.getBoundingClientRect();
                    return style.display !== 'none' && 
                           style.visibility !== 'hidden' && 
                           style.opacity !== '0' &&
                           rect.width > 0 && 
                           rect.height > 0;
                };
                
                for (const [provider, patterns] of Object.entries(enterprisePatterns)) {
                    // Check if domain matches (more lenient matching)
                    const domainMatch = patterns.domains.some(domain => 
                        currentDomain.includes(domain.toLowerCase()) || 
                        currentUrl.includes(domain.toLowerCase())
                    );
                    
                    if (domainMatch) {
                        // Try to find elements with these selectors
                        const foundElements = [];
                        for (const selector of patterns.elements) {
                            try {
                                const els = Array.from(document.querySelectorAll(selector));
                                const visibleEls = els.filter(el => isVisible(el));
                                foundElements.push(...visibleEls);
                            } catch (e) {
                                // Invalid selector, skip
                            }
                        }
                        
                        const hasElements = foundElements.length > 0;
                        
                        // Check text patterns in page content
                        const pageText = (document.body.innerText || document.body.textContent || '').toLowerCase();
                        const hasTextPatterns = patterns.text_patterns.some(pattern => 
                            pageText.includes(pattern.toLowerCase())
                        );
                        
                        // Also check for passkey-related terms in URL or title
                        const titleText = (document.title || '').toLowerCase();
                        const hasTitlePatterns = patterns.text_patterns.some(pattern => 
                            titleText.includes(pattern.toLowerCase())
                        );
                        
                        if (hasElements || hasTextPatterns || hasTitlePatterns) {
                            results.found = true;
                            results.confidence = "HIGH";
                            results.key_indicators.push(`${provider.toUpperCase()} authentication detected`);
                            
                            if (hasElements) {
                                const elementTexts = foundElements
                                    .map(el => (el.innerText || el.textContent || el.value || el.getAttribute('aria-label') || '').trim())
                                    .filter(Boolean)
                                    .slice(0, 3);
                                elementTexts.forEach(text => 
                                    results.key_indicators.push(`${provider} element: "${text.substring(0, 50)}"`)
                                );
                            }
                            
                            if (hasTextPatterns) {
                                const matchedPatterns = patterns.text_patterns.filter(pattern => 
                                    pageText.includes(pattern.toLowerCase())
                                );
                                matchedPatterns.slice(0, 2).forEach(pattern => 
                                    results.key_indicators.push(`${provider} text: "${pattern}"`)
                                );
                            }
                        }
                    }
                }
                
                return results;
            }
            ''', self.enterprise_patterns)
            
            return result
        except Exception as e:
            logger.error(f"Error in enterprise detection: {e}")
            return {"found": False, "error": str(e)}
    
    def _detect_passkey_keywords(self) -> Dict[str, Any]:
        """Detect presence of passkey keywords in page content (from passkey-crawler)"""
        try:
            # Get visible text content
            page_data = self.page.evaluate('''
            () => {
                // Function to get visible text from the page
                const getVisibleText = () => {
                    // Get text content from visible elements likely to contain passkey info
                    const elements = document.querySelectorAll('p, div, span, button, a, label');
                    const texts = [];
                    
                    for (const el of elements) {
                        // Skip if not visible
                        const style = window.getComputedStyle(el);
                        if (style.display === 'none' || style.visibility === 'hidden') {
                            continue;
                        }
                        
                        const text = el.innerText || el.textContent || '';
                        if (text.trim()) {
                            texts.push(text.trim());
                        }
                    }
                    
                    return texts.join(' ');
                };
                
                // Function to check if we're in an auth context
                const isInAuthContext = () => {
                    // Check URL
                    if (/login|signin|auth|account/i.test(window.location.href)) {
                        return true;
                    }
                    
                    // Check page title
                    if (/login|sign.?in|auth/i.test(document.title)) {
                        return true;
                    }
                    
                    // Check for login forms
                    return !!document.querySelector('form input[type="password"]') ||
                           !!document.querySelector('form input[type="email"]');
                };
                
                return {
                    visibleText: getVisibleText(),
                    inAuthContext: isInAuthContext(),
                    pageTitle: document.title
                };
            }
            ''')
            
            # Define patterns with increasing specificity (from passkey-crawler)
            patterns = [
                # High confidence patterns - specific to passkeys
                (r'sign\s+in\s+with\s+passkey', "Sign in with passkey", "HIGH"),
                (r'login\s+with\s+passkey', "Login with passkey", "HIGH"),
                (r'use\s+passkey', "Use a passkey", "HIGH"),
                (r'continue\s+with\s+passkey', "Continue with passkey", "HIGH"),
                (r'passkey\s+authentication', "Passkey authentication", "HIGH"),
                
                # Medium confidence patterns - clear passkey terms
                (r'passkey', "Passkey reference", "MEDIUM"),
                (r'webauthn', "WebAuthn reference", "MEDIUM"),
                
                # Lower confidence patterns - related to passkey features
                (r'biometric\s+login', "Biometric login", "LOW"),
                (r'passwordless\s+login', "Passwordless login", "LOW"),
                (r'login\s+without\s+password', "Login without password", "LOW")
            ]
            
            # Get text content
            visible_text = page_data.get('visibleText', '')
            page_title = page_data.get('pageTitle', '')
            in_auth_context = page_data.get('inAuthContext', False)
            
            # Check for matches
            found_patterns = []
            highest_confidence = "LOW"
            
            for pattern, description, confidence in patterns:
                # Check visible text
                if re.search(pattern, visible_text, re.IGNORECASE):
                    location = "page text"
                    found_patterns.append(f"{description} (in {location})")
                    
                    # Update confidence if higher
                    if confidence == "HIGH" or (confidence == "MEDIUM" and highest_confidence == "LOW"):
                        highest_confidence = confidence
                
                # Check title (higher confidence if in title)
                if re.search(pattern, page_title, re.IGNORECASE):
                    location = "page title"
                    found_patterns.append(f"{description} (in {location})")
                    
                    if confidence == "HIGH" or confidence == "MEDIUM":
                        highest_confidence = confidence
            
            # Boost confidence if in auth context
            if in_auth_context and highest_confidence == "MEDIUM":
                highest_confidence = "HIGH"
            
            # Need at least one pattern to consider it a match
            has_passkey = len(found_patterns) > 0
            
            # Limit the indicators we return
            key_indicators = found_patterns[:5]
            
            return {
                "found": has_passkey,
                "confidence": highest_confidence,
                "found_in": "TEXT",
                "key_indicators": key_indicators,
                "in_auth_context": in_auth_context
            }
        except Exception as e:
            logger.debug(f"Error in passkey keyword detection: {e}")
            return {"found": False, "error": str(e)}
    
    def _detect_ui_detailed(self) -> Dict[str, Any]:
        """Comprehensive UI detection with retries (like passkey-crawler)"""
        try:
            from common.modules.helper.detection import DetectionHelper
            
            # First try basic detection
            result = self._detect_ui_detailed_core()
            
            # If not found, try waiting for dynamic content to load (like passkey-crawler)
            if not result.get("found", False):
                logger.debug("Initial UI detection failed, waiting for dynamic content...")
                try:
                    # Wait a bit for dynamic content to load (common JS frameworks have delay)
                    time.sleep(1)
                    self.page.wait_for_timeout(500)  # Extra 500ms in Playwright
                    
                    # Try again after waiting
                    result = self._detect_ui_detailed_core()
                    
                    # If still not found, try scrolling to reveal lazy-loaded content
                    if not result.get("found", False):
                        logger.debug("Secondary UI detection failed, trying scroll...")
                        self.page.evaluate('''
                        () => {
                            window.scrollTo(0, document.body.scrollHeight / 2);
                        }
                        ''')
                        time.sleep(0.5)
                        result = self._detect_ui_detailed_core()
                except Exception as e:
                    logger.debug(f"Error during dynamic content check: {e}")
            
            return result
        except Exception as e:
            logger.error(f"Error in UI detection: {e}")
            return {"found": False, "error": str(e)}
    
    def _detect_ui_detailed_core(self) -> Dict[str, Any]:
        """Core UI detection logic"""
        try:
            from common.modules.helper.detection import DetectionHelper
            
            # Wait for page to be ready
            try:
                self.page.wait_for_load_state("domcontentloaded", timeout=5000)
            except:
                pass
            
            result = self.page.evaluate('''
                () => {
                    const results = {
                        found: false,
                        confidence: "LOW",
                        indicators: [],
                        element_info: null
                    };
                    
                    // Helper function to check if element is likely a social media icon (false positive)
                    const isSocialMediaIcon = (el) => {
                        const src = el.src || '';
                        const classes = el.className || '';
                        const ariaLabel = el.getAttribute('aria-label') || '';
                        const alt = el.getAttribute('alt') || '';
                        
                        // Common social media patterns to exclude
                        const socialPatterns = [
                            /facebook/i, /twitter/i, /instagram/i, /google/i, /linkedin/i,
                            /social-media/i, /social_media/i, /socialmedia/i,
                            /fb-icon/i, /tw-icon/i, /ig-icon/i
                        ];
                        
                        return socialPatterns.some(pattern => 
                            pattern.test(src) || pattern.test(classes) || 
                            pattern.test(ariaLabel) || pattern.test(alt)
                        );
                    };
                    
                    // Helper to check if element is visible (matching passkey-crawler logic)
                    const isVisible = (el) => {
                        if (!el) return false;
                        let currentEl = el;
                        while (currentEl) {
                            const style = window.getComputedStyle(currentEl);
                            if (style.display === 'none' || 
                                style.visibility === 'hidden' || 
                                style.opacity === '0') {
                                return false;
                            }
                            currentEl = currentEl.parentElement;
                        }
                        const rect = el.getBoundingClientRect();
                        const viewportWidth = window.innerWidth || document.documentElement.clientWidth;
                        const viewportHeight = window.innerHeight || document.documentElement.clientHeight;
                        const extendedViewport = {
                            left: -300,
                            top: -300,
                            right: viewportWidth + 300,
                            bottom: viewportHeight + 1000
                        };
                        const isInViewport = 
                            rect.right > extendedViewport.left &&
                            rect.left < extendedViewport.right &&
                            rect.bottom > extendedViewport.top && 
                            rect.top < extendedViewport.bottom;
                        return rect.width > 0 && rect.height > 0 && isInViewport;
                    };
                    
                    // Check if element is near authentication context
                    const isNearAuthContext = (el) => {
                        const isInForm = !!el.closest('form');
                        const nearInputs = !!document.querySelector('input[type="password"], input[type="email"]');
                        const hasAuthUrl = /login|signin|auth|account/i.test(window.location.href);
                        const hasAuthTitle = /login|sign.?in|auth/i.test(document.title);
                        return isInForm || (nearInputs && (hasAuthUrl || hasAuthTitle));
                    };
                    
                    // 1. Look for explicit passkey buttons - expanded patterns
                    const passkeyButtons = Array.from(document.querySelectorAll(
                        'button, a, div[role="button"], span[role="button"], input[type="button"], input[type="submit"], ' +
                        '[role="button"], [data-testid*="passkey" i], [data-testid*="security-key" i]'
                    )).filter(el => {
                        const text = (el.innerText || el.value || el.textContent || '').toLowerCase();
                        const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
                        const title = (el.getAttribute('title') || '').toLowerCase();
                        const id = (el.getAttribute('id') || '').toLowerCase();
                        const className = (el.getAttribute('class') || '').toLowerCase();
                        const allText = text + ' ' + ariaLabel + ' ' + title + ' ' + id + ' ' + className;
                        
                        // Expanded passkey patterns
                        const hasPasskeyKeyword = (
                            /passkey|pass.?key/i.test(allText) ||
                            /sign.in.with.passkey|continue.with.passkey|use.passkey|use.a.passkey/i.test(allText) ||
                            (/no.?password|passwordless/i.test(allText) && 
                             /sign.?in|log.?in|login|continue/i.test(allText)) ||
                            /security.?key/i.test(allText) ||
                            /webauthn/i.test(allText)
                        );
                        
                        // Exclude third-party SSO buttons
                        const isThirdParty = /continue.with.google|sign.in.with.google|continue.with.apple|sign.in.with.apple|continue.with.facebook|sign.in.with.facebook/i.test(allText);
                        
                        return hasPasskeyKeyword && !isThirdParty && !isSocialMediaIcon(el) && isVisible(el);
                    });
                    
                    // 2. Look for biometric buttons - expanded patterns
                    const biometricButtons = Array.from(document.querySelectorAll(
                        'button, a, div[role="button"], span[role="button"], input[type="button"], input[type="submit"], ' +
                        '[role="button"]'
                    )).filter(el => {
                        const text = (el.innerText || el.textContent || el.value || '').toLowerCase();
                        const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
                        const title = (el.getAttribute('title') || '').toLowerCase();
                        const allText = text + ' ' + ariaLabel + ' ' + title;
                        
                        return (/fingerprint|face.?id|touch.?id|biometric|windows.?hello|security.?key/i.test(allText) &&
                               /sign.?in|log.?in|login|continue|verify/i.test(allText)) &&
                               !isSocialMediaIcon(el) &&
                               isVisible(el);
                    });
                    
                    // 3. Look for passkey attributes
                    const passkeyAttrElements = Array.from(document.querySelectorAll(
                        '[data-webauthn], [data-passkey], [data-credential], ' +
                        '[data-authentication-method="passkey"], [data-auth-type="passkey"], ' +
                        '[autocomplete="webauthn"]'
                    )).filter(el => isVisible(el));
                    
                    // 4. Look for credential inputs
                    const credentialInputs = Array.from(document.querySelectorAll(
                        'input[autocomplete="webauthn"], input[type="publickey"], ' +
                        'input[data-auth-type="passkey"]'
                    )).filter(el => isVisible(el));
                    
                    // 5. Look for ARIA elements
                    const ariaPasskeyElements = Array.from(document.querySelectorAll(
                        'button[aria-label*="passkey" i], [role="button"][aria-label*="passkey" i], ' +
                        'button[aria-label*="security key" i], [role="button"][aria-label*="biometric" i]'
                    )).filter(el => isVisible(el));
                    
                    // Build indicators - prioritize visible buttons
                    if (passkeyButtons.length > 0) {
                        // Find the most visible/clickable button
                        const visibleButtons = passkeyButtons.filter(btn => {
                            const rect = btn.getBoundingClientRect();
                            return rect.width > 0 && rect.height > 0;
                        });
                        
                        const btn = visibleButtons.length > 0 ? visibleButtons[0] : passkeyButtons[0];
                        const rect = btn.getBoundingClientRect();
                        results.found = true;
                        results.confidence = isNearAuthContext(btn) ? "HIGH" : "MEDIUM";
                        results.indicators.push(`${passkeyButtons.length} passkey button(s)`);
                        results.element_info = {
                            x: rect.x,
                            y: rect.y,
                            width: rect.width,
                            height: rect.height,
                            inner_text: (btn.innerText || btn.value || btn.textContent || '').trim(),
                            outer_html: btn.outerHTML
                        };
                    } else if (biometricButtons.length > 0) {
                        const btn = biometricButtons[0];
                        const rect = btn.getBoundingClientRect();
                        results.found = true;
                        results.confidence = isNearAuthContext(btn) ? "MEDIUM" : "LOW";
                        results.indicators.push(`${biometricButtons.length} biometric button(s)`);
                        results.element_info = {
                            x: rect.x,
                            y: rect.y,
                            width: rect.width,
                            height: rect.height,
                            inner_text: (btn.innerText || btn.value || btn.textContent || '').trim(),
                            outer_html: btn.outerHTML
                        };
                    } else if (credentialInputs.length > 0) {
                        const input = credentialInputs[0];
                        const rect = input.getBoundingClientRect();
                        results.found = true;
                        results.confidence = "HIGH";
                        results.indicators.push("WebAuthn credential input field");
                        results.element_info = {
                            x: rect.x,
                            y: rect.y,
                            width: rect.width,
                            height: rect.height,
                            inner_text: input.value || input.placeholder || '',
                            outer_html: input.outerHTML
                        };
                    } else if (passkeyAttrElements.length > 0) {
                        const el = passkeyAttrElements[0];
                        const rect = el.getBoundingClientRect();
                        results.found = true;
                        results.confidence = "MEDIUM";
                        results.indicators.push("Element with passkey data attribute");
                        results.element_info = {
                            x: rect.x,
                            y: rect.y,
                            width: rect.width,
                            height: rect.height,
                            inner_text: (el.innerText || el.textContent || '').trim(),
                            outer_html: el.outerHTML
                        };
                    } else if (ariaPasskeyElements.length > 0) {
                        const el = ariaPasskeyElements[0];
                        const rect = el.getBoundingClientRect();
                        results.found = true;
                        results.confidence = "MEDIUM";
                        results.indicators.push("Element with passkey ARIA label");
                        results.element_info = {
                            x: rect.x,
                            y: rect.y,
                            width: rect.width,
                            height: rect.height,
                            inner_text: (el.innerText || el.textContent || '').trim(),
                            outer_html: el.outerHTML
                        };
                    } else {
                        // Check for passkey text in page - be more lenient
                        const bodyText = (document.body.innerText || document.body.textContent || '').toLowerCase();
                        if (/passkey|security.?key|biometric|webauthn|fido/i.test(bodyText)) {
                            // Check if it's in an auth context
                            const hasAuthUrl = /login|signin|auth|account/i.test(window.location.href);
                            const hasAuthTitle = /login|sign.?in|auth/i.test(document.title);
                            if (hasAuthUrl || hasAuthTitle) {
                                results.found = true;
                                results.confidence = "LOW";
                                results.indicators.push("Passkey text found in auth context");
                            }
                        }
                    }
                    
                    return results;
                }
            ''')
            
            if result.get("found") and result.get("element_info"):
                el_info = result["element_info"]
                x = el_info["x"] + el_info["width"] / 2
                y = el_info["y"] + el_info["height"] / 2
                element_tree, _ = DetectionHelper.get_coordinate_metadata(self.page, x, y)
                result["element_info"]["element_tree"] = element_tree
            
            return result
        except Exception as e:
            logger.error(f"Error in UI detection: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return {"found": False, "error": str(e)}
    
    def _detect_javascript(self) -> Dict[str, Any]:
        try:
            result = self.page.evaluate('''
                () => {
                    const results = {
                        found: false,
                        confidence: "LOW",
                        indicators: []
                    };
                    
                    const scripts = Array.from(document.scripts)
                        .filter(s => !s.src)
                        .map(s => s.textContent);
                    
                    const hasCreate = scripts.some(s => 
                        /navigator\.credentials\.create\s*\(\s*\{[\s\S]*?publicKey/.test(s)
                    );
                    const hasGet = scripts.some(s => 
                        /navigator\.credentials\.get\s*\(\s*\{[\s\S]*?publicKey/.test(s)
                    );
                    const hasPlatformCheck = scripts.some(s => 
                        /PublicKeyCredential\.isUserVerifyingPlatformAuthenticatorAvailable/.test(s)
                    );
                    const hasConditionalUI = scripts.some(s => 
                        /PublicKeyCredential\.isConditionalMediationAvailable/.test(s)
                    );
                    
                    if (hasCreate || hasGet) {
                        results.found = true;
                        results.confidence = "HIGH";
                        if (hasCreate) results.indicators.push("Credential creation found");
                        if (hasGet) results.indicators.push("Credential retrieval found");
                    } else if (hasPlatformCheck || hasConditionalUI) {
                        results.found = true;
                        results.confidence = "MEDIUM";
                        results.indicators.push("WebAuthn API checks found");
                    }
                    
                    return results;
                }
            ''')
            return result
        except Exception as e:
            logger.error(f"Error in JS detection: {e}")
            return {"found": False, "error": str(e)}
    
    def _inject_instrumentation(self):
        logger.info("Injecting WebAuthn instrumentation")
        
        import os
        from pathlib import Path
        
        script_path = Path(__file__).parent.parent / "browser" / "js" / "webauthn-instrumentation.js"
        
        if script_path.exists():
            with open(script_path, 'r') as f:
                script = f.read()
            
            self.page.context.add_init_script(script)
            try:
                self.page.add_init_script(script)
                self.page.evaluate(script)
            except Exception:
                pass
            logger.info("Instrumentation injected")
        else:
            logger.warning(f"Instrumentation script not found at {script_path}")
    
    def _setup_virtual_authenticator(self) -> Optional[str]:
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
            logger.error(f"Error clicking passkey button: {e}")
            return False
    
    def _try_fill_username(self) -> bool:
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
            logger.error(f"Error filling username: {e}")
            return False
    
    def _extract_captured_params(self) -> List[Dict[str, Any]]:
        try:
            captures = self.page.evaluate("window.__webauthn_capture || []")
            if captures:
                logger.info(f"Extracted {len(captures)} WebAuthn captures")
            return captures
        except Exception as e:
            logger.error(f"Error extracting captured params: {e}")
            return []
    
    def _get_credentials(self) -> List[Dict[str, Any]]:
        if not self.cdp_manager:
            return []
        
        try:
            credentials = self.cdp_manager.get_credentials()
            if credentials:
                logger.info(f"Retrieved {len(credentials)} credentials")
            return credentials
        except Exception as e:
            logger.error(f"Error getting credentials: {e}")
            return []
    
    def _get_cdp_events(self) -> List[Dict[str, Any]]:
        if not self.cdp_manager:
            return []
        
        try:
            events = self.cdp_manager.get_events()
            if events:
                logger.info(f"Retrieved {len(events)} CDP events")
            return events
        except Exception as e:
            logger.error(f"Error getting CDP events: {e}")
            return []
    
    def _cleanup(self):
        logger.info("Cleaning up passkey mechanism resources")
        if self.cdp_manager:
            self.cdp_manager.close()
            self.cdp_manager = None


