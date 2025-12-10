import logging
import time
import re
from typing import Tuple, List, Dict, Any
from playwright.sync_api import Page, Response
from modules.browser.browser import PlaywrightHelper
from modules.helper.detection import DetectionHelper
from config.idp_rules import IdpRules

logger = logging.getLogger(__name__)

class PasskeyDetector:
    """
    Detector for Passkey buttons, text references, and elements with a comprehensive
    multi-layered detection strategy
    """

    def __init__(self, result: dict, page: Page):
        self.result = result
        self.page = page
        self.url = None
        self.passkey_keywords = IdpRules["PASSKEY BUTTON"]["keywords"]
        self.script_contents = []  # Store script contents for JS detection
        self.excluded_patterns = [
            # Common patterns that cause false positives
            r"facebook.*\.svg",
            r"social-media.*\.svg",
            r"twitter.*\.svg",
            r"google.*\.svg"
        ]
        self.processed_urls = set()  # Track URLs we've already processed
        
        # Enterprise-specific patterns
        self.enterprise_patterns = {
            "microsoft": {
                "domains": ["login.microsoft.com", "login.live.com", "account.microsoft.com"],
                "elements": ["#idBtn_Back", ".win-button", "[data-bind*='winButton']"],
                "text_patterns": ["Windows Hello", "Security Key", "FIDO2"]
            },
            "adobe": {
                "domains": ["account.adobe.com", "auth.services.adobe.com"],
                "elements": [".spectrum-Button", "[data-testid*='security-key']"],
                "text_patterns": ["Security Key", "Biometric Sign In"]
            },
            "google": {
                "domains": ["accounts.google.com"],
                "elements": ["[data-primary-action-label]", ".ZFr60d"],
                "text_patterns": ["Security Key", "2-Step Verification"]
            }
        }

    def detect_passkey_button(self, url: str) -> Tuple[bool, dict]:
        """
        Detects passkey buttons or links on the current page using a comprehensive
        multi-layered detection approach
        """
        logger.info(f"Checking for passkey buttons on: {url}")
        self.url = url
        
        # If we've already processed this URL, skip it to avoid duplicates
        if url in self.processed_urls:
            logger.info(f"URL {url} already processed, skipping to avoid duplicates")
            return False, None
            
        # Add to processed URLs
        self.processed_urls.add(url)
        
        # Clean up any duplicate entries that might already exist
        self._remove_duplicate_entries(url)
        
        # Track which detection methods have already been used for this URL
        methods_already_detected = set()
        existing_idp = None
        
        # Check for existing passkey detections for this URL
        for idp in self.result.get("recognized_idps", []):
            if (idp.get("idp_name") == "PASSKEY" and idp.get("login_page_url") == url):
                detection_method = idp.get("detection_method", "")
                if detection_method:
                    methods_already_detected.update(detection_method.split("+"))
                existing_idp = idp  # Store the existing idp entry
                break
        
        # If we've already done any detection, update existing entry instead of creating a new one
        if existing_idp:
            logger.info(f"Passkey already detected for {url}, updating existing entry")
            
        # Check if WebAuthn API is available (sanity check)
        webauthn_info = self._check_webauthn_availability()
        if not webauthn_info.get("available", False):
            logger.info("WebAuthn API not available, skipping passkey detection")
            return False, None
            
        # Use a combined approach - run all detection methods and consolidate results
        detection_results = {}
        detection_indicators = []
        highest_validity = "LOW"
        auth_context = False
        
        # Enterprise detection
        enterprise_found, enterprise_details = self._detect_enterprise_implementation()
        if enterprise_found:
            detection_results["ENTERPRISE"] = enterprise_details
            detection_indicators.extend(enterprise_details.get("key_indicators", []))
            highest_validity = enterprise_details.get("confidence", "LOW")
            auth_context = True
        
        # Run UI detection if not already detected
        if "UI" not in methods_already_detected:
            ui_found, ui_details = self._detect_passkey_ui()
            if ui_found:
                logger.info(f"PASSKEY UI detected with confidence: {ui_details.get('confidence')}")
                detection_results["UI"] = ui_details
                detection_indicators.extend(ui_details.get("key_indicators", []))
                
                # Update highest validity
                if ui_details.get("confidence") in ["HIGH", "MEDIUM"]:
                    highest_validity = ui_details.get("confidence")
                
                # Update auth context
                auth_context = auth_context or ui_details.get("in_auth_context", False)
        
        # Run JS detection if not already detected
        if "JS" not in methods_already_detected:
            js_found, js_details = self._detect_passkey_js()
            if js_found:
                logger.info(f"PASSKEY JS detected with confidence: {js_details.get('confidence')}")
                detection_results["JS"] = js_details
                detection_indicators.extend(js_details.get("key_indicators", []))
                
                # Update highest validity
                if js_details.get("confidence") == "HIGH":
                    highest_validity = "HIGH"
        
        # Run keyword detection if not already detected
        if "KEYWORD" not in methods_already_detected:
            kw_found, kw_details = self._detect_passkey_keywords()
            if kw_found:
                logger.info(f"PASSKEY KEYWORD detected with confidence: {kw_details.get('confidence')}")
                detection_results["KEYWORD"] = kw_details
                detection_indicators.extend([f"Text: {ind}" for ind in kw_details.get("key_indicators", [])])
                
                # Update highest validity
                if kw_details.get("confidence") == "HIGH" or (kw_details.get("confidence") == "MEDIUM" and highest_validity != "HIGH"):
                    highest_validity = kw_details.get("confidence")
                
                # Update auth context
                if kw_details.get("in_auth_context", False):
                    auth_context = True
        
        # If no detection, return false
        if not detection_results:
            return False, None
        
        # Construct combined detection method
        detection_methods = "+".join(detection_results.keys())
        if not detection_methods:
            detection_methods = "KEYWORD"  # Fallback
        
        # Limit to unique indicators and cap at 5
        unique_indicators = []
        for indicator in detection_indicators:
            if indicator not in unique_indicators:
                unique_indicators.append(indicator)
                if len(unique_indicators) >= 5:
                    break
        
        # Set default found_in value
        found_in = "ELEMENT"
        
        # Determine the found_in value based on detection results
        if len(detection_results.keys()) > 1:
            found_in = "MULTIPLE"
        elif detection_results:  # Only try to access values if we have results
            first_detection = list(detection_results.values())[0]
            if first_detection:  # Check that the first detection is not None
                found_in = first_detection.get("found_in", "ELEMENT")
        
        # Create or update the passkey detection entry
        combined_details = {
            "idp_name": "PASSKEY",
            "login_page_url": self.url,
            "detection_method": detection_methods,
            "validity": highest_validity,
            "details": {
                "found_in": found_in,
                "secure_context": webauthn_info.get("secure_context", False),
                "key_indicators": unique_indicators,
                "in_auth_context": auth_context,
                "detection_types": list(detection_results.keys())
            }
        }
        
        # If there's an existing entry, update it instead of returning a new one
        if existing_idp:
            # Update the existing IDP entry
            for key, value in combined_details.items():
                existing_idp[key] = value
            logger.info(f"Updated existing Passkey entry for {url}")
            return True, combined_details  # Return combined_details instead of None
        
        logger.info(f"Created new Passkey entry with methods: {detection_methods}")
        return True, combined_details

    def _detect_enterprise_implementation(self) -> Tuple[bool, Dict[str, Any]]:
        try:
            result = self.page.evaluate('''
            (enterprisePatterns) => {
                const results = {
                    found: false,
                    confidence: "LOW",
                    key_indicators: [],
                    found_in: "ENTERPRISE"
                };

                const currentDomain = window.location.hostname;
                
                for (const [provider, patterns] of Object.entries(enterprisePatterns)) {
                    if (patterns.domains.some(domain => currentDomain.includes(domain))) {
                        const elements = patterns.elements.map(selector => 
                            Array.from(document.querySelectorAll(selector))
                        ).flat();
                        
                        const hasElements = elements.length > 0;
                        const hasTextPatterns = patterns.text_patterns.some(pattern => 
                            document.body.innerText.includes(pattern)
                        );
                        
                        if (hasElements || hasTextPatterns) {
                            results.found = true;
                            results.confidence = "HIGH";
                            results.key_indicators.push(`${provider.toUpperCase()} authentication detected`);
                            
                            if (hasElements) {
                                const elementTexts = elements
                                    .map(el => el.innerText || el.value || '')
                                    .filter(Boolean)
                                    .slice(0, 2);
                                elementTexts.forEach(text => 
                                    results.key_indicators.push(`${provider} element: "${text.substring(0, 30)}"`)
                                );
                            }
                        }
                    }
                }
                
                return results;
            }
            ''', self.enterprise_patterns)
            
            return result.get("found", False), result
        except Exception as e:
            logger.error(f"Error in enterprise detection: {e}")
            return False, {"error": str(e)}

    def _check_webauthn_availability(self) -> dict:
        """
        Check if WebAuthn API is available in the browser
        """
        try:
            return self.page.evaluate('''
            () => ({
                available: typeof window.PublicKeyCredential !== 'undefined',
                secure_context: window.isSecureContext === true
            })
            ''')
        except Exception as e:
            logger.error(f"Error checking WebAuthn: {e}")
            return {"available": False, "secure_context": False}

    def _detect_passkey_ui(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Comprehensive detection of passkey UI elements using multiple techniques
        with improved filtering to avoid common false positives
        """
        try:
            # First try basic detection
            result = self._detect_passkey_ui_core()
            
            # If not found, try waiting for dynamic content to load
            if not result.get("found", False):
                logger.debug("Initial UI detection failed, waiting for dynamic content...")
                try:
                    # Wait a bit for dynamic content to load (common JS frameworks have delay)
                    time.sleep(1)
                    self.page.wait_for_timeout(500)  # Extra 500ms in Playwright
                    
                    # Try again after waiting
                    result = self._detect_passkey_ui_core()
                    
                    # If still not found, try scrolling to reveal lazy-loaded content
                    if not result.get("found", False):
                        logger.debug("Secondary UI detection failed, trying scroll...")
                        self.page.evaluate('''
                        () => {
                            window.scrollTo(0, document.body.scrollHeight / 2);
                        }
                        ''')
                        time.sleep(0.5)
                        result = self._detect_passkey_ui_core()
                except Exception as e:
                    logger.debug(f"Error during dynamic content check: {e}")
            
            logger.debug(f"Passkey UI detection result: {result}")
            return result.get("found", False), result
            
        except Exception as e:
            logger.error(f"Error in enhanced passkey UI detection: {e}")
            return False, {"error": str(e)}
            
    def _detect_passkey_ui_core(self) -> Dict[str, Any]:
        """
        Core UI detection logic focusing on actual passkey buttons and forms in DOM
        """
        return self.page.evaluate('''
        () => {
            const results = {
                found: false,
                confidence: "LOW",
                found_in: "ELEMENT",
                in_auth_context: false,
                key_indicators: []
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
            
            // Helper function to check if element is visible and interactive
            const isVisible = (el) => {
                if (!el) return false;
                
                // Check if element or any parent is hidden
                let currentEl = el;
                while (currentEl) {
                    const style = window.getComputedStyle(currentEl);
                    // Reject clearly hidden elements
                    if (style.display === 'none' || 
                        style.visibility === 'hidden' || 
                        style.opacity === '0' || 
                        (style.height === '0px' && style.overflow === 'hidden')) {
                        return false;
                    }
                    currentEl = currentEl.parentElement;
                }
                
                // Check if element is in viewport or reasonable distance outside
                const rect = el.getBoundingClientRect();
                const viewportWidth = window.innerWidth || document.documentElement.clientWidth;
                const viewportHeight = window.innerHeight || document.documentElement.clientHeight;
                
                // Allow elements slightly outside viewport
                const extendedViewport = {
                    left: -300,
                    top: -300,
                    right: viewportWidth + 300,
                    bottom: viewportHeight + 1000 // Allow more space below for scrolling content
                };
                
                const isInViewport = 
                    rect.right > extendedViewport.left &&
                    rect.left < extendedViewport.right &&
                    rect.bottom > extendedViewport.top && 
                    rect.top < extendedViewport.bottom;
                
                // Element must have some size
                return rect.width > 0 && rect.height > 0 && isInViewport;
            };
            
            // Check if element is near authentication context
            const isNearAuthContext = (el) => {
                // Check if element is inside a form
                const isInForm = !!el.closest('form');
                
                // Check if element is near auth inputs
                const nearInputs = !!document.querySelector('input[type="password"], input[type="email"]');
                
                // Check if page has login/auth terms in URL or title
                const hasAuthUrl = /login|signin|auth|account|register|signup/i.test(window.location.href);
                const hasAuthTitle = /login|sign.?in|auth/i.test(document.title);
                
                // Check if element is nearby login buttons
                const loginButtons = Array.from(document.querySelectorAll(
                    'button, input[type="submit"], [role="button"]'
                )).filter(btn => {
                    const text = btn.innerText || btn.value || '';
                    return /sign.?in|log.?in|login|continue|submit/i.test(text);
                });
                
                const nearLoginButton = loginButtons.length > 0;
                
                return isInForm || (nearInputs && (hasAuthUrl || hasAuthTitle || nearLoginButton));
            };
            
            // IMPROVED PASSKEY BUTTON DETECTION
            // 1. Look for explicit passkey buttons by text
            const passkeyButtons = Array.from(document.querySelectorAll(
                'button, a, div[role="button"], span[role="button"], input[type="button"], input[type="submit"]'
            )).filter(el => {
                const text = el.innerText || el.value || '';
                // Expanded passkey terms including "passkey" variations
                return (/passkey|sign.in.with.passkey|continue.with.passkey|use.passkey/i.test(text) ||
                       (/no.?password|passwordless/i.test(text) && 
                        /sign.?in|log.?in|login|continue|sign.?on|auth/i.test(text))) &&
                       !isSocialMediaIcon(el) &&
                       isVisible(el);
            });
            
            // 2. Look for biometric authentication buttons (fingerprint, Face ID, etc.)
            const biometricButtons = Array.from(document.querySelectorAll(
                'button, a, div[role="button"], span[role="button"], input[type="button"], input[type="submit"]'
            )).filter(el => {
                const text = el.innerText || el.value || '';
                // Check for biometric authentication terms
                return (/fingerprint|face.?id|touch.?id|biometric|windows.?hello/i.test(text) &&
                       /sign.?in|log.?in|login|continue|sign.?on|auth/i.test(text)) &&
                       !isSocialMediaIcon(el) &&
                       isVisible(el);
            });
            
            // 3. Look for elements with explicit passkey attributes
            const passkeyAttrElements = Array.from(document.querySelectorAll(
                '[data-webauthn], [data-passkey], [data-credential], ' +
                '[data-authentication-method="passkey"], [data-auth-type="passkey"], ' +
                '[data-login-type="passkey"], [data-auth="webauthn"], ' +
                '[data-method="passkey"], [data-method="webauthn"]'
            )).filter(el => isVisible(el));
            
            // 4. Look for credential inputs
            const credentialInputs = Array.from(document.querySelectorAll(
                'input[autocomplete="webauthn"], input[type="publickey"], ' +
                'input[data-auth-type="passkey"], input[data-credential-type="passkey"]'
            )).filter(el => isVisible(el));
            
            // 5. Look for ARIA elements specifically labeled for passkeys
            const ariaPasskeyElements = Array.from(
                document.querySelectorAll(
                    'button[aria-label*="passkey"], [role="button"][aria-label*="passkey"], ' +
                    'a[aria-label*="passkey"], [role="button"][aria-label*="security key"], ' +
                    'button[aria-label*="fingerprint"], [role="button"][aria-label*="biometric"]'
                )
            ).filter(el => isVisible(el) && !isSocialMediaIcon(el));
            
            // 6. Look for passkey-specific images or icons
            const passkeyImages = Array.from(document.querySelectorAll('img, svg')).filter(el => {
                const alt = el.getAttribute('alt') || '';
                const ariaLabel = el.getAttribute('aria-label') || '';
                const title = el.getAttribute('title') || '';
                
                return isVisible(el) && 
                       /passkey|security.?key|fingerprint|biometric/i.test(alt + ' ' + ariaLabel + ' ' + title) &&
                       !isSocialMediaIcon(el);
            });
            
            // 7. Check for forms with passkey-related attributes or contents
            const passkeyForms = Array.from(document.querySelectorAll('form')).filter(form => {
                // Check if form has passkey attributes
                if (/passkey|webauthn|credential/i.test(form.getAttribute('class') || '') ||
                    /passkey|webauthn|credential/i.test(form.getAttribute('id') || '') ||
                    form.hasAttribute('data-webauthn') ||
                    form.hasAttribute('data-passkey')) {
                    return true;
                }
                
                // Check if form has passkey-related inputs
                const hasPasskeyInput = !!form.querySelector(
                    'input[autocomplete="webauthn"], input[type="publickey"], ' +
                    'input[name*="passkey"], input[name*="webauthn"], input[name*="credential"]'
                );
                
                if (hasPasskeyInput) {
                    return true;
                }
                
                // Check if form has passkey text inside it
                const formText = form.innerText || '';
                return /use.passkey|sign.in.with.passkey|continue.with.passkey/i.test(formText);
            });
            
            // Build key indicators
            const indicators = [];
            
            if (passkeyButtons.length > 0) {
                const buttonTexts = passkeyButtons.map(el => (el.innerText || el.value || '').trim()).filter(Boolean).slice(0, 2);
                buttonTexts.forEach(text => indicators.push(`Passkey button: "${text.substring(0, 30)}"`));
            }
            
            if (biometricButtons.length > 0) {
                const buttonTexts = biometricButtons.map(el => (el.innerText || el.value || '').trim()).filter(Boolean).slice(0, 2);
                buttonTexts.forEach(text => indicators.push(`Biometric button: "${text.substring(0, 30)}"`));
            }
            
            if (passkeyAttrElements.length > 0) {
                indicators.push("Element with passkey data attribute");
            }
            
            if (credentialInputs.length > 0) {
                indicators.push("WebAuthn credential input field");
            }
            
            if (ariaPasskeyElements.length > 0) {
                indicators.push("Element with passkey/biometric ARIA label");
            }
            
            if (passkeyImages.length > 0) {
                indicators.push("Passkey/biometric image/icon");
            }
            
            if (passkeyForms.length > 0) {
                indicators.push("Form with passkey attributes/content");
                results.found_in = "FORM";
            }
            
            // Check for authentication context
            const inAuthContext = (
                (passkeyButtons.length > 0 && passkeyButtons.some(el => isNearAuthContext(el))) ||
                (biometricButtons.length > 0 && biometricButtons.some(el => isNearAuthContext(el))) ||
                (passkeyAttrElements.length > 0 && passkeyAttrElements.some(el => isNearAuthContext(el))) ||
                (credentialInputs.length > 0 && credentialInputs.some(el => isNearAuthContext(el))) ||
                (ariaPasskeyElements.length > 0 && ariaPasskeyElements.some(el => isNearAuthContext(el))) ||
                passkeyForms.length > 0
            );
            
            // Set results
            const hasStrongIndicator = passkeyButtons.length > 0 || credentialInputs.length > 0 || passkeyForms.length > 0;
            const hasMediumIndicator = biometricButtons.length > 0 || passkeyAttrElements.length > 0 || ariaPasskeyElements.length > 0;
            const hasWeakIndicator = passkeyImages.length > 0;
            
            results.found = hasStrongIndicator || hasMediumIndicator || hasWeakIndicator;
            results.key_indicators = indicators;
            results.in_auth_context = inAuthContext;
            
            // Set confidence level based on indicators and auth context
            if (hasStrongIndicator && inAuthContext) {
                results.confidence = "HIGH";
            } else if (hasStrongIndicator || (hasMediumIndicator && inAuthContext)) {
                results.confidence = "MEDIUM";
            } else {
                results.confidence = "LOW";
            }
            
            return results;
        }
        ''')

    def _detect_passkey_js(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Improved detection of passkey JS implementation focusing on actual passkey code
        rather than just API availability
        """
        try:
            # First collect all script contents
            self._collect_script_contents()
            
            # Then perform the detection
            result = self.page.evaluate('''
            () => {
                const results = {
                    found: false,
                    confidence: "LOW",
                    key_indicators: [],
                    libraries: []
                };
                
                // 1. Check WebAuthn API availability (basic requirement)
                const hasWebAuthn = typeof window.PublicKeyCredential !== 'undefined';
                if (!hasWebAuthn) {
                    return results;
                }
                
                // 2. Collect inline scripts
                const inlineScripts = Array.from(document.scripts)
                    .filter(s => !s.src)
                    .map(s => s.textContent);
                
                // 3. Check for WebAuthn implementation patterns in scripts
                // These are specific implementation patterns, not just API checks
                const patternChecks = [
                    {
                        pattern: /navigator\.credentials\.create\s*\(\s*\{[\s\S]*?publicKey\s*:/,
                        description: "WebAuthn credential creation"
                    },
                    {
                        pattern: /navigator\.credentials\.get\s*\(\s*\{[\s\S]*?publicKey\s*:/,
                        description: "WebAuthn credential retrieval" 
                    },
                    {
                        pattern: /PublicKeyCredential\.isUserVerifyingPlatformAuthenticatorAvailable/,
                        description: "Platform authenticator check"
                    },
                    {
                        pattern: /PublicKeyCredential\.isConditionalMediationAvailable/,
                        description: "Conditional mediation check"
                    },
                    {
                        pattern: /\.getCredential\s*\(\s*\{[\s\S]*?type\s*:\s*['"]public-key['"]/,
                        description: "Credential API with public-key type"
                    },
                    {
                        pattern: /\.create\s*\(\s*\{[\s\S]*?type\s*:\s*['"]public-key['"]/,
                        description: "Credential creation with public-key type"
                    },
                    {
                        pattern: /authenticatorAttachment\s*:\s*['"]platform['"]/,
                        description: "Platform authenticator configuration"
                    },
                    {
                        pattern: /authenticatorAttachment\s*:\s*['"]cross-platform['"]/,
                        description: "Security key configuration"
                    },
                    {
                        pattern: /userVerification\s*:\s*['"]preferred|required['"]/,
                        description: "User verification configuration"
                    },
                    {
                        pattern: /"challenge"\s*:\s*["'][A-Za-z0-9+/=]+["']/,
                        description: "WebAuthn challenge data"
                    },
                    {
                        pattern: /"publicKey"\s*:\s*\{[\s\S]*?"challenge"\s*:/,
                        description: "PublicKey credential options"
                    }
                ];
                
                // Check for matches in scripts
                const detectedPatterns = [];
                
                // First 4 patterns are considered strong evidence
                const strongPatternMatches = [];
                for (let i = 0; i < 4; i++) {
                    const check = patternChecks[i];
                    for (const script of inlineScripts) {
                        if (check.pattern.test(script)) {
                            strongPatternMatches.push(check.description);
                            break;
                        }
                    }
                }
                
                // Remaining patterns are medium evidence
                const mediumPatternMatches = [];
                if (strongPatternMatches.length === 0) {
                    for (let i = 4; i < patternChecks.length; i++) {
                        const check = patternChecks[i];
                        for (const script of inlineScripts) {
                            if (check.pattern.test(script)) {
                                mediumPatternMatches.push(check.description);
                                break;
                            }
                        }
                    }
                }
                
                // Check for common WebAuthn libraries
                const commonLibraries = [
                    '@simplewebauthn/browser',
                    'webauthn-json',
                    'fido2-lib',
                    '@github/webauthn-json',
                    'webauthn-framework',
                    'passkey-client',
                    'webauthn.io',
                    'fidoalliance',
                    'passwordless.id'
                ];
                
                const detectedLibraries = [];
                for (const lib of commonLibraries) {
                    for (const script of inlineScripts) {
                        if (script.includes(lib)) {
                            detectedLibraries.push(lib);
                            break;
                        }
                    }
                }
                
                // Check for passkey implementation functions
                const functionPatterns = [
                    {
                        pattern: /function\s+(\w+Passkey|\w+WebAuthn|\w+Credential|\w+PublicKey)/,
                        description: "Passkey/WebAuthn function definition"
                    },
                    {
                        pattern: /passkey(Login|SignIn|Register|Auth)/,
                        description: "Passkey authentication function" 
                    },
                    {
                        pattern: /webauthn(Login|SignIn|Register|Auth)/,
                        description: "WebAuthn authentication function"
                    }
                ];
                
                const detectedFunctions = [];
                for (const funcPattern of functionPatterns) {
                    for (const script of inlineScripts) {
                        if (funcPattern.pattern.test(script)) {
                            detectedFunctions.push(funcPattern.description);
                            break;
                        }
                    }
                }
                
                // Build key indicators
                const indicators = [];
                
                // Add strong pattern matches first
                indicators.push(...strongPatternMatches);
                
                // Then medium pattern matches
                indicators.push(...mediumPatternMatches);
                
                // Add function implementations
                indicators.push(...detectedFunctions);
                
                // Add libraries last
                if (detectedLibraries.length > 0) {
                    detectedLibraries.forEach(lib => {
                        indicators.push(`Library: ${lib}`);
                    });
                }
                
                // Determine if we found actual passkey JS implementation
                // Important: Just having WebAuthn API available is NOT enough
                const hasStrong = strongPatternMatches.length > 0 || 
                                 (detectedLibraries.length > 0 && detectedFunctions.length > 0);
                                 
                const hasMedium = mediumPatternMatches.length > 0 || 
                                 (detectedLibraries.length > 0 || detectedFunctions.length > 0);
                
                // Set results
                results.found = hasStrong || hasMedium;
                results.key_indicators = indicators.slice(0, 5); // Limit to 5 indicators
                results.libraries = detectedLibraries;
                
                // Set confidence level
                if (hasStrong) {
                    results.confidence = "HIGH";
                } else if (hasMedium) {
                    results.confidence = "MEDIUM";
                }
                
                return results;
            }
            ''')
            
            logger.debug(f"Passkey JS detection result: {result}")
            return result.get("found", False), result
            
        except Exception as e:
            logger.error(f"Error in passkey JS detection: {e}")
            return False, {"error": str(e)}

    def _collect_script_contents(self):
        """
        Collect script contents from the page for JS detection
        """
        try:
            # Get external script sources that are likely to contain passkey code
            scripts = self.page.evaluate('''
            () => {
                return Array.from(document.scripts)
                    .filter(s => s.src)
                    .map(s => ({
                        src: s.src,
                        type: s.type || 'text/javascript',
                        hasPasskeyTerms: s.src.toLowerCase().includes('passkey') || 
                                       s.src.toLowerCase().includes('webauthn') ||
                                       s.src.toLowerCase().includes('credential') ||
                                       s.src.toLowerCase().includes('auth')
                    }));
            }
            ''')
            
            logger.debug(f"Found {len(scripts)} external scripts")
            
            # Try to fetch content of passkey-related scripts
            external_scripts = []
            try:
                # Prioritize scripts with passkey terms in URL
                priority_scripts = [s for s in scripts if s.get('hasPasskeyTerms', False)]
                
                # Only fetch a limited number to avoid performance issues
                scripts_to_fetch = priority_scripts[:3]
                
                for script in scripts_to_fetch:
                    try:
                        script_src = script.get('src')
                        if not script_src:
                            continue
                            
                        script_content = self.page.evaluate(f'''
                        async () => {{
                            try {{
                                const controller = new AbortController();
                                const timeoutId = setTimeout(() => controller.abort(), 2000);
                                
                                const response = await fetch("{script_src}", {{ 
                                    signal: controller.signal,
                                    credentials: 'same-origin' 
                                }});
                                
                                clearTimeout(timeoutId);
                                
                                if (response.ok) {{
                                    return await response.text();
                                }}
                            }} catch (e) {{
                                return null;
                            }}
                            return null;
                        }}
                        ''')
                        
                        if script_content and re.search(r'(webauthn|passkey|credential|PublicKeyCredential)', 
                                                      script_content, re.IGNORECASE):
                            external_scripts.append(script_content)
                    except Exception as e:
                        logger.debug(f"Error fetching script {script_src}: {e}")
            except Exception as e:
                logger.debug(f"Error processing external scripts: {e}")
            
            # Get inline scripts
            inline_scripts = self.page.evaluate('''
            () => {
                // Get regular inline scripts
                return Array.from(document.scripts)
                    .filter(s => !s.src)
                    .map(s => s.textContent);
            }
            ''')
            
            self.script_contents = inline_scripts + external_scripts
            logger.debug(f"Collected {len(inline_scripts)} inline scripts and {len(external_scripts)} external scripts")
            
        except Exception as e:
            logger.debug(f"Error collecting script contents: {e}")

    def _detect_passkey_keywords(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Detect presence of passkey keywords in page content as fallback detection.
        """
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
                        
                        const text = el.innerText || '';
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
            
            # Define patterns with increasing specificity and descriptive names
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
            
            return has_passkey, {
                "confidence": highest_confidence,
                "found_in": "TEXT",
                "key_indicators": key_indicators,
                "in_auth_context": in_auth_context
            }
        except Exception as e:
            logger.debug(f"Error in passkey keyword detection: {e}")
            return False, {"error": str(e)}

    def _remove_duplicate_entries(self, url: str) -> None:
        """
        Remove duplicate passkey entries for the given URL from recognized_idps
        """
        if "recognized_idps" not in self.result:
            self.result["recognized_idps"] = []
            return
            
        # Find all passkey entries for this URL
        passkey_entries = [
            (i, idp) for i, idp in enumerate(self.result["recognized_idps"]) 
            if idp.get("idp_name") == "PASSKEY" and idp.get("login_page_url") == url
        ]
        
        # If more than one entry exists, keep only the first one and remove the rest
        if len(passkey_entries) > 1:
            # Sort by indices in descending order to safely remove from the end first
            indices_to_remove = sorted([i for i, _ in passkey_entries[1:]], reverse=True)
            
            logger.info(f"Removing {len(indices_to_remove)} duplicate passkey entries for {url}")
            
            # Remove the duplicates
            for idx in indices_to_remove:
                del self.result["recognized_idps"][idx]
