import logging
import time
import json
import base64
from typing import Dict, Any, List, Tuple
from playwright.sync_api import Page
from common.modules.browser.browser import CDPSessionManager, PlaywrightHelper


logger = logging.getLogger(__name__)


class WebAuthnParamDetector:
    """
    Detects and captures WebAuthn parameters using multiple techniques:
    1. JavaScript instrumentation of navigator.credentials.create/get
    2. CDP WebAuthn events and virtual authenticator
    3. QR code detection for mobile-only flows
    4. Network request analysis
    """

    def __init__(self, page: Page, result: dict, browser_config: dict, detection_config: dict = None, site_domain: str = None):
        self.page = page
        self.result = result
        self.browser_config = browser_config
        self.detection_config = detection_config or {}
        self.site_domain = site_domain
        self.cdp_manager: CDPSessionManager = None
        self.captures: List[Dict[str, Any]] = []
        self.network_requests: List[Dict[str, Any]] = []
        
    def setup_virtual_authenticator(self, 
                                    protocol: str = "ctap2",
                                    transport: str = "internal") -> str:
        """
        Set up a virtual authenticator via CDP
        
        Args:
            protocol: 'ctap2' (FIDO2) or 'u2f' (legacy)
            transport: 'internal' (platform), 'usb', 'ble', 'nfc'
        
        Returns:
            authenticator_id: The ID of the created authenticator
        """
        logger.info(f"Setting up virtual authenticator: protocol={protocol}, transport={transport}")
        
        # Create CDP session manager
        self.cdp_manager = CDPSessionManager(self.page.context, self.page)
        
        # Enable WebAuthn and add virtual authenticator
        self.cdp_manager.enable_webauthn()
        authenticator_id = self.cdp_manager.add_virtual_authenticator(
            protocol=protocol,
            transport=transport,
            has_resident_key=True,
            has_user_verification=True,
            is_user_verified=True,
            automatic_presence_simulation=True,
            is_user_consenting=True
        )
        
        logger.info(f"Virtual authenticator ready: {authenticator_id}")
        return authenticator_id

    def inject_instrumentation(self):
        """
        Inject WebAuthn instrumentation script into the page
        This must be done before navigation via addInitScript
        """
        logger.info("Injecting WebAuthn instrumentation")
        
        # Read instrumentation script from common modules
        import os
        from pathlib import Path
        
        # Use common module's webauthn-instrumentation.js
        # Try multiple paths for flexibility
        script_paths = [
            Path("/app/common/modules/browser/js/webauthn-instrumentation.js"),
            Path(__file__).parent.parent.parent / "common" / "modules" / "browser" / "js" / "webauthn-instrumentation.js"
        ]
        script_path = None
        for sp in script_paths:
            if sp.exists():
                script_path = sp
                break
        
        if not script_path or not script_path.exists():
            logger.warning(f"webauthn-instrumentation.js not found in any expected location")
            return
        
        if script_path.exists():
            with open(script_path, 'r') as f:
                script = f.read()
            
            # Add to context so it runs on all future pages/frames
            self.page.context.add_init_script(script)
            # Also add on this specific page and evaluate immediately for current document
            try:
                self.page.add_init_script(script)
            except Exception:
                pass
            try:
                self.page.evaluate(script)
            except Exception:
                # Evaluate can fail if not yet navigated; it's fine
                pass
            logger.info("WebAuthn instrumentation injected")
        else:
            logger.warning(f"Instrumentation script not found at {script_path}")

    def extract_captured_params(self) -> List[Dict[str, Any]]:
        """
        Extract captured WebAuthn parameters from the page
        
        Returns:
            List of captured WebAuthn calls with parameters
        """
        logger.info("Extracting captured WebAuthn parameters from page")
        
        try:
            captures = self.page.evaluate("window.__webauthn_capture || []")
            
            if captures:
                logger.info(f"Found {len(captures)} WebAuthn captures")
                for i, capture in enumerate(captures, 1):
                    logger.info(f"  Capture {i}: {capture.get('type')} at {capture.get('url')}")
                    
                    # Log extracted parameters
                    if 'extracted_params' in capture:
                        params = capture['extracted_params']
                        if capture['type'] == 'create':
                            logger.info(f"    RP ID: {params.get('rp', {}).get('id')}")
                            logger.info(f"    Challenge length: {params.get('challenge', {}).get('byteLength')} bytes")
                            logger.info(f"    Algorithms: {[p.get('alg') for p in params.get('pubKeyCredParams', [])]}")
                            logger.info(f"    User verification: {params.get('authenticatorSelection', {}).get('userVerification')}")
                            logger.info(f"    Attestation: {params.get('attestation')}")
                        elif capture['type'] == 'get':
                            logger.info(f"    RP ID: {params.get('rpId')}")
                            logger.info(f"    Challenge length: {params.get('challenge', {}).get('byteLength')} bytes")
                            logger.info(f"    User verification: {params.get('userVerification')}")
            else:
                logger.info("No WebAuthn captures found")
            
            return captures
            
        except Exception as e:
            logger.error(f"Error extracting captured params: {e}")
            return []

    def get_cdp_credentials(self) -> List[Dict[str, Any]]:
        """
        Get credentials from the virtual authenticator via CDP
        
        Returns:
            List of credentials stored in the virtual authenticator
        """
        if not self.cdp_manager:
            logger.warning("CDP manager not initialized")
            return []
        
        try:
            credentials = self.cdp_manager.get_credentials()
            
            if credentials:
                logger.info(f"Retrieved {len(credentials)} credentials from virtual authenticator")
                for i, cred in enumerate(credentials, 1):
                    logger.info(f"  Credential {i}:")
                    logger.info(f"    Credential ID: {cred.get('credentialId', 'N/A')}")
                    logger.info(f"    Is resident: {cred.get('isResidentCredential', False)}")
                    logger.info(f"    RP ID: {cred.get('rpId', 'N/A')}")
                    logger.info(f"    User handle: {cred.get('userHandle', 'N/A')}")
                    logger.info(f"    Sign count: {cred.get('signCount', 0)}")
            
            return credentials
            
        except Exception as e:
            logger.error(f"Error getting CDP credentials: {e}")
            return []

    def get_cdp_events(self) -> List[Dict[str, Any]]:
        """
        Get captured CDP WebAuthn events
        
        Returns:
            List of WebAuthn events
        """
        if not self.cdp_manager:
            return []
        
        events = self.cdp_manager.get_events()
        
        if events:
            logger.info(f"Retrieved {len(events)} CDP WebAuthn events")
            for i, event in enumerate(events, 1):
                logger.info(f"  Event {i}: {event.get('type')}")
        
        return events

    def detect_qr_code(self) -> Dict[str, Any]:
        """
        Detect QR codes on the page (for mobile-only passkey flows)
        
        Returns:
            QR code detection results
        """
        logger.info("Detecting QR codes on page")
        
        try:
            # Look for QR code images
            qr_detection = self.page.evaluate("""
                () => {
                    const qrCodes = [];
                    
                    // Look for images that might be QR codes
                    const images = document.querySelectorAll('img, canvas');
                    for (const img of images) {
                        const src = img.src || '';
                        const alt = img.alt || '';
                        const className = img.className || '';
                        
                        // Common QR code patterns
                        if (/qr|code|scan/i.test(src + alt + className)) {
                            qrCodes.push({
                                type: img.tagName.toLowerCase(),
                                src: img.src || null,
                                alt: img.alt || null,
                                className: img.className || null,
                                width: img.width,
                                height: img.height
                            });
                        }
                    }
                    
                    // Look for QR-related text
                    const qrText = [];
                    const bodyText = document.body.innerText || '';
                    if (/scan.*qr|qr.*code|use.*phone/i.test(bodyText)) {
                        qrText.push('QR code related text detected');
                    }
                    
                    return {
                        found: qrCodes.length > 0,
                        qrCodes: qrCodes,
                        qrRelatedText: qrText
                    };
                }
            """)
            
            if qr_detection.get('found'):
                logger.info(f"QR codes detected: {len(qr_detection.get('qrCodes', []))}")
            
            return qr_detection
            
        except Exception as e:
            logger.error(f"Error detecting QR codes: {e}")
            return {"found": False, "error": str(e)}

    def analyze_network_for_webauthn(self) -> List[Dict[str, Any]]:
        """
        Analyze network requests for WebAuthn-related activity
        
        Returns:
            List of WebAuthn-related network requests
        """
        logger.info("Analyzing network requests for WebAuthn activity")
        
        webauthn_requests = []
        
        # This would need to be integrated with HAR capture or network listener
        # For now, return empty list - can be enhanced later
        
        return webauthn_requests

    def attempt_trigger_webauthn(self, url: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Attempt to trigger WebAuthn flow by interacting with the page
        
        Args:
            url: The URL being analyzed
            
        Returns:
            (success, details) tuple
        """
        logger.info(f"Attempting to trigger WebAuthn flow on {url}")
        
        details = {
            "url": url,
            "attempts": [],
            "webauthn_triggered": False
        }
        
        try:
            # Wait for page to be ready
            PlaywrightHelper.wait_for_page_load(self.page, self.browser_config)
            
            # Strategy 0: Passive detection
            passive_wait = int(self.detection_config.get("wait_time", 2))
            logger.info(f"Strategy 0: Passive WebAuthn detection (waiting {passive_wait}s)")
            time.sleep(passive_wait)
            captures = self.extract_captured_params()
            if captures:
                details["webauthn_triggered"] = True
                logger.info("WebAuthn detected passively (auto-triggered on page load)")
                return True, details

            # Strategy 1: Look for passkey/WebAuthn buttons (initial scan) if clicking allowed
            allow_click = bool(self.detection_config.get("allow_click", False))
            if allow_click:
                logger.info("Strategy 1: Initial passkey button scan")
                attempt1 = self._try_click_passkey_buttons()
                details["attempts"].append(attempt1)
            
                if attempt1.get("clicked"):
                    # Wait a bit to see if WebAuthn is triggered
                    time.sleep(3)
                    captures = self.extract_captured_params()
                    if captures:
                        details["webauthn_triggered"] = True
                        logger.info("WebAuthn triggered successfully via button click (initial)")
                        return True, details
            
            # Strategy 2: Try filling username to reveal passkey options
            logger.info("Strategy 2: Filling username to reveal passkey options")
            attempt2 = self._try_login_form_with_passkey()
            details["attempts"].append(attempt2)
            
            if attempt2.get("attempted"):
                # After filling username, check for WebAuthn trigger
                time.sleep(2)
                captures = self.extract_captured_params()
                if captures:
                    details["webauthn_triggered"] = True
                    logger.info("WebAuthn triggered successfully via form interaction")
                    return True, details
                
                # Try clicking buttons again - they might have appeared after username entry
                if allow_click:
                    logger.info("Strategy 2b: Retry clicking passkey buttons after username entry")
                    attempt2b = self._try_click_passkey_buttons()
                    details["attempts"].append(attempt2b)

                    if attempt2b.get("clicked"):
                        time.sleep(3)
                        captures = self.extract_captured_params()
                        if captures:
                            details["webauthn_triggered"] = True
                            logger.info("WebAuthn triggered successfully via button click (after username)")
                            return True, details
            
            # Strategy 3: Check for autofill/conditional UI
            logger.info("Strategy 3: Conditional UI check")
            attempt3 = self._try_conditional_ui()
            details["attempts"].append(attempt3)
            
            if attempt3.get("detected"):
                time.sleep(2)
                captures = self.extract_captured_params()
                if captures:
                    details["webauthn_triggered"] = True
                    logger.info("WebAuthn triggered via conditional UI")
                    return True, details
            
            # Final check - see if WebAuthn was triggered silently
            captures = self.extract_captured_params()
            if captures:
                details["webauthn_triggered"] = True
                logger.info("WebAuthn was triggered silently (captured without explicit interaction)")
                return True, details
            
            logger.info("Could not trigger WebAuthn flow")
            return False, details
            
        except Exception as e:
            logger.error(f"Error attempting to trigger WebAuthn: {e}")
            details["error"] = str(e)
            return False, details

    def _try_click_passkey_buttons(self) -> Dict[str, Any]:
        """Try clicking buttons that might trigger passkey authentication"""
        logger.info("Looking for passkey buttons to click")
        
        try:
            # Wait a bit for dynamic content to load
            time.sleep(2)
            
            result = self.page.evaluate("""
                () => {
                    const buttons = Array.from(document.querySelectorAll(
                        'button, a, [role="button"], input[type="button"], input[type="submit"], div[role="button"]'
                    ));
                    
                    // Passkey-specific keyword patterns (exclude generic SSO like "continue with google")
                    const passkeyKeywords = [
                        'passkey', 'pass key', 'security key', 'biometric', 'fingerprint',
                        'face id', 'touch id', 'webauthn', 'fido', 'authenticator', 'use passkey', 'sign in with passkey', 'sign in with a passkey', 'create a passkey'
                    ];

                    // Third-party SSO providers to skip
                    const thirdPartyProviders = [
                        'google', 'facebook', 'apple', 'microsoft', 'twitter', 'x.com',
                        'github', 'gitlab', 'bitbucket', 'linkedin', 'amazon', 'yahoo',
                        'discord', 'slack', 'oauth', 'saml', 'sso'
                    ];
                    
                    for (const btn of buttons) {
                        const text = (btn.innerText || btn.value || btn.textContent || '').toLowerCase();
                        const ariaLabel = (btn.getAttribute('aria-label') || '').toLowerCase();
                        const title = (btn.getAttribute('title') || '').toLowerCase();
                        const id = (btn.getAttribute('id') || '').toLowerCase();
                        const className = (btn.getAttribute('class') || '').toLowerCase();
                        const allText = text + ' ' + ariaLabel + ' ' + title + ' ' + id + ' ' + className;

                        // Skip third-party SSO buttons
                        const isThirdParty = thirdPartyProviders.some(provider => allText.includes(provider));
                        if (isThirdParty) {
                            continue;
                        }
                        
                        // Check for passkey-related keywords
                        const hasPasskeyKeyword = passkeyKeywords.some(keyword => allText.includes(keyword));
                        
                        if (hasPasskeyKeyword) {
                            // Check if button is visible and clickable
                            const rect = btn.getBoundingClientRect();
                            if (rect.width > 0 && rect.height > 0) {
                                btn.click();
                                return {
                                    clicked: true,
                                    buttonText: text || ariaLabel || title,
                                    buttonType: btn.tagName,
                                    buttonId: id,
                                    buttonClass: className
                                };
                            }
                        }
                    }
                    
                    return { clicked: false };
                }
            """)
            
            if result.get("clicked"):
                logger.info(f"Clicked passkey button: {result.get('buttonText')}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error clicking passkey buttons: {e}")
            return {"clicked": False, "error": str(e)}

    def _try_login_form_with_passkey(self) -> Dict[str, Any]:
        """Try interacting with login forms that have passkey support"""
        logger.info("Looking for login forms with passkey support")
        
        try:
            # First, try to enter a test username to reveal passkey options
            result = self.page.evaluate("""
                () => {
                    // Look for username/email inputs
                    const usernameInputs = Array.from(document.querySelectorAll(
                        'input[type="text"], input[type="email"], input[name*="user"], input[name*="email"], input[id*="user"], input[id*="email"], input[autocomplete*="username"], input[autocomplete*="email"]'
                    ));
                    
                    // Check for webauthn autocomplete first
                    for (const input of usernameInputs) {
                        const autocomplete = input.getAttribute('autocomplete') || '';
                        if (autocomplete.includes('webauthn')) {
                            input.focus();
                            return {
                                attempted: true,
                                method: 'webauthn_autocomplete',
                                inputType: input.type
                            };
                        }
                    }
                    
                    // Try filling in a test email to trigger passkey options
                    if (usernameInputs.length > 0) {
                        const input = usernameInputs[0];
                        input.focus();
                        input.value = 'test@example.com';
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        input.blur();
                        
                        return {
                            attempted: true,
                            method: 'username_filled',
                            inputType: input.type
                        };
                    }
                    
                    return { attempted: false };
                }
            """)
            
            if result.get("attempted"):
                logger.info(f"Triggered login form interaction: {result.get('method')}")
                # Wait for passkey button to appear after username entry
                time.sleep(3)
            
            return result
            
        except Exception as e:
            logger.error(f"Error with login form interaction: {e}")
            return {"attempted": False, "error": str(e)}

    def _try_conditional_ui(self) -> Dict[str, Any]:
        """Check for and try to trigger conditional UI (autofill)"""
        logger.info("Checking for conditional UI support")
        
        try:
            result = self.page.evaluate("""
                async () => {
                    if (!window.PublicKeyCredential || 
                        !PublicKeyCredential.isConditionalMediationAvailable) {
                        return { detected: false, reason: 'API not available' };
                    }
                    
                    try {
                        const available = await PublicKeyCredential.isConditionalMediationAvailable();
                        return {
                            detected: available,
                            conditionalMediationAvailable: available
                        };
                    } catch (e) {
                        return { detected: false, error: e.message };
                    }
                }
            """)
            
            if result.get("detected"):
                logger.info("Conditional UI is available")
            
            return result
            
        except Exception as e:
            logger.error(f"Error checking conditional UI: {e}")
            return {"detected": False, "error": str(e)}

    def cleanup(self):
        """Clean up resources"""
        logger.info("Cleaning up WebAuthn detector resources")
        
        if self.cdp_manager:
            self.cdp_manager.close()
            self.cdp_manager = None
        
        logger.info("Cleanup complete")

