"""
MFAMechanism - Multi-Factor Authentication Detection
Detects OTP, TOTP, SMS, Email, Push, and QR-based MFA implementations.

Detection Categories:
1. OTP_INPUT: Single or segmented OTP input fields
2. TOTP_APP: Authenticator app references (Google/Microsoft Authenticator, Authy)
3. SMS_EMAIL: SMS or email-based verification codes
4. PUSH: Push notification-based authentication
5. QR_CODE: QR code for authenticator setup
"""

import logging
import time
from typing import Dict, Any, Tuple, List, Optional
from playwright.sync_api import Page

logger = logging.getLogger(__name__)


class MFAMechanism:
    """
    Comprehensive MFA detection with reduced false positives.
    Requires strong context signals before confirming MFA presence.
    """
    
    # MFA types
    MFA_TYPES = ["TOTP", "SMS", "EMAIL", "PUSH", "QR", "CUSTOM"]
    
    def __init__(self, page: Page):
        self.page = page
        self.url = None
        
        # Negative indicators - if present, we need stronger signals
        self.negative_indicators = [
            "password",
            "sign up",
            "register",
            "create account",
            "reset password",
            "zip code",
            "postal code",
            "credit card",
            "cvv",
            "ssn",
            "social security",
            "birth",
            "phone number",  # Could be sign-up, not MFA
        ]
        
        # Strong MFA context indicators - these confirm we're in an MFA flow
        self.strong_mfa_context = [
            # 2FA/MFA explicit mentions
            "two-factor authentication",
            "2-factor authentication",
            "multi-factor authentication",
            "two-step verification",
            "2-step verification",
            "additional verification",
            "verify your identity",
            "verify it's you",
            "second step",
            
            # Code delivery
            "we sent a code",
            "code sent to",
            "enter the code we sent",
            "check your phone for a code",
            "check your email for a code",
            "verification code sent",
            
            # Authenticator app
            "use your authenticator app",
            "open your authenticator app",
            "authenticator app code",
            "code from your app",
            
            # Push notification
            "approve the sign-in",
            "approve this login",
            "push notification sent",
            "check your device",
            
            # Security code
            "security code",
            "one-time code",
            "one time code",
            "6-digit code",
            "verification code",
        ]
        
        # TOTP-specific indicators
        self.totp_indicators = [
            "authenticator app",
            "google authenticator",
            "microsoft authenticator",
            "authy",
            "totp",
            "time-based code",
            "code from app",
            "authenticator code",
        ]
        
        # SMS-specific indicators  
        self.sms_indicators = [
            "text message",
            "sms",
            "sent to your phone",
            "sent to your mobile",
            "phone number ending in",
            "mobile ending in",
            "code via text",
            "code by text",
        ]
        
        # Email-specific indicators
        self.email_indicators = [
            "sent to your email",
            "check your inbox",
            "check your email",
            "email ending in",
            "code via email",
            "email verification",
        ]
        
        # Push-specific indicators
        self.push_indicators = [
            "push notification",
            "approve sign-in",
            "approve login",
            "duo push",
            "okta verify",
            "check your device",
            "tap approve",
        ]
        
        # High-confidence OTP input selectors
        self.otp_selectors_high = [
            'input[autocomplete="one-time-code"]',
            'input[name="otp"]',
            'input[name="otpCode"]',
            'input[name="verificationCode"]',
            'input[name="oneTimeCode"]',
            'input[name="totp"]',
            'input[name="mfaCode"]',
            'input[name="2faCode"]',
            'input[id*="otp" i]',
            'input[id*="mfa" i]',
            'input[id*="2fa" i]',
            'input[id*="verification-code" i]',
            'input[aria-label*="verification code" i]',
            'input[aria-label*="one time code" i]',
            'input[aria-label*="otp" i]',
            'input[placeholder*="verification code" i]',
            'input[placeholder*="one time code" i]',
        ]
        
        # Medium-confidence OTP input selectors
        self.otp_selectors_medium = [
            'input[name="code"]',
            'input[placeholder*="code" i][maxlength="6"]',
            'input[placeholder*="code" i][maxlength="8"]',
            'input[aria-label*="code" i][maxlength="6"]',
            'input[type="tel"][maxlength="6"]',
            'input[type="number"][maxlength="6"]',
            'input[inputmode="numeric"][maxlength="6"]',
        ]
        
        # Segmented OTP container selectors
        self.segmented_otp_containers = [
            'div[class*="otp" i]',
            'div[class*="verification" i]',
            'div[class*="code-input" i]',
            'div[class*="mfa" i]',
            'div[class*="2fa" i]',
            'div[id*="otp" i]',
            'div[id*="verification" i]',
        ]

    def detect(self, url: str) -> Dict[str, Any]:
        """
        Detect MFA/2FA on the page with high accuracy.
        Returns structured result compatible with landscape analysis.
        """
        self.url = url
        logger.info(f"Detecting MFA/2FA on: {url}")
        
        result = {
            "mechanism": "mfa",
            "detected": False,
            "mfa_type": None,
            "confidence": "NONE",
            "indicators": [],
            "detection_signals": [],
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
        
        # Check for negative indicators
        has_negative = self._check_negative_indicators()
        required_signals = 2 if has_negative else 1
        
        # Track detection signals
        signals_found = 0
        detection_signals = []
        
        # 1. Check for strong MFA context first
        mfa_context = self._check_mfa_context()
        if mfa_context["found"]:
            signals_found += 1
            detection_signals.append(f"MFA context: {mfa_context['type']}")
            result["mfa_type"] = mfa_context["type"]
        
        # 2. Detect OTP input fields
        otp_result = self._detect_otp_inputs()
        if otp_result["found"]:
            otp_confidence = otp_result["confidence"]
            
            # High confidence OTP or medium with context = count as signal
            if otp_confidence == "HIGH" or (otp_confidence == "MEDIUM" and mfa_context["found"]):
                signals_found += 1
                detection_signals.append(f"OTP input: {otp_result['type']}")
                
                if not result["mfa_type"]:
                    result["mfa_type"] = otp_result.get("mfa_type") or self._determine_type()
                
                # Update element info
                if otp_result.get("element_info"):
                    self._update_element_info(result, otp_result["element_info"])
        
        # 3. Check for MFA text indicators on page
        if signals_found < required_signals:
            text_result = self._detect_mfa_text()
            if text_result["found"]:
                text_confidence = text_result["confidence"]
                
                if text_confidence == "HIGH" or (text_confidence == "MEDIUM" and mfa_context["found"]):
                    signals_found += 1
                    detection_signals.append(f"MFA text: {text_result['mfa_type']}")
                    
                    if not result["mfa_type"]:
                        result["mfa_type"] = text_result["mfa_type"]
        
        # 4. Check for QR code (only in authenticator context)
        if signals_found < required_signals and mfa_context["found"]:
            qr_found = self._detect_qr_code()
            if qr_found:
                signals_found += 1
                detection_signals.append("QR code for authenticator setup")
                if not result["mfa_type"]:
                    result["mfa_type"] = "QR"
        
        # Determine final detection result
        result["detection_signals"] = detection_signals
        
        if signals_found >= required_signals:
            result["detected"] = True
            result["confidence"] = "HIGH" if signals_found > 1 else "MEDIUM"
            result["indicators"] = detection_signals[:5]
            if not result["mfa_type"]:
                result["mfa_type"] = self._determine_type()
        elif otp_result.get("found"):
            # OTP field alone is a strong signal even without context
            result["detected"] = True
            result["confidence"] = otp_result["confidence"]
            result["indicators"] = [f"OTP input field ({otp_result['type']})"]
            if otp_result.get("element_info"):
                self._update_element_info(result, otp_result["element_info"])
            if not result["mfa_type"]:
                result["mfa_type"] = otp_result.get("mfa_type") or self._determine_type()
        elif mfa_context["found"]:
            # Strong MFA context alone
            result["detected"] = True
            result["confidence"] = "MEDIUM"
            result["indicators"] = [f"MFA context ({mfa_context['type']})"]
            if not result["mfa_type"]:
                result["mfa_type"] = mfa_context["type"]
        
        logger.info(f"MFA detection result: detected={result['detected']}, type={result['mfa_type']}, confidence={result['confidence']}")
        return result

    def _wait_for_page_ready(self):
        """Wait for page to be ready for detection."""
        try:
            self.page.wait_for_load_state("domcontentloaded", timeout=5000)
        except:
            pass
        
        # Wait for input fields to appear
        try:
            self.page.wait_for_selector('input[type="text"], input[type="number"], input[maxlength]', timeout=5000, state="attached")
        except:
            pass
        
        time.sleep(1)

    def _check_negative_indicators(self) -> bool:
        """Check if page has negative indicators that require stronger MFA signals."""
        try:
            page_text = self.page.content().lower()
            for indicator in self.negative_indicators:
                if indicator in page_text:
                    logger.debug(f"Found negative indicator: {indicator}")
                    return True
            return False
        except:
            return False

    def _check_mfa_context(self) -> Dict[str, Any]:
        """Check if page is clearly in an MFA flow."""
        try:
            page_text = self.page.content().lower()
            
            # Check for strong MFA context
            for indicator in self.strong_mfa_context:
                if indicator in page_text:
                    mfa_type = self._determine_type_from_text(page_text)
                    logger.debug(f"Found strong MFA context: {indicator}")
                    return {"found": True, "type": mfa_type, "indicator": indicator}
            
            return {"found": False, "type": None}
        except Exception as e:
            logger.debug(f"Error checking MFA context: {e}")
            return {"found": False, "type": None}

    def _determine_type_from_text(self, page_text: str) -> str:
        """Determine MFA type from page text."""
        # Check TOTP
        for indicator in self.totp_indicators:
            if indicator in page_text:
                return "TOTP"
        
        # Check SMS
        for indicator in self.sms_indicators:
            if indicator in page_text:
                return "SMS"
        
        # Check Email
        for indicator in self.email_indicators:
            if indicator in page_text:
                return "EMAIL"
        
        # Check Push
        for indicator in self.push_indicators:
            if indicator in page_text:
                return "PUSH"
        
        return "CUSTOM"

    def _detect_otp_inputs(self) -> Dict[str, Any]:
        """Detect OTP input fields."""
        try:
            from common.modules.helper.detection import DetectionHelper
            
            # Try high-confidence selectors first
            for selector in self.otp_selectors_high:
                try:
                    elements = self.page.query_selector_all(selector)
                    visible_elements = [el for el in elements if self._is_element_visible(el)]
                    
                    if visible_elements:
                        element = visible_elements[0]
                        element_info = self._get_element_info(element)
                        logger.debug(f"Found high-confidence OTP input: {selector}")
                        return {
                            "found": True,
                            "confidence": "HIGH",
                            "type": "single_input",
                            "mfa_type": self._determine_type(),
                            "element_info": element_info
                        }
                except Exception as e:
                    logger.debug(f"Error with selector {selector}: {e}")
            
            # Try medium-confidence selectors
            for selector in self.otp_selectors_medium:
                try:
                    elements = self.page.query_selector_all(selector)
                    visible_elements = [el for el in elements if self._is_element_visible(el)]
                    
                    if visible_elements:
                        element = visible_elements[0]
                        element_info = self._get_element_info(element)
                        logger.debug(f"Found medium-confidence OTP input: {selector}")
                        return {
                            "found": True,
                            "confidence": "MEDIUM",
                            "type": "single_input",
                            "mfa_type": self._determine_type(),
                            "element_info": element_info
                        }
                except Exception as e:
                    logger.debug(f"Error with selector {selector}: {e}")
            
            # Try segmented OTP detection
            segmented_result = self._detect_segmented_otp()
            if segmented_result["found"]:
                return segmented_result
            
            return {"found": False, "confidence": "NONE", "type": None}
            
        except Exception as e:
            logger.debug(f"Error in OTP detection: {e}")
            return {"found": False, "confidence": "NONE", "type": None, "error": str(e)}

    def _detect_segmented_otp(self) -> Dict[str, Any]:
        """Detect segmented OTP inputs (multiple single-digit fields)."""
        try:
            # Look for container with multiple single-digit inputs
            for container_selector in self.segmented_otp_containers:
                try:
                    containers = self.page.query_selector_all(container_selector)
                    
                    for container in containers:
                        inputs = container.query_selector_all('input[maxlength="1"]')
                        visible_inputs = [inp for inp in inputs if self._is_element_visible(inp)]
                        
                        # Segmented OTP typically has 4-8 inputs
                        if 4 <= len(visible_inputs) <= 8:
                            element_info = self._get_element_info(visible_inputs[0])
                            logger.debug(f"Found segmented OTP with {len(visible_inputs)} inputs")
                            return {
                                "found": True,
                                "confidence": "HIGH",
                                "type": f"segmented_{len(visible_inputs)}_digit",
                                "mfa_type": self._determine_type(),
                                "element_info": element_info
                            }
                except:
                    continue
            
            # Fallback: look for adjacent single-digit inputs
            result = self.page.evaluate('''
                () => {
                    const inputs = Array.from(document.querySelectorAll('input[maxlength="1"]'));
                    const visibleInputs = inputs.filter(el => {
                        const rect = el.getBoundingClientRect();
                        const style = window.getComputedStyle(el);
                        return rect.width > 0 && rect.height > 0 && 
                               style.display !== 'none' && style.visibility !== 'hidden';
                    });
                    
                    // Check if inputs are adjacent (likely segmented OTP)
                    if (visibleInputs.length >= 4 && visibleInputs.length <= 8) {
                        // Check if they're horizontally aligned
                        const rects = visibleInputs.map(el => el.getBoundingClientRect());
                        const yPositions = rects.map(r => Math.round(r.y));
                        const sameRow = yPositions.every(y => Math.abs(y - yPositions[0]) < 20);
                        
                        if (sameRow) {
                            const firstRect = rects[0];
                            return {
                                found: true,
                                count: visibleInputs.length,
                                x: firstRect.x,
                                y: firstRect.y,
                                width: firstRect.width,
                                height: firstRect.height,
                                outer_html: visibleInputs[0].outerHTML.substring(0, 500)
                            };
                        }
                    }
                    
                    return { found: false };
                }
            ''')
            
            if result.get("found"):
                return {
                    "found": True,
                    "confidence": "MEDIUM",
                    "type": f"segmented_{result['count']}_digit",
                    "mfa_type": self._determine_type(),
                    "element_info": {
                        "x": result.get("x"),
                        "y": result.get("y"),
                        "width": result.get("width"),
                        "height": result.get("height"),
                        "outer_html": result.get("outer_html"),
                        "inner_text": "",
                        "element_tree": []
                    }
                }
            
            return {"found": False, "confidence": "NONE", "type": None}
            
        except Exception as e:
            logger.debug(f"Error in segmented OTP detection: {e}")
            return {"found": False, "confidence": "NONE", "type": None}

    def _detect_mfa_text(self) -> Dict[str, Any]:
        """Detect MFA-related text on page."""
        try:
            page_text = self.page.content().lower()
            
            # High-confidence text patterns
            high_confidence_patterns = {
                "TOTP": [
                    "code from your authenticator app",
                    "google authenticator code",
                    "microsoft authenticator code",
                    "enter the code from your app",
                    "open your authenticator app",
                ],
                "SMS": [
                    "code sent to your phone",
                    "verification code via sms",
                    "text message with a code",
                    "sms verification code",
                    "we sent a text to",
                ],
                "EMAIL": [
                    "code sent to your email",
                    "verification code via email",
                    "check your inbox for a code",
                    "we sent an email to",
                ],
                "PUSH": [
                    "push notification sent",
                    "approve the sign-in request",
                    "duo push sent",
                    "check your phone to approve",
                ]
            }
            
            for mfa_type, patterns in high_confidence_patterns.items():
                for pattern in patterns:
                    if pattern in page_text:
                        return {"found": True, "confidence": "HIGH", "mfa_type": mfa_type}
            
            # Medium-confidence patterns
            medium_confidence_patterns = {
                "TOTP": ["authenticator", "totp"],
                "SMS": ["sms code", "text message"],
                "EMAIL": ["email code", "check your inbox"],
            }
            
            # Only count medium patterns if we have verification context
            has_verification_context = any(ctx in page_text for ctx in [
                "verification code",
                "enter the code",
                "security code",
            ])
            
            if has_verification_context:
                for mfa_type, patterns in medium_confidence_patterns.items():
                    for pattern in patterns:
                        if pattern in page_text:
                            return {"found": True, "confidence": "MEDIUM", "mfa_type": mfa_type}
            
            return {"found": False, "confidence": "NONE", "mfa_type": None}
            
        except Exception as e:
            logger.debug(f"Error in MFA text detection: {e}")
            return {"found": False, "confidence": "NONE", "mfa_type": None}

    def _detect_qr_code(self) -> bool:
        """Detect QR code for authenticator setup (only in authenticator context)."""
        try:
            page_text = self.page.content().lower()
            
            # Must have authenticator context
            has_auth_context = any(term in page_text for term in [
                "scan qr code",
                "scan this code",
                "authenticator app",
                "google authenticator",
                "microsoft authenticator",
            ])
            
            if not has_auth_context:
                return False
            
            # Look for QR code elements
            qr_selectors = [
                'img[alt*="qr" i]',
                'img[src*="qr" i]',
                'img[class*="qr" i]',
                'canvas[id*="qr" i]',
                'div[class*="qr" i] img',
                'svg[class*="qr" i]',
            ]
            
            for selector in qr_selectors:
                try:
                    elements = self.page.query_selector_all(selector)
                    for element in elements:
                        box = element.bounding_box()
                        if box:
                            # QR codes are typically square and 50-300px
                            width = box['width']
                            height = box['height']
                            if 50 < width < 350 and 50 < height < 350:
                                aspect_ratio = width / height
                                if 0.8 <= aspect_ratio <= 1.2:
                                    logger.debug(f"Found QR code with selector: {selector}")
                                    return True
                except:
                    continue
            
            return False
            
        except Exception as e:
            logger.debug(f"Error in QR code detection: {e}")
            return False

    def _determine_type(self) -> str:
        """Determine MFA type from page context."""
        try:
            page_text = self.page.content().lower()
            return self._determine_type_from_text(page_text)
        except:
            return "CUSTOM"

    def _is_element_visible(self, element) -> bool:
        """Check if element is visible."""
        try:
            box = element.bounding_box()
            if not box:
                return False
            return box['width'] > 0 and box['height'] > 0
        except:
            return False

    def _get_element_info(self, element) -> Dict[str, Any]:
        """Get element information for result."""
        try:
            from common.modules.helper.detection import DetectionHelper
            
            box = element.bounding_box()
            if not box:
                return None
            
            outer_html = element.evaluate("el => el.outerHTML")
            placeholder = element.get_attribute("placeholder") or ""
            value = element.get_attribute("value") or ""
            
            x = box['x'] + box['width'] / 2
            y = box['y'] + box['height'] / 2
            
            try:
                element_tree, _ = DetectionHelper.get_coordinate_metadata(self.page, x, y)
            except:
                element_tree = []
            
            return {
                "x": box['x'],
                "y": box['y'],
                "width": box['width'],
                "height": box['height'],
                "inner_text": value or placeholder,
                "outer_html": outer_html[:500] if outer_html else "",
                "element_tree": element_tree
            }
        except Exception as e:
            logger.debug(f"Error getting element info: {e}")
            return None

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
