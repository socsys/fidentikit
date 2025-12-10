import logging
import traceback
from typing import Dict, Any, Tuple
from playwright.sync_api import Page

logger = logging.getLogger(__name__)


class MFAMechanism:
    
    def __init__(self, page: Page):
        self.page = page
        self.url = None
        self.negative_indicators = [
            "password",
            "sign up",
            "register",
            "create account",
            "passkey",
            "reset password",
            "zip code",
            "postal code",
            "credit card",
            "pin",
            "ssn",
            "social security"
        ]
        
    def detect(self, url: str) -> Dict[str, Any]:
        self.url = url
        logger.info(f"Detecting MFA/2FA on: {url}")
        
        result = {
            "mechanism": "mfa",
            "detected": False,
            "mfa_type": None,
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
        
        # Check for negative indicators first - if present, be extra cautious
        try:
            page_text = self.page.content().lower()
            has_negative_indicators = any(indicator in page_text for indicator in self.negative_indicators)
        except:
            has_negative_indicators = False
        
        # If negative indicators are present, we need at least two strong signals to confirm MFA
        required_signals = 2 if has_negative_indicators else 1
        signals_found = 0
        
        # First check if we're in a clear MFA context
        strong_mfa_context = self._has_strong_mfa_context()
        if strong_mfa_context:
            signals_found += 1
            result["indicators"].append("MFA context")
            
        # Try to detect OTP input fields with high confidence
        otp_result = self._detect_otp_inputs()
        otp_input_found = otp_result[0]
        otp_confidence = otp_result[1]
        otp_type = otp_result[2]
        
        if otp_input_found:
            if otp_confidence == "HIGH" or (otp_confidence == "MEDIUM" and strong_mfa_context):
                signals_found += 1
                result["indicators"].append("OTP input field")
                result["mfa_type"] = otp_type
                if otp_result[3]:  # element_info
                    el_info = otp_result[3]
                    result["element_coordinates_x"] = el_info.get("x")
                    result["element_coordinates_y"] = el_info.get("y")
                    result["element_width"] = el_info.get("width")
                    result["element_height"] = el_info.get("height")
                    result["element_inner_text"] = el_info.get("inner_text")
                    result["element_outer_html"] = el_info.get("outer_html")
                    result["element_tree"] = el_info.get("element_tree", [])
                    result["element_validity"] = "HIGH"
        
        # If we haven't found enough signals, try to detect MFA keywords on the page
        if signals_found < required_signals:
            mfa_text_found, mfa_confidence, mfa_text_type = self._detect_mfa_text()
            if mfa_text_found:
                if mfa_confidence == "HIGH" or (mfa_confidence == "MEDIUM" and strong_mfa_context):
                    signals_found += 1
                    result["indicators"].append("MFA text")
                    if not result["mfa_type"]:
                        result["mfa_type"] = mfa_text_type
        
        # Finally check for QR code images only if we have supporting context
        if signals_found < required_signals and strong_mfa_context:
            qr_found = self._detect_qr_code()
            if qr_found:
                signals_found += 1
                result["indicators"].append("QR code")
                if not result["mfa_type"]:
                    result["mfa_type"] = "QR"
        
        # Only report MFA if we found enough signals
        # Be more lenient - if we find an OTP field, that's a strong signal
        if signals_found >= required_signals:
            result["detected"] = True
            result["confidence"] = "HIGH" if signals_found > 1 else "MEDIUM"
            if not result["mfa_type"]:
                result["mfa_type"] = self._determine_type()
        elif otp_input_found:
            # If we find an OTP field, that's a strong signal even without other indicators
            result["detected"] = True
            result["confidence"] = "MEDIUM"
            result["indicators"].append("OTP input field")
            if not result["mfa_type"]:
                result["mfa_type"] = otp_type or self._determine_type()
            if otp_result[3]:  # element_info
                el_info = otp_result[3]
                result["element_coordinates_x"] = el_info.get("x")
                result["element_coordinates_y"] = el_info.get("y")
                result["element_width"] = el_info.get("width")
                result["element_height"] = el_info.get("height")
                result["element_inner_text"] = el_info.get("inner_text")
                result["element_outer_html"] = el_info.get("outer_html")
                result["element_tree"] = el_info.get("element_tree", [])
                result["element_validity"] = "HIGH"
        elif strong_mfa_context:
            # If we have strong MFA context, report it even without OTP field
            result["detected"] = True
            result["confidence"] = "MEDIUM"
            if not result["mfa_type"]:
                result["mfa_type"] = self._determine_type()
        
        logger.info(f"MFA detection final result: detected={result['detected']}, signals={signals_found}, required={required_signals}, indicators={result['indicators']}")
        return result
    
    def _has_strong_mfa_context(self) -> bool:
        """Check if the page has clear indicators of being in an MFA flow"""
        try:
            page_text = self.page.content().lower()
            
            strong_indicators = [
                "two-factor authentication",
                "2-factor authentication", 
                "multi-factor authentication",
                "two-step verification",
                "2-step verification",
                "additional security step",
                "verify your identity",
                "authentication code"
            ]
            
            for indicator in strong_indicators:
                if indicator in page_text:
                    logger.debug(f"Found strong MFA indicator: {indicator}")
                    return True
            
            verification_context = any(ctx in page_text for ctx in [
                "we sent a code to your",
                "enter the code we sent",
                "verification code sent",
                "check your phone for a code",
                "check your email for a code",
                "use your authenticator app"
            ])
            
            if verification_context:
                logger.debug("Found verification context explaining code delivery")
                return True
                
            return False
        except Exception as e:
            logger.debug(f"Error checking MFA context: {e}")
            return False

    def _detect_otp_inputs(self) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Detect OTP input fields that suggest MFA/2FA. Returns: (found, confidence, type, element_info)"""
        try:
            from common.modules.helper.detection import DetectionHelper
            
            # Wait for page to be ready
            try:
                self.page.wait_for_load_state("domcontentloaded", timeout=5000)
            except:
                pass
            
            # Wait for input fields to appear (for dynamic pages)
            try:
                self.page.wait_for_selector('input[type="text"], input[type="number"], input[maxlength]', timeout=10000, state="attached")
            except:
                pass
            
            # Additional wait for dynamic content
            import time
            time.sleep(2)
            
            page_text = self.page.content().lower()
            
            high_confidence_selectors = [
                'input[autocomplete="one-time-code"]',
                'input[name="otp"]',
                'input[name="verificationCode"]',
                'input[aria-label*="verification code" i]',
                'input[placeholder*="verification code" i]',
            ]
            
            medium_confidence_selectors = [
                'input[name="code"]',
                'input[placeholder*="code" i][maxlength="6"]',
                'input[placeholder*="code" i][maxlength="8"]',
                'input[placeholder*="code" i][maxlength="4"]',
            ]
            
            segmented_otp_selectors = [
                'div[class*="otp"] input[maxlength="1"]',
                'div[class*="verification"] input[maxlength="1"]',
                'div[class*="authCode"] input[maxlength="1"]'
            ]
            
            # Check high-confidence selectors first
            for selector in high_confidence_selectors:
                try:
                    elements = self.page.query_selector_all(selector)
                    if elements:
                        logger.debug(f"Found high-confidence OTP input with selector: {selector}")
                        element = elements[0]
                        rect = element.bounding_box()
                        if rect:
                            x = rect['x'] + rect['width'] / 2
                            y = rect['y'] + rect['height'] / 2
                            element_tree, _ = DetectionHelper.get_coordinate_metadata(self.page, x, y)
                            element_info = {
                                "x": rect['x'],
                                "y": rect['y'],
                                "width": rect['width'],
                                "height": rect['height'],
                                "inner_text": element.get_attribute("value") or element.get_attribute("placeholder") or "",
                                "outer_html": element.evaluate("el => el.outerHTML"),
                                "element_tree": element_tree
                            }
                            return True, "HIGH", self._determine_type(), element_info
                except Exception as e:
                    logger.debug(f"Error finding OTP input with selector {selector}: {e}")
            
            # Check medium-confidence selectors
            for selector in medium_confidence_selectors:
                try:
                    elements = self.page.query_selector_all(selector)
                    if elements:
                        element = elements[0]
                        rect = element.bounding_box()
                        if rect:
                            x = rect['x'] + rect['width'] / 2
                            y = rect['y'] + rect['height'] / 2
                            element_tree, _ = DetectionHelper.get_coordinate_metadata(self.page, x, y)
                            element_info = {
                                "x": rect['x'],
                                "y": rect['y'],
                                "width": rect['width'],
                                "height": rect['height'],
                                "inner_text": element.get_attribute("value") or element.get_attribute("placeholder") or "",
                                "outer_html": element.evaluate("el => el.outerHTML"),
                                "element_tree": element_tree
                            }
                            return True, "MEDIUM", self._determine_type(), element_info
                except Exception as e:
                    logger.debug(f"Error finding OTP input with selector {selector}: {e}")
            
            # Check segmented inputs if we have verification context
            verification_context = self._has_strong_mfa_context()
            if verification_context:
                for selector in segmented_otp_selectors:
                    try:
                        elements = self.page.query_selector_all(selector)
                        if elements and len(elements) >= 4:
                            element = elements[0]
                            rect = element.bounding_box()
                            if rect:
                                x = rect['x'] + rect['width'] / 2
                                y = rect['y'] + rect['height'] / 2
                                element_tree, _ = DetectionHelper.get_coordinate_metadata(self.page, x, y)
                                element_info = {
                                    "x": rect['x'],
                                    "y": rect['y'],
                                    "width": rect['width'],
                                    "height": rect['height'],
                                    "inner_text": "",
                                    "outer_html": element.evaluate("el => el.outerHTML"),
                                    "element_tree": element_tree
                                }
                                return True, "MEDIUM", self._determine_type(), element_info
                    except Exception as e:
                        logger.debug(f"Error finding segmented OTP input with selector {selector}: {e}")
        except Exception as e:
            logger.debug(f"Error in OTP detection: {e}")
            
        return False, "", "", None

    def _detect_mfa_text(self) -> Tuple[bool, str, str]:
        """Detect text on the page indicating MFA/2FA. Returns: (found, confidence, type)"""
        try:
            page_text = self.page.content().lower()
            
            high_confidence_indicators = {
                "TOTP": [
                    "authenticator app code",
                    "google authenticator code",
                    "microsoft authenticator code",
                    "authy code",
                    "totp code",
                    "use your authenticator app",
                    "open your authenticator app"
                ],
                "SMS": [
                    "verification code via sms", 
                    "verification code by text", 
                    "code sent to your phone",
                    "text message with a code",
                    "sms verification code",
                    "code sent to phone number",
                    "we've sent a text to"
                ],
                "EMAIL": [
                    "verification code via email",
                    "code sent to your email",
                    "check your inbox for a code",
                    "we've sent a code to your email",
                    "email verification code"
                ]
            }
            
            medium_confidence_indicators = {
                "TOTP": [
                    "authenticator", 
                    "google authenticator", 
                    "microsoft authenticator", 
                    "authy", 
                    "totp"
                ],
                "SMS": [
                    "sms code",
                    "text message code",
                    "via text message"
                ],
                "EMAIL": [
                    "email code", 
                    "sent to your email", 
                    "check your inbox"
                ]
            }
            
            # Check high-confidence indicators first
            for mfa_type, indicators in high_confidence_indicators.items():
                for indicator in indicators:
                    if indicator in page_text:
                        logger.debug(f"Found high-confidence {mfa_type} indicator: {indicator}")
                        return True, "HIGH", mfa_type
            
            # Check medium-confidence indicators only if we have verification context
            verification_context = any(ctx in page_text for ctx in [
                "enter the code",
                "verification code",
                "security code",
                "one-time code",
                "2fa code",
                "two-factor",
                "verify your identity"
            ])
            
            if verification_context:
                for mfa_type, indicators in medium_confidence_indicators.items():
                    for indicator in indicators:
                        if indicator in page_text:
                            logger.debug(f"Found medium-confidence {mfa_type} indicator with verification context: {indicator}")
                            return True, "MEDIUM", mfa_type
        except Exception as e:
            logger.debug(f"Error detecting MFA text: {e}")
            
        return False, "", ""

    def _detect_qr_code(self) -> bool:
        """Detect QR code images on the page, but only if in MFA context"""
        try:
            page_text = self.page.content().lower()
            authenticator_context = any(term in page_text for term in [
                "scan qr code",
                "scan this code", 
                "authenticator app",
                "google authenticator", 
                "microsoft authenticator"
            ])
            
            if not authenticator_context:
                logger.debug("No authenticator app context for QR code")
                return False
            
            qr_selectors = [
                'img[alt*="qr" i]',
                'img[src*="qr" i]',
                'img[class*="qr" i]',
                'canvas[id*="qr" i]',
                'div[class*="qr" i] img',
                'div[class*="qrcode" i]'
            ]
            
            for selector in qr_selectors:
                try:
                    elements = self.page.query_selector_all(selector)
                    if elements:
                        for element in elements:
                            box = element.bounding_box()
                            if box:
                                width = box['width']
                                height = box['height']
                                if width > 50 and height > 50:
                                    aspect_ratio = width / height
                                    if 0.7 <= aspect_ratio <= 1.3:
                                        logger.debug(f"Found QR code with selector: {selector}")
                                        return True
                except Exception as e:
                    logger.debug(f"Error finding QR code with selector {selector}: {e}")
        except Exception as e:
            logger.debug(f"Error in QR code detection: {e}")
            
        return False
    
    def _determine_type(self) -> str:
        """Determine the type of MFA based on page context"""
        try:
            page_text = self.page.content().lower()
            
            if any(keyword in page_text for keyword in [
                "authenticator app", 
                "google authenticator", 
                "microsoft authenticator", 
                "authy", 
                "totp"
            ]):
                return "TOTP"
            elif any(phrase in page_text for phrase in [
                "verification code via sms", 
                "verification code by text", 
                "sent to your phone",
                "text message with a code",
                "sms verification code",
                "security code via text",
                "we sent a text to",
                "mobile number",
                "phone number ending in"
            ]):
                return "SMS"
            elif any(phrase in page_text for phrase in [
                "sent to your email",
                "check your inbox",
                "check your email for a code",
                "verification code via email",
                "email address ending in"
            ]):
                return "EMAIL"
            elif any(keyword in page_text for keyword in ["scan qr code", "scan this code", "scan with authenticator"]):
                return "QR"
            else:
                return "CUSTOM"
        except Exception as e:
            logger.debug(f"Error determining MFA type: {e}")
            return "CUSTOM"


