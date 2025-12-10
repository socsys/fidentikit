import logging
import time
import re
from typing import Tuple, List, Dict, Any, Optional
from dataclasses import dataclass
from playwright.sync_api import Page, Response

logger = logging.getLogger(__name__)

@dataclass
class PasskeyIndicator:
    type: str  # UI, JS, DOM, API
    description: str
    confidence: str  # HIGH, MEDIUM, LOW
    context: Dict[str, Any]

@dataclass
class DetectionResult:
    found: bool
    confidence: str
    indicators: List[PasskeyIndicator]
    auth_context: bool
    detection_method: str
    details: Dict[str, Any]

class EnhancedPasskeyDetector:
    """
    Advanced passkey detection with multi-layered validation and improved accuracy.
    Uses multiple detection strategies with cross-validation.
    """
    
    def __init__(self, page: Page):
        self.page = page
        self.url = page.url
        self.processed_urls = set()
        self.detection_cache = {}
        
        # Initialize detection configurations
        self._init_detection_configs()
        
    def _init_detection_configs(self):
        """Initialize detection configuration patterns and rules"""
        self.api_patterns = {
            'core': [
                'navigator.credentials.create',
                'navigator.credentials.get',
                'PublicKeyCredential',
                'authenticatorAttachment',
                'isUserVerifyingPlatformAuthenticatorAvailable'
            ],
            'modern': [
                'isConditionalMediationAvailable',
                'authenticatorSelection',
                'residentKey',
                'userVerification'
            ]
        }
        
        self.dom_patterns = {
            'attributes': [
                'data-webauthn',
                'data-passkey',
                'data-credential',
                'data-authentication-method="passkey"'
            ],
            'elements': [
                '[autocomplete="webauthn"]',
                '[type="publickey"]',
                '[data-auth-type="passkey"]'
            ]
        }
        
        self.libraries = [
            '@simplewebauthn/browser',
            'webauthn-json',
            'fido2-lib',
            '@github/webauthn-json',
            'webauthn-framework'
        ]
        
        self.text_patterns = {
            'high_confidence': [
                r'sign\s+in\s+with\s+passkey',
                r'continue\s+with\s+passkey',
                r'use\s+(?:your\s+)?passkey',
                r'passkey\s+authentication'
            ],
            'medium_confidence': [
                r'passkey',
                r'webauthn',
                r'security\s+key',
                r'biometric\s+authentication'
            ]
        }

    async def detect(self) -> DetectionResult:
        """
        Main detection method that orchestrates multiple detection strategies
        """
        try:
            # Skip if already processed
            if self.url in self.processed_urls:
                return self.detection_cache.get(self.url)
                
            logger.info(f"Starting enhanced passkey detection for {self.url}")
            
            # Initialize result container
            indicators: List[PasskeyIndicator] = []
            
            # 1. Check WebAuthn API availability
            api_available = await self._check_webauthn_api()
            if not api_available:
                logger.info("WebAuthn API not available, skipping detailed detection")
                return self._create_negative_result()
            
            # 2. Perform layered detection
            api_indicators = await self._detect_api_implementation()
            dom_indicators = await self._detect_dom_elements()
            js_indicators = await self._detect_js_implementation()
            ui_indicators = await self._detect_ui_elements()
            
            # Combine all indicators
            indicators.extend(api_indicators)
            indicators.extend(dom_indicators)
            indicators.extend(js_indicators)
            indicators.extend(ui_indicators)
            
            # 3. Validate authentication context
            auth_context = await self._validate_auth_context()
            
            # 4. Calculate final confidence and create result
            result = self._calculate_final_result(indicators, auth_context)
            
            # Cache result
            self.processed_urls.add(self.url)
            self.detection_cache[self.url] = result
            
            return result
            
        except Exception as e:
            logger.error(f"Error in passkey detection: {e}", exc_info=True)
            return self._create_negative_result()
            
    async def _check_webauthn_api(self) -> bool:
        """Check if WebAuthn API is available"""
        try:
            return await self.page.evaluate('''
                () => {
                    return typeof window.PublicKeyCredential !== 'undefined' &&
                           typeof navigator.credentials !== 'undefined';
                }
            ''')
        except Exception as e:
            logger.error(f"Error checking WebAuthn API: {e}")
            return False
            
    async def _detect_api_implementation(self) -> List[PasskeyIndicator]:
        """Detect WebAuthn API implementation details"""
        indicators = []
        try:
            api_check_result = await self.page.evaluate('''
                () => {
                    const results = [];
                    
                    // Check core API methods
                    if (typeof navigator.credentials.create === 'function') {
                        results.push({
                            type: 'core_api',
                            detail: 'credentials.create available'
                        });
                    }
                    
                    if (typeof navigator.credentials.get === 'function') {
                        results.push({
                            type: 'core_api',
                            detail: 'credentials.get available'
                        });
                    }
                    
                    // Check modern API features
                    if (typeof PublicKeyCredential !== 'undefined') {
                        if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
                            results.push({
                                type: 'modern_api',
                                detail: 'platform authenticator check available'
                            });
                        }
                        
                        if (typeof PublicKeyCredential.isConditionalMediationAvailable === 'function') {
                            results.push({
                                type: 'modern_api',
                                detail: 'conditional mediation available'
                            });
                        }
                    }
                    
                    return results;
                }
            ''')
            
            for result in api_check_result:
                confidence = "HIGH" if result['type'] == 'modern_api' else "MEDIUM"
                indicators.append(PasskeyIndicator(
                    type="API",
                    description=result['detail'],
                    confidence=confidence,
                    context={'api_type': result['type']}
                ))
                
        except Exception as e:
            logger.error(f"Error in API detection: {e}")
            
        return indicators
            
    def _create_negative_result(self) -> DetectionResult:
        """Create a negative detection result"""
        return DetectionResult(
            found=False,
            confidence="LOW",
            indicators=[],
            auth_context=False,
            detection_method="NONE",
            details={}
        )
        
    def _calculate_final_result(
        self, 
        indicators: List[PasskeyIndicator],
        auth_context: bool
    ) -> DetectionResult:
        """Calculate final detection result based on all indicators"""
        if not indicators:
            return self._create_negative_result()
            
        # Count indicators by confidence
        high_conf = len([i for i in indicators if i.confidence == "HIGH"])
        med_conf = len([i for i in indicators if i.confidence == "MEDIUM"])
        
        # Determine final confidence
        confidence = "LOW"
        if high_conf >= 2 or (high_conf >= 1 and auth_context):
            confidence = "HIGH"
        elif high_conf >= 1 or (med_conf >= 2 and auth_context):
            confidence = "MEDIUM"
            
        # Determine detection method
        methods = set(i.type for i in indicators)
        detection_method = "+".join(sorted(methods))
        
        return DetectionResult(
            found=True,
            confidence=confidence,
            indicators=indicators[:5],  # Limit to top 5 indicators
            auth_context=auth_context,
            detection_method=detection_method,
            details={
                'indicator_count': len(indicators),
                'high_confidence_count': high_conf,
                'medium_confidence_count': med_conf
            }
        )
        
    async def _detect_ui_elements(self) -> List[PasskeyIndicator]:
        """Detect passkey UI elements with improved accuracy"""
        indicators = []
        try:
            ui_elements = await self.page.evaluate('''
                () => {
                    const results = [];
                    
                    // Helper to check element visibility
                    const isVisible = (el) => {
                        if (!el) return false;
                        const style = window.getComputedStyle(el);
                        return style.display !== 'none' && 
                               style.visibility !== 'hidden' && 
                               style.opacity !== '0' &&
                               el.offsetWidth > 0 && 
                               el.offsetHeight > 0;
                    };
                    
                    // Helper to check if element is likely a social button
                    const isSocialButton = (el) => {
                        const text = (el.textContent || '').toLowerCase();
                        const classes = (el.className || '').toLowerCase();
                        return /facebook|twitter|google|github|linkedin/.test(text) ||
                               /social|oauth/.test(classes);
                    };
                    
                    // 1. Check explicit passkey buttons
                    document.querySelectorAll('button, [role="button"], a').forEach(el => {
                        if (!isVisible(el) || isSocialButton(el)) return;
                        
                        const text = (el.textContent || '').toLowerCase();
                        const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
                        
                        if (/passkey|security.?key|webauthn/.test(text) || 
                            /passkey|security.?key|webauthn/.test(ariaLabel)) {
                            results.push({
                                type: 'button',
                                text: el.textContent?.trim(),
                                ariaLabel,
                                isAuthButton: /sign.?in|log.?in|continue/.test(text)
                            });
                        }
                    });
                    
                    // 2. Check biometric authentication buttons
                    document.querySelectorAll('button, [role="button"], a').forEach(el => {
                        if (!isVisible(el) || isSocialButton(el)) return;
                        
                        const text = (el.textContent || '').toLowerCase();
                        if (/face.?id|touch.?id|fingerprint|biometric/.test(text) &&
                            /sign.?in|log.?in|continue|verify/.test(text)) {
                            results.push({
                                type: 'biometric',
                                text: el.textContent?.trim(),
                                inAuthFlow: true
                            });
                        }
                    });
                    
                    // 3. Check for passkey-specific images and icons
                    document.querySelectorAll('img, svg').forEach(el => {
                        if (!isVisible(el)) return;
                        
                        const alt = (el.getAttribute('alt') || '').toLowerCase();
                        const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
                        
                        if (/passkey|security.?key|fingerprint/.test(alt) || 
                            /passkey|security.?key|fingerprint/.test(ariaLabel)) {
                            results.push({
                                type: 'image',
                                alt,
                                ariaLabel
                            });
                        }
                    });
                    
                    return results;
                }
            ''')
            
            # Process UI elements and create indicators
            for element in ui_elements:
                if element['type'] == 'button':
                    confidence = "HIGH" if element.get('isAuthButton') else "MEDIUM"
                    indicators.append(PasskeyIndicator(
                        type="UI",
                        description=f"Passkey button: {element.get('text', '')}",
                        confidence=confidence,
                        context={'element_type': 'button'}
                    ))
                elif element['type'] == 'biometric':
                    indicators.append(PasskeyIndicator(
                        type="UI",
                        description=f"Biometric auth: {element.get('text', '')}",
                        confidence="MEDIUM",
                        context={'element_type': 'biometric'}
                    ))
                elif element['type'] == 'image':
                    indicators.append(PasskeyIndicator(
                        type="UI",
                        description=f"Passkey image: {element.get('alt', '')}",
                        confidence="LOW",
                        context={'element_type': 'image'}
                    ))
                    
        except Exception as e:
            logger.error(f"Error in UI detection: {e}")
            
        return indicators
        
    async def _detect_dom_elements(self) -> List[PasskeyIndicator]:
        """Detect passkey-related DOM elements and attributes"""
        indicators = []
        try:
            dom_elements = await self.page.evaluate('''
                () => {
                    const results = [];
                    
                    // 1. Check for passkey-specific attributes
                    const attrSelectors = [
                        '[data-webauthn]',
                        '[data-passkey]',
                        '[data-credential]',
                        '[data-authentication-method="passkey"]',
                        '[data-auth-type="passkey"]'
                    ];
                    
                    attrSelectors.forEach(selector => {
                        document.querySelectorAll(selector).forEach(el => {
                            results.push({
                                type: 'attribute',
                                selector,
                                inForm: !!el.closest('form'),
                                nearPassword: !!el.closest('form')?.querySelector('input[type="password"]')
                            });
                        });
                    });
                    
                    // 2. Check for credential inputs
                    document.querySelectorAll('input').forEach(input => {
                        const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
                        const type = (input.getAttribute('type') || '').toLowerCase();
                        
                        if (autocomplete === 'webauthn' || type === 'publickey') {
                            results.push({
                                type: 'input',
                                autocomplete,
                                inputType: type,
                                inForm: !!input.closest('form')
                            });
                        }
                    });
                    
                    // 3. Check for forms with passkey indicators
                    document.querySelectorAll('form').forEach(form => {
                        const formText = form.textContent?.toLowerCase() || '';
                        const hasPasskeyAttr = form.hasAttribute('data-webauthn') || 
                                             form.hasAttribute('data-passkey');
                        
                        if (hasPasskeyAttr || /passkey|webauthn/.test(formText)) {
                            results.push({
                                type: 'form',
                                hasPasskeyAttr,
                                hasAuthFields: !!form.querySelector('input[type="password"], input[type="email"]')
                            });
                        }
                    });
                    
                    return results;
                }
            ''')
            
            # Process DOM elements and create indicators
            for element in dom_elements:
                if element['type'] == 'attribute':
                    confidence = "HIGH" if element.get('inForm') and element.get('nearPassword') else "MEDIUM"
                    indicators.append(PasskeyIndicator(
                        type="DOM",
                        description=f"Passkey attribute: {element.get('selector')}",
                        confidence=confidence,
                        context={'element_type': 'attribute'}
                    ))
                elif element['type'] == 'input':
                    indicators.append(PasskeyIndicator(
                        type="DOM",
                        description="WebAuthn credential input",
                        confidence="HIGH",
                        context={'element_type': 'input'}
                    ))
                elif element['type'] == 'form':
                    confidence = "HIGH" if element.get('hasAuthFields') else "MEDIUM"
                    indicators.append(PasskeyIndicator(
                        type="DOM",
                        description="Passkey-enabled form",
                        confidence=confidence,
                        context={'element_type': 'form'}
                    ))
                    
        except Exception as e:
            logger.error(f"Error in DOM detection: {e}")
            
        return indicators
        
    async def _validate_auth_context(self) -> bool:
        """Validate if we're in an authentication context"""
        try:
            return await self.page.evaluate('''
                () => {
                    // Check URL for auth indicators
                    const url = window.location.href.toLowerCase();
                    if (/login|signin|auth|account|register|signup/.test(url)) {
                        return true;
                    }
                    
                    // Check page title
                    const title = document.title.toLowerCase();
                    if (/login|sign.?in|register|create.?account/.test(title)) {
                        return true;
                    }
                    
                    // Check for auth forms
                    const hasAuthForm = !!document.querySelector(
                        'form input[type="password"], ' +
                        'form input[type="email"][required], ' +
                        'form input[name*="username"][required]'
                    );
                    
                    if (hasAuthForm) {
                        return true;
                    }
                    
                    // Check for auth-related buttons
                    const hasAuthButton = Array.from(
                        document.querySelectorAll('button, [role="button"], input[type="submit"]')
                    ).some(el => {
                        const text = (el.textContent || el.value || '').toLowerCase();
                        return /sign.?in|log.?in|register|create.?account/.test(text);
                    });
                    
                    return hasAuthButton;
                }
            ''')
        except Exception as e:
            logger.error(f"Error validating auth context: {e}")
            return False 

    async def _detect_js_implementation(self) -> List[PasskeyIndicator]:
        """Detect passkey JavaScript implementation with improved accuracy"""
        indicators = []
        try:
            # 1. Collect and analyze script contents
            script_analysis = await self.page.evaluate('''
                () => {
                    const results = {
                        implementations: [],
                        libraries: []
                    };
                    
                    // Helper to safely get script content
                    const getScriptContent = (script) => {
                        try {
                            return script.textContent || '';
                        } catch {
                            return '';
                        }
                    };
                    
                    // Analyze all scripts in the page
                    const scripts = Array.from(document.scripts);
                    scripts.forEach(script => {
                        const content = getScriptContent(script);
                        
                        // Skip empty scripts
                        if (!content.trim()) return;
                        
                        // Check for WebAuthn implementation patterns
                        const patterns = {
                            credential_create: /navigator\.credentials\.create\s*\(\s*\{[\s\S]*?publicKey/,
                            credential_get: /navigator\.credentials\.get\s*\(\s*\{[\s\S]*?publicKey/,
                            platform_check: /isUserVerifyingPlatformAuthenticatorAvailable/,
                            conditional_ui: /isConditionalMediationAvailable/,
                            challenge_handling: /"challenge"\s*:\s*["'][A-Za-z0-9+/=]+["']/,
                            authenticator_selection: /authenticatorSelection\s*:\s*\{[\s\S]*?\}/,
                            user_verification: /userVerification\s*:\s*["'](?:required|preferred)["']/
                        };
                        
                        Object.entries(patterns).forEach(([key, pattern]) => {
                            if (pattern.test(content)) {
                                results.implementations.push({
                                    type: key,
                                    isAsync: /async/.test(content)
                                });
                            }
                        });
                        
                        // Check for common WebAuthn libraries
                        const libraries = [
                            '@simplewebauthn/browser',
                            'webauthn-json',
                            'fido2-lib',
                            '@github/webauthn-json',
                            'webauthn-framework',
                            'passkey-client',
                            'webauthn.io'
                        ];
                        
                        libraries.forEach(lib => {
                            if (content.includes(lib)) {
                                results.libraries.push(lib);
                            }
                        });
                        
                        // Check for passkey-specific function implementations
                        const functionPatterns = [
                            /function\s+(\w+Passkey|\w+WebAuthn|\w+Credential)/,
                            /const\s+(\w+Passkey|\w+WebAuthn|\w+Credential)\s*=/,
                            /let\s+(\w+Passkey|\w+WebAuthn|\w+Credential)\s*=/,
                            /class\s+(\w+Passkey|\w+WebAuthn|\w+Credential)/
                        ];
                        
                        functionPatterns.forEach(pattern => {
                            const matches = content.match(pattern);
                            if (matches) {
                                results.implementations.push({
                                    type: 'custom_implementation',
                                    name: matches[1]
                                });
                            }
                        });
                    });
                    
                    return results;
                }
            ''')
            
            # Process implementation findings
            for impl in script_analysis.get('implementations', []):
                impl_type = impl.get('type', '')
                
                # Determine confidence based on implementation type
                confidence = "MEDIUM"
                if impl_type in ['credential_create', 'credential_get', 'platform_check']:
                    confidence = "HIGH"
                
                description = {
                    'credential_create': 'WebAuthn credential creation',
                    'credential_get': 'WebAuthn credential retrieval',
                    'platform_check': 'Platform authenticator check',
                    'conditional_ui': 'Conditional UI support',
                    'challenge_handling': 'Challenge-response handling',
                    'authenticator_selection': 'Authenticator selection logic',
                    'user_verification': 'User verification configuration',
                    'custom_implementation': f"Custom implementation: {impl.get('name', 'unknown')}"
                }.get(impl_type, impl_type)
                
                indicators.append(PasskeyIndicator(
                    type="JS",
                    description=description,
                    confidence=confidence,
                    context={
                        'implementation_type': impl_type,
                        'is_async': impl.get('isAsync', False)
                    }
                ))
            
            # Process library findings
            for lib in script_analysis.get('libraries', []):
                indicators.append(PasskeyIndicator(
                    type="JS",
                    description=f"WebAuthn library: {lib}",
                    confidence="HIGH",
                    context={'library': lib}
                ))
            
            # Additional dynamic checks
            dynamic_check = await self.page.evaluate('''
                () => {
                    const results = [];
                    
                    // Check for event listeners related to passkey/webauthn
                    const relevantEvents = [
                        'webauthnregister',
                        'webauthnlogin',
                        'passkeyauth',
                        'credentialcreate',
                        'credentialget'
                    ];
                    
                    // Helper to check if an element has relevant event listeners
                    const hasRelevantListener = (el) => {
                        const events = getEventListeners(el);
                        return Object.keys(events).some(event => 
                            relevantEvents.includes(event.toLowerCase())
                        );
                    };
                    
                    try {
                        // Check forms and buttons for relevant event listeners
                        document.querySelectorAll('form, button').forEach(el => {
                            if (hasRelevantListener(el)) {
                                results.push({
                                    type: 'event_listener',
                                    element: el.tagName.toLowerCase(),
                                    inForm: el.tagName === 'FORM' || !!el.closest('form')
                                });
                            }
                        });
                    } catch (e) {
                        // Some browsers may not expose getEventListeners
                        console.error('Event listener check failed:', e);
                    }
                    
                    return results;
                }
            ''')
            
            # Process dynamic check findings
            for check in dynamic_check:
                if check.get('type') == 'event_listener':
                    confidence = "HIGH" if check.get('inForm') else "MEDIUM"
                    indicators.append(PasskeyIndicator(
                        type="JS",
                        description=f"WebAuthn event listener on {check.get('element')}",
                        confidence=confidence,
                        context={'event_type': 'listener'}
                    ))
                    
        except Exception as e:
            logger.error(f"Error in JS detection: {e}")
            
        return indicators 