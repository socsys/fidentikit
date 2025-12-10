/**
 * WebAuthn Instrumentation Script
 * 
 * This script intercepts navigator.credentials.create() and navigator.credentials.get()
 * calls to capture WebAuthn parameters before they're sent to the authenticator.
 * 
 * It runs in an isolated world injected via Playwright's addInitScript,
 * ensuring it executes before any page scripts.
 */

(function() {
    'use strict';

    // Helper to convert ArrayBuffer to base64
    function arrayBufferToBase64(buffer) {
        if (!buffer) return null;
        try {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary);
        } catch (e) {
            console.error('Error converting ArrayBuffer to base64:', e);
            return null;
        }
    }

    // Helper to serialize objects with ArrayBuffers
    function serializeWithArrayBuffers(obj, seen = new WeakSet()) {
        if (obj === null || obj === undefined) {
            return obj;
        }

        // Handle circular references
        if (typeof obj === 'object' && seen.has(obj)) {
            return '[Circular]';
        }

        if (typeof obj === 'object') {
            seen.add(obj);
        }

        // Handle ArrayBuffer
        if (obj instanceof ArrayBuffer) {
            return {
                __type__: 'ArrayBuffer',
                __base64__: arrayBufferToBase64(obj),
                __byteLength__: obj.byteLength
            };
        }

        // Handle TypedArrays (Uint8Array, etc.)
        if (ArrayBuffer.isView(obj)) {
            return {
                __type__: obj.constructor.name,
                __base64__: arrayBufferToBase64(obj.buffer),
                __byteLength__: obj.byteLength
            };
        }

        // Handle Arrays
        if (Array.isArray(obj)) {
            return obj.map(item => serializeWithArrayBuffers(item, seen));
        }

        // Handle plain objects
        if (typeof obj === 'object') {
            const serialized = {};
            for (const key in obj) {
                if (obj.hasOwnProperty(key)) {
                    try {
                        serialized[key] = serializeWithArrayBuffers(obj[key], seen);
                    } catch (e) {
                        serialized[key] = `[Error: ${e.message}]`;
                    }
                }
            }
            return serialized;
        }

        // Primitive types
        return obj;
    }

    // Initialize capture storage
    if (!window.__webauthn_capture) {
        window.__webauthn_capture = [];
    }

    // Store original methods
    const originalCredentials = {
        create: navigator.credentials && navigator.credentials.create?.bind(navigator.credentials),
        get: navigator.credentials && navigator.credentials.get?.bind(navigator.credentials)
    };

    // Only instrument if WebAuthn API is available
    if (!navigator.credentials) {
        console.log('[WebAuthn Instrumentation] navigator.credentials not available');
        return;
    }

    // Intercept navigator.credentials.create()
    if (originalCredentials.create) {
        navigator.credentials.create = async function(options) {
            const captureEntry = {
                type: 'create',
                url: window.location.href,
                timestamp: Date.now(),
                options: null,
                result: null,
                error: null
            };

            try {
                // Capture the options
                if (options && options.publicKey) {
                    captureEntry.options = {
                        publicKey: serializeWithArrayBuffers(options.publicKey)
                    };

                    // Extract key parameters
                    const pk = options.publicKey;
                    captureEntry.extracted_params = {
                        rp: {
                            id: pk.rp?.id,
                            name: pk.rp?.name
                        },
                        user: {
                            id_base64: pk.user?.id ? arrayBufferToBase64(pk.user.id) : null,
                            name: pk.user?.name,
                            displayName: pk.user?.displayName
                        },
                        challenge: {
                            base64: pk.challenge ? arrayBufferToBase64(pk.challenge) : null,
                            byteLength: pk.challenge ? pk.challenge.byteLength : 0
                        },
                        pubKeyCredParams: pk.pubKeyCredParams?.map(p => ({
                            type: p.type,
                            alg: p.alg
                        })),
                        timeout: pk.timeout,
                        excludeCredentials: pk.excludeCredentials?.map(c => ({
                            type: c.type,
                            id_base64: c.id ? arrayBufferToBase64(c.id) : null,
                            transports: c.transports
                        })),
                        authenticatorSelection: pk.authenticatorSelection ? {
                            authenticatorAttachment: pk.authenticatorSelection.authenticatorAttachment,
                            requireResidentKey: pk.authenticatorSelection.requireResidentKey,
                            residentKey: pk.authenticatorSelection.residentKey,
                            userVerification: pk.authenticatorSelection.userVerification
                        } : null,
                        attestation: pk.attestation,
                        extensions: pk.extensions
                    };
                }

                console.log('[WebAuthn Instrumentation] Intercepted create() call:', captureEntry);

                // Call original method
                const result = await originalCredentials.create.call(this, options);

                // Capture result
                if (result) {
                    captureEntry.result = {
                        id: result.id,
                        type: result.type,
                        rawId_base64: result.rawId ? arrayBufferToBase64(result.rawId) : null,
                        response: result.response ? {
                            clientDataJSON_base64: result.response.clientDataJSON ? 
                                arrayBufferToBase64(result.response.clientDataJSON) : null,
                            attestationObject_base64: result.response.attestationObject ? 
                                arrayBufferToBase64(result.response.attestationObject) : null
                        } : null
                    };

                    // Try to decode clientDataJSON
                    if (result.response?.clientDataJSON) {
                        try {
                            const decoder = new TextDecoder();
                            const clientDataStr = decoder.decode(result.response.clientDataJSON);
                            captureEntry.result.clientDataJSON_decoded = JSON.parse(clientDataStr);
                        } catch (e) {
                            captureEntry.result.clientDataJSON_decode_error = e.message;
                        }
                    }
                }

                window.__webauthn_capture.push(captureEntry);
                return result;

            } catch (error) {
                captureEntry.error = {
                    name: error.name,
                    message: error.message,
                    code: error.code
                };
                window.__webauthn_capture.push(captureEntry);
                throw error;
            }
        };
    }

    // Intercept navigator.credentials.get()
    if (originalCredentials.get) {
        navigator.credentials.get = async function(options) {
            const captureEntry = {
                type: 'get',
                url: window.location.href,
                timestamp: Date.now(),
                options: null,
                result: null,
                error: null
            };

            try {
                // Capture the options
                if (options && options.publicKey) {
                    captureEntry.options = {
                        publicKey: serializeWithArrayBuffers(options.publicKey)
                    };

                    // Extract key parameters
                    const pk = options.publicKey;
                    captureEntry.extracted_params = {
                        challenge: {
                            base64: pk.challenge ? arrayBufferToBase64(pk.challenge) : null,
                            byteLength: pk.challenge ? pk.challenge.byteLength : 0
                        },
                        timeout: pk.timeout,
                        rpId: pk.rpId,
                        allowCredentials: pk.allowCredentials?.map(c => ({
                            type: c.type,
                            id_base64: c.id ? arrayBufferToBase64(c.id) : null,
                            transports: c.transports
                        })),
                        userVerification: pk.userVerification,
                        extensions: pk.extensions
                    };
                }

                console.log('[WebAuthn Instrumentation] Intercepted get() call:', captureEntry);

                // Call original method
                const result = await originalCredentials.get.call(this, options);

                // Capture result
                if (result) {
                    captureEntry.result = {
                        id: result.id,
                        type: result.type,
                        rawId_base64: result.rawId ? arrayBufferToBase64(result.rawId) : null,
                        response: result.response ? {
                            clientDataJSON_base64: result.response.clientDataJSON ? 
                                arrayBufferToBase64(result.response.clientDataJSON) : null,
                            authenticatorData_base64: result.response.authenticatorData ? 
                                arrayBufferToBase64(result.response.authenticatorData) : null,
                            signature_base64: result.response.signature ? 
                                arrayBufferToBase64(result.response.signature) : null,
                            userHandle_base64: result.response.userHandle ? 
                                arrayBufferToBase64(result.response.userHandle) : null
                        } : null
                    };

                    // Try to decode clientDataJSON
                    if (result.response?.clientDataJSON) {
                        try {
                            const decoder = new TextDecoder();
                            const clientDataStr = decoder.decode(result.response.clientDataJSON);
                            captureEntry.result.clientDataJSON_decoded = JSON.parse(clientDataStr);
                        } catch (e) {
                            captureEntry.result.clientDataJSON_decode_error = e.message;
                        }
                    }
                }

                window.__webauthn_capture.push(captureEntry);
                return result;

            } catch (error) {
                captureEntry.error = {
                    name: error.name,
                    message: error.message,
                    code: error.code
                };
                window.__webauthn_capture.push(captureEntry);
                throw error;
            }
        };
    }

    // Also override isUserVerifyingPlatformAuthenticatorAvailable for better compatibility
    if (window.PublicKeyCredential && window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
        const originalIsUVPAA = window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable.bind(window.PublicKeyCredential);
        window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async function() {
            const result = await originalIsUVPAA();
            console.log('[WebAuthn Instrumentation] isUserVerifyingPlatformAuthenticatorAvailable:', result);
            return result;
        };
    }

    // Override isConditionalMediationAvailable
    if (window.PublicKeyCredential && window.PublicKeyCredential.isConditionalMediationAvailable) {
        const originalIsCMA = window.PublicKeyCredential.isConditionalMediationAvailable.bind(window.PublicKeyCredential);
        window.PublicKeyCredential.isConditionalMediationAvailable = async function() {
            const result = await originalIsCMA();
            console.log('[WebAuthn Instrumentation] isConditionalMediationAvailable:', result);
            return result;
        };
    }

    console.log('[WebAuthn Instrumentation] Instrumentation installed successfully');
})();

