console.log("navcred-tracker.js: execution started");

/**
 * Make credential objects JSON serializable.
 * - https://developer.mozilla.org/en-US/docs/Web/API/Credential
 */

// https://developer.mozilla.org/en-US/docs/Web/API/PasswordCredential
PasswordCredential.prototype.toJSON = function() {
    return {
        id: this.id,
        type: this.type,
        name: this.name,
        iconURL: this.iconURL,
        password: this.password
    }
}

// https://developer.mozilla.org/en-US/docs/Web/API/FederatedCredential
FederatedCredential.prototype.toJSON = function() {
    return {
        id: this.id,
        type: this.type,
        name: this.name,
        iconURL: this.iconURL,
        provider: this.provider,
        protocol: this.protocol
    }
}

// https://developer.mozilla.org/en-US/docs/Web/API/IdentityCredential
IdentityCredential.prototype.toJSON = function() {
    return {
        id: this.id,
        type: this.type,
        token: this.token
    }
}

// https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential
PublicKeyCredential.prototype.toJSON = function() {
    return {
        id: this.id,
        type: this.type,
        rawId: this.rawId ? arrayBufferToBase64(this.rawId) : null,
        response: this.response ? {
            clientDataJSON: arrayBufferToBase64(this.response.clientDataJSON),
            attestationObject: this.response.attestationObject ? arrayBufferToBase64(this.response.attestationObject) : undefined,
            authenticatorData: this.response.authenticatorData ? arrayBufferToBase64(this.response.authenticatorData) : undefined,
            signature: this.response.signature ? arrayBufferToBase64(this.response.signature) : undefined,
            userHandle: this.response.userHandle ? arrayBufferToBase64(this.response.userHandle) : undefined
        } : null,
        authenticatorAttachment: this.authenticatorAttachment
    }
}

/**
 * Helper functions for handling WebAuthn binary data
 */
function arrayBufferToBase64(buffer) {
    if (!buffer) return null;
    
    try {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    } catch (e) {
        console.error("Error converting ArrayBuffer to base64:", e);
        return null;
    }
}

function processPublicKeyCredentialOptions(options) {
    if (!options || typeof options !== 'object') return options;
    
    const processedOptions = JSON.parse(JSON.stringify(options));
    
    // Process challenge (ArrayBuffer or base64url string)
    if (options.challenge instanceof ArrayBuffer) {
        processedOptions.challenge = arrayBufferToBase64(options.challenge);
        processedOptions._challengeEncoding = "base64";
    }
    
    // Process user.id for create()
    if (options.user && options.user.id instanceof ArrayBuffer) {
        processedOptions.user.id = arrayBufferToBase64(options.user.id);
        processedOptions.user._idEncoding = "base64";
    }
    
    // Process excludeCredentials for create()
    if (Array.isArray(options.excludeCredentials)) {
        processedOptions.excludeCredentials = options.excludeCredentials.map(cred => {
            const processed = {...cred};
            if (cred.id instanceof ArrayBuffer) {
                processed.id = arrayBufferToBase64(cred.id);
                processed._idEncoding = "base64";
            }
            return processed;
        });
    }
    
    // Process allowCredentials for get()
    if (Array.isArray(options.allowCredentials)) {
        processedOptions.allowCredentials = options.allowCredentials.map(cred => {
            const processed = {...cred};
            if (cred.id instanceof ArrayBuffer) {
                processed.id = arrayBufferToBase64(cred.id);
                processed._idEncoding = "base64";
            }
            return processed;
        });
    }
    
    return processedOptions;
}

/**
 * Wrap navigator.credentials methods to track their arguments.
 * - https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer
 * - https://web.dev/security-credential-management/
 * - https://blog.sentry.io/wrap-javascript-functions/
 */

window._ssomon_navigator_credentials_create = navigator.credentials.create
navigator.credentials.create = function create(...args) {
    try {
        // Process WebAuthn-specific parameters before logging
        const processedArgs = [...args];
        if (args.length > 0 && args[0] && args[0].publicKey) {
            processedArgs[0] = {...args[0]};
            processedArgs[0].publicKey = processPublicKeyCredentialOptions(args[0].publicKey);
        }
        
        console.log(`navcred-tracker.js: navigator.credentials.create(${JSON.stringify(processedArgs)})`)
        if (window._ssomon_navcred_callback) window._ssomon_navcred_callback("create", processedArgs)
    } catch (error) {
        console.error("Error in navigator.credentials.create wrapper:", error)
    }
    return window._ssomon_navigator_credentials_create.apply(navigator.credentials, args)
}

window._ssomon_navigator_credentials_get = navigator.credentials.get
navigator.credentials.get = function get(...args) {
    try {
        // Process WebAuthn-specific parameters before logging
        const processedArgs = [...args];
        if (args.length > 0 && args[0] && args[0].publicKey) {
            processedArgs[0] = {...args[0]};
            processedArgs[0].publicKey = processPublicKeyCredentialOptions(args[0].publicKey);
        }
        
        console.log(`navcred-tracker.js: navigator.credentials.get(${JSON.stringify(processedArgs)})`)
        if (window._ssomon_navcred_callback) window._ssomon_navcred_callback("get", processedArgs)
    } catch (error) {
        console.error("Error in navigator.credentials.get wrapper:", error)
    }
    return window._ssomon_navigator_credentials_get.apply(navigator.credentials, args)
}

window._ssomon_navigator_credentials_preventSilentAccess = navigator.credentials.preventSilentAccess
navigator.credentials.preventSilentAccess = function preventSilentAccess(...args) {
    try {
        console.log(`navcred-tracker.js: navigator.credentials.preventSilentAccess(${JSON.stringify(args)})`)
        if (window._ssomon_navcred_callback) window._ssomon_navcred_callback("preventSilentAccess", JSON.parse(JSON.stringify(args)))
    } catch (error) {
        console.error(error)
    }
    return window._ssomon_navigator_credentials_preventSilentAccess.apply(navigator.credentials, args)
}

window._ssomon_navigator_credentials_store = navigator.credentials.store
navigator.credentials.store = function store(...args) {
    try {
        console.log(`navcred-tracker.js: navigator.credentials.store(${JSON.stringify(args)})`)
        if (window._ssomon_navcred_callback) window._ssomon_navcred_callback("store", JSON.parse(JSON.stringify(args)))
    } catch (error) {
        console.error(error)
    }
    return window._ssomon_navigator_credentials_store.apply(navigator.credentials, args)
}

// Optionally track network requests related to WebAuthn if sites fetch challenge data via XHR/fetch
if (window.fetch) {
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        const response = await originalFetch.apply(this, args);
        
        try {
            // Clone the response so we can read it without consuming it
            const clone = response.clone();
            
            // Check if request might be related to WebAuthn by URL pattern
            const url = response.url.toLowerCase();
            if (url.includes('webauthn') || 
                url.includes('passkey') || 
                url.includes('credential') || 
                url.includes('auth') || 
                url.includes('signin') ||
                url.includes('login')) {
                
                // Try to parse as JSON
                clone.json().then(data => {
                    // Look for WebAuthn-related fields
                    if (data && 
                        (data.challenge || 
                         data.publicKey || 
                         data.attestation || 
                         data.authenticatorSelection)) {
                         
                        console.log(`navcred-tracker.js: Detected potential WebAuthn network request: ${url}`);
                        if (window._ssomon_navcred_callback) 
                            window._ssomon_navcred_callback("network_request", {
                                url: url,
                                method: args[1]?.method || 'GET',
                                response: data
                            });
                    }
                }).catch(() => {
                    // Not JSON or other error, ignore
                });
            }
        } catch (error) {
            // Ignore errors in our tracking code
            console.error("Error tracking fetch:", error);
        }
        
        return response;
    };
}

console.log("navcred-tracker.js: execution finished");
