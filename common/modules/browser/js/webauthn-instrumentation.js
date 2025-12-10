(function() {
    'use strict';
    
    window.__webauthn_capture = window.__webauthn_capture || [];
    
    if (typeof navigator.credentials === 'undefined') {
        return;
    }
    
    const originalCreate = navigator.credentials.create;
    const originalGet = navigator.credentials.get;
    
    function extractCreateParams(options) {
        if (!options || !options.publicKey) return null;
        
        const pk = options.publicKey;
        return {
            rp: pk.rp ? {id: pk.rp.id, name: pk.rp.name} : null,
            user: pk.user ? {
                id: pk.user.id,
                name: pk.user.name,
                displayName: pk.user.displayName
            } : null,
            challenge: pk.challenge ? {byteLength: pk.challenge.byteLength} : null,
            pubKeyCredParams: pk.pubKeyCredParams || [],
            timeout: pk.timeout,
            excludeCredentials: pk.excludeCredentials || [],
            authenticatorSelection: pk.authenticatorSelection || {},
            attestation: pk.attestation,
            extensions: pk.extensions || {}
        };
    }
    
    function extractGetParams(options) {
        if (!options || !options.publicKey) return null;
        
        const pk = options.publicKey;
        return {
            challenge: pk.challenge ? {byteLength: pk.challenge.byteLength} : null,
            timeout: pk.timeout,
            rpId: pk.rpId,
            allowCredentials: pk.allowCredentials || [],
            userVerification: pk.userVerification,
            extensions: pk.extensions || {}
        };
    }
    
    navigator.credentials.create = function(options) {
        const timestamp = Date.now();
        const extracted = extractCreateParams(options);
        
        window.__webauthn_capture.push({
            type: 'create',
            timestamp: timestamp,
            url: window.location.href,
            extracted_params: extracted,
            raw_options: JSON.parse(JSON.stringify(options, (key, value) => {
                if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
                    return {__type: 'ArrayBuffer', byteLength: value.byteLength};
                }
                return value;
            }))
        });
        
        return originalCreate.apply(this, arguments);
    };
    
    navigator.credentials.get = function(options) {
        const timestamp = Date.now();
        const extracted = extractGetParams(options);
        
        window.__webauthn_capture.push({
            type: 'get',
            timestamp: timestamp,
            url: window.location.href,
            extracted_params: extracted,
            raw_options: JSON.parse(JSON.stringify(options, (key, value) => {
                if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
                    return {__type: 'ArrayBuffer', byteLength: value.byteLength};
                }
                return value;
            }))
        });
        
        return originalGet.apply(this, arguments);
    };
})();


