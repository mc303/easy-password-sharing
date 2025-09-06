function getSecretKey() {
    const urlParams = new URLSearchParams(window.location.hash.substring(1));
    return urlParams.get('key');
}

function setSecretKey(key) {
    window.location.hash = `key=${key}`;
}

function base64urlEncode(buffer) {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) {
        str += '=';
    }
    const binary = atob(str);
    const buffer = new ArrayBuffer(binary.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
        view[i] = binary.charCodeAt(i);
    }
    return buffer;
}

async function generateKey() {
    const key = await crypto.subtle.generateKey(
        {
            name: 'AES-GCM',
            length: 256
        },
        true,
        ['encrypt', 'decrypt']
    );
    
    const exported = await crypto.subtle.exportKey('raw', key);
    return base64urlEncode(exported);
}

async function importKey(keyString) {
    const keyBuffer = base64urlDecode(keyString);
    return await crypto.subtle.importKey(
        'raw',
        keyBuffer,
        {
            name: 'AES-GCM',
            length: 256
        },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptText(plaintext) {
    try {
        if (!plaintext || typeof plaintext !== 'string') {
            throw new Error('Invalid plaintext');
        }
        
        const keyString = await generateKey();
        const key = await importKey(keyString);
        
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const encrypted = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            data
        );
        
        const encryptedData = base64urlEncode(encrypted);
        const ivString = base64urlEncode(iv);
        
        setSecretKey(keyString);
        
        return {
            encryptedData,
            iv: ivString
        };
        
    } catch (error) {
        console.error('Encryption failed:', error);
        throw new Error('Failed to encrypt data');
    }
}

async function decryptText(encryptedData, ivString) {
    try {
        const keyString = getSecretKey();
        if (!keyString) {
            throw new Error('Decryption key not found in URL');
        }
        
        const key = await importKey(keyString);
        const encrypted = base64urlDecode(encryptedData);
        const iv = base64urlDecode(ivString);
        
        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            encrypted
        );
        
        const decoder = new TextDecoder();
        const plaintext = decoder.decode(decrypted);
        
        history.replaceState(null, null, window.location.pathname);
        
        return plaintext;
        
    } catch (error) {
        console.error('Decryption failed:', error);
        throw new Error('Failed to decrypt data. The secret may be corrupted or the link is invalid.');
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        encryptText,
        decryptText,
        generateKey,
        importKey,
        base64urlEncode,
        base64urlDecode
    };
}