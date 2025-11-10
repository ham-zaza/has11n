// src/utils/cryptoUtils.js

// Derive AES key from PIN (6-digit)
export async function deriveKeyFromPIN(pin) {
    const enc = new TextEncoder();
    const pinBuf = enc.encode(pin.padStart(6, '0')); // ensure 6 digits
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        pinBuf,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    const aesKey = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
    return { aesKey, salt };
}

// Encrypt private key x (as BigInt string)
export async function encryptPrivateKey(xStr, aesKey, salt) {
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    const enc = new TextEncoder();
    const data = enc.encode(xStr);
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        aesKey,
        data
    );
    return {
        encrypted: Array.from(new Uint8Array(encrypted)),
        iv: Array.from(iv),
        salt: Array.from(salt)
    };
}

// Decrypt private key
export async function decryptPrivateKey(encryptedData, pin) {
    const { encrypted, iv, salt } = encryptedData;
    const enc = new TextEncoder();
    const pinBuf = enc.encode(pin.padStart(6, '0'));
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        pinBuf,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    const aesKey = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: new Uint8Array(salt),
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(iv) },
        aesKey,
        new Uint8Array(encrypted)
    );
    const dec = new TextDecoder();
    return dec.decode(decrypted);
}