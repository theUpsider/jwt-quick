import { Buffer } from 'buffer';

// Currently only supporting Required, Recommended and Recommended+ algorithms
// https://www.rfc-editor.org/rfc/inline-errata/rfc7518.html
const algDict: { [id: string]: string; } = {
    "HS256": "HMAC", // Required
    "RS256": "RSASSA-PKCS1-v1_5", // Recommended
    "ES256": "ECDSA", // Recommended +
    "ES384": "ECDSA", // Optional
    "ES512": "ECDSA", // Optional
}

const findAlg = (alg: string): string => {
    // Explicitly reject "none" algorithm to prevent security bypass
    if (!alg || alg.toLowerCase() === "none") {
        throw new Error("Algorithm 'none' is not allowed");
    }
    
    if (algDict[alg]) {
        return algDict[alg];
    } else {
        throw new Error("Unsupported algorithm: " + alg);
    }
}

const hashDict: { [id: string]: string; } = {
    "HS256": "SHA-256",
    "RS256": "SHA-256",
    "ES256": "SHA-256",
    "ES384": "SHA-384",
    "ES512": "SHA-512"

}

const findHash = (hash: string): string => {
    if (hashDict[hash]) {
        return hashDict[hash];
    } else {
        throw new Error("Unsupported algorithm (hash): " + hash);
    }
}

const decodeBase64toObject = <T>(base64: string): T => {
    try {
        return JSON.parse(decodeBase64(base64));
    } catch (error) {
        throw new Error("Failed to decode base64 or parse JSON: " + (error instanceof Error ? error.message : String(error)));
    }
}

const decodeBase64 = (b64Encoded: string): string => {
    try {
        return Buffer.from(b64Encoded, 'base64').toString();
    } catch (error) {
        throw new Error("Failed to decode base64: " + (error instanceof Error ? error.message : String(error)));
    }
}

export { findAlg, findHash, decodeBase64toObject, decodeBase64 }