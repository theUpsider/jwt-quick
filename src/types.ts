/**
 * Represents the decoded header of a JSON Web Token (JWT).
 * The header contains information about the algorithm used to sign the token and the type of the token.
 */
export type DecodedTokenHeader = {
    alg: string;
    typ: string;
    kid: string;
}

/**
 * Represents the decoded payload of a JSON Web Token (JWT).
 * The payload contains claims about the entity and additional data.
 */
export type DecodedTokenPayload = {
    sub?: string;
    iat?: number; // Issued At
    exp?: number; // Expiration Time
    nbf?: number; // Not Before
    iss?: string; // Issuer
    aud?: string | string[]; // Audience
    jti?: string; // JWT ID
    [key: string]: any; // Allow additional custom claims
}

/**
 * JWK Spec: https://www.rfc-editor.org/rfc/rfc7517#page-3
 */
export type JWK = {
    kty: string; // "kty" (Key Type) Parameter - REQUIRED.  The "kty" (key type) parameter identifies the cryptographic algorithm family used with the key, such as "RSA" or "EC". 
    use?: string; // "use" (Public Key Use) Parameter - OPTIONAL.  The "use" (public key use) parameter identifies the intended use of the public key.  The "use" parameter is employed to indicate whether a public key is used for encrypting data or verifying the signature on data.  If the "use" parameter is not present, its value is assumed to be "sig" (signature).  Valid values are "sig" for signatures, "enc" for encrypting content, and "ver" for verifying signatures.
    key_ops?: string[]; // "key_ops" (Key Operations) Parameter - OPTIONAL.  The "key_ops" (key operations) parameter identifies the operation(s) for which the key is intended
    alg?: string; // "alg" (Algorithm) Parameter - OPTIONAL.  The "alg" (algorithm) parameter identifies the algorithm intended for use with the key.  The values used should either be registered in the IANA "JSON Web Signature and Encryption Algorithms" registry established by [JWA] or be a value that contains a Collision-Resistant Name.  The "alg" value is a case-sensitive ASCII string.  Use of this member is OPTIONAL.
    kid?: string; // "kid" (Key ID) Parameter - OPTIONAL.  The "kid" (key ID) parameter is used to match a specific key.  This is used, for instance, to choose among a set of keys within a JWK Set during key rollover.  The structure of the "kid" value is unspecified.  When "kid" values are used within a JWK Set, different keys within the JWK Set SHOULD use distinct "kid" values.  (One example in which different keys might use the same "kid" value is if they have different "kty" (key type) values but are considered to be equivalent alternatives by the application using them.)  The "kid" value is a case-sensitive string.  Use of this member is OPTIONAL.
    x5u?: string; // "x5u" (X.509 URL) Parameter - OPTIONAL
    x5c?: string; // "x5c" (X.509 Certificate Chain) Parameter - OPTIONAL
    x5t?: string; // "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter - OPTIONAL
    e: string;
    n: string;
    crv?: string;
}
/**
 * JWK Set Spec: https://www.rfc-editor.org/rfc/rfc7517#page-4
 */
export type JWKSet = {
    keys: JWK[]; // "keys" (Public Keys) Parameter - REQUIRED.  The "keys" (public keys) parameter contains the set of public keys.  The value of the "keys" parameter is an array of JWK values.  By default, the set of public keys represents the public keys used to verify any JWS object
}

/**
 * Options for JWT verification
 */
export type VerificationOptions = {
    /**
     * Whether to validate the expiration time (exp claim)
     * Default: true
     */
    validateExpiration?: boolean;
    
    /**
     * Whether to validate the not before time (nbf claim)
     * Default: true
     */
    validateNotBefore?: boolean;
    
    /**
     * Clock tolerance in seconds to account for clock skew
     * Default: 0
     */
    clockTolerance?: number;
    
    /**
     * Current time override for testing purposes (Unix timestamp in seconds)
     * If not provided, uses the current system time
     */
    currentTime?: number;
}