# JWT - JWKS Verification Library

This is a TypeScript library for verifying JSON Web Tokens (JWTs) using JSON Web Key (JWK) sets URL endpoints in the browser.

#### Note
This library uses the [Web Crypto Subtle API](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle) to verify JWTs. Cryptography is a complex subject, and it is easy to make mistakes. This is a personal project, and should be used with caution or in controlled environments. I am not a cryptography expert, and I cannot guarantee the security of this library. Please use at your own risk.

## Security Features

This library includes comprehensive security measures to protect against common JWT vulnerabilities:

- ✅ **Algorithm Confusion Prevention**: Explicitly rejects the "none" algorithm to prevent signature bypass attacks
- ✅ **Token Structure Validation**: Validates token format, ensuring all required parts are present
- ✅ **Base64 Decoding Protection**: Handles malformed base64 and JSON parsing errors gracefully
- ✅ **Key ID (kid) Validation**: Validates kid exists and matches keys in JWKS
- ✅ **Claims Validation**: Optional validation of exp (expiration), nbf (not before), and iat (issued at) claims
- ✅ **Clock Tolerance**: Configurable clock skew tolerance for time-based claims
- ✅ **Injection Attack Prevention**: Safely handles special characters in kid and other fields
- ✅ **Comprehensive Error Handling**: Returns false or throws descriptive errors for invalid tokens

## Installation

You can install the library using [npm](https://www.npmjs.com/) or [yarn](https://yarnpkg.com/):

```bash
npm install jwt-quick
```

or

```bash
yarn add jwt-quick
```

## Usage

### Basic Token Verification

To use the library, you can import the `verifyTokenByJWKS` function and pass in the URL of the JWK set and the JWT to verify:

```typescript
import { jwt, Token } from "jwt-quick"

const jwksUrl = new URL('https://example.com/.well-known/jwks.json');
const token: Token = {
    header: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    payload: 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
    signature: 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
};

const isValid = await jwt.verifyTokenByJWKS(jwksUrl, token);
console.log(isValid); // true or false
```

### Token Creation from String

You can create a Token object from a JWT string:

```typescript
import { Token } from "jwt-quick"

const jwtString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const token = new Token(jwtString);
```

### Verification with Claims Validation

The library now supports validating JWT claims (exp, nbf, iat) with configurable options:

```typescript
import { jwt, Token, VerificationOptions } from "jwt-quick"

const jwksUrl = new URL('https://example.com/.well-known/jwks.json');
const token = new Token(jwtString);

const options: VerificationOptions = {
    validateExpiration: true,  // Validate exp claim (default: true)
    validateNotBefore: true,   // Validate nbf claim (default: true)
    clockTolerance: 60,        // Allow 60 seconds clock skew (default: 0)
};

const isValid = await jwt.verifyTokenByJWKS(jwksUrl, token, options);
console.log(isValid); // true or false
```

### Verifying with a Single JWK

If you already have a JWK, you can use the `verifyTokenByJWK` function instead:

```typescript
import { jwt, Token } from "jwt-quick"

const token: Token = {
    header: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    payload: 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
    signature: 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
};

const jwk = /* ... */;

const isValid = await jwt.verifyTokenByJWK(token, jwk);
console.log(isValid); // true or false
```
## API

### `verifyTokenByJWKS(jwksUrl: URL, token: Token, options?: VerificationOptions): Promise<boolean>`

Verifies a JWT using a JWK set at the specified URL.

- `jwksUrl`: The URL of the JWK set to use for verification.
- `token`: The JWT to verify.
- `options`: (Optional) Verification options for claims validation.

Returns a `Promise` that resolves to `true` if the JWT is valid, or `false` otherwise.

**Example:**
```typescript
const options: VerificationOptions = {
    validateExpiration: true,
    validateNotBefore: true,
    clockTolerance: 60
};
const isValid = await jwt.verifyTokenByJWKS(jwksUrl, token, options);
```

### `verifyTokenByJWK(token: Token, jwk: JWK, options?: VerificationOptions): Promise<boolean>`

Verifies a JWT using a single JWK.

- `token`: The JWT to verify.
- `jwk`: The JWK to use for verification.
- `options`: (Optional) Verification options for claims validation.

Returns a `Promise` that resolves to `true` if the JWT is valid. Throws an error if the token fails validation due to security issues (invalid algorithm, malformed structure, failed claims validation, etc.).

**Example:**
```typescript
try {
    const isValid = await jwt.verifyTokenByJWK(token, jwk, {
        validateExpiration: true,
        clockTolerance: 30
    });
    console.log('Token is valid:', isValid);
} catch (error) {
    console.error('Token validation failed:', error.message);
}
```

### `VerificationOptions`

Options for configuring JWT verification:

```typescript
type VerificationOptions = {
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
```

### `Token`

Represents a JSON Web Token with its three parts separated:

```typescript
class Token {
    header: string;
    payload: string;
    signature: string;
    
    constructor(token: string); // Creates Token from JWT string
}
```

**Security Validations:**
- Token must be a non-empty string
- Token must have exactly 3 parts separated by dots
- All parts (header, payload, signature) must be non-empty

## Supported Algorithms

This library currently supports the following algorithms for verifying JSON Web Tokens (JWTs):

- HMAC using SHA-256 (HS256) - Required
- RSASSA-PKCS1-v1_5 using SHA-256 (RS256) - Recommended
- ECDSA using SHA-256 (ES256) - Recommended+
- ECDSA using SHA-384 (ES384) - Optional
- ECDSA using SHA-512 (ES512) - Optional

These algorithms are based on the [JSON Web Algorithms (JWA)](https://www.rfc-editor.org/rfc/rfc7518.html) specification. The library currently only supports the Required, Recommended, and Recommended+ algorithms from the specification.

**Security Note:** The "none" algorithm is explicitly rejected (case-insensitive) to prevent signature bypass attacks.

To use the library with a different algorithm, you will need to modify the `algDict` and `hashDict` objects in the `helper.ts` file to include the new algorithm and its corresponding hash algorithm. You will also need to modify the `verifyTokenByJWK` and `verifyTokenByJWKS` functions to support the new algorithm.

## Security Best Practices

When using this library, follow these security best practices:

1. **Always validate claims**: Enable `validateExpiration` and `validateNotBefore` in production environments
2. **Use clock tolerance**: Set a reasonable `clockTolerance` (e.g., 30-60 seconds) to account for clock skew between systems
3. **HTTPS only**: Always fetch JWKS from HTTPS URLs to prevent man-in-the-middle attacks
4. **Error handling**: Properly handle errors when verification fails - don't assume failures are benign
5. **Keep dependencies updated**: Regularly update the library to get security patches
6. **Test your implementation**: Use the provided test patterns to verify your integration

## Edge Cases and Attack Prevention

This library is designed to handle various edge cases and prevent common JWT attacks:

### Algorithm Confusion Attacks
- Rejects "none" algorithm (case-insensitive: "none", "None", "NONE", etc.)
- Validates algorithm matches between token header and JWK
- Throws errors for unsupported algorithms

### Token Structure Attacks
- Validates token has exactly 3 parts
- Ensures all parts are non-empty
- Handles null, undefined, and non-string inputs

### Base64/JSON Attacks
- Gracefully handles invalid base64 encoding
- Catches JSON parsing errors
- Validates structure after decoding

### Key Management
- Validates kid exists in token header for JWKS verification
- Handles missing or null kid values
- Safely compares kid values without injection risks

### Claims Validation
- Validates exp, nbf, and iat are numeric values
- Checks token expiration and not-before times
- Prevents tokens issued in the future
- Supports configurable clock tolerance

### Injection Prevention
- Safely handles special characters in kid
- Protects against SQL injection attempts in kid
- Sanitizes XSS attempts in token fields
- Handles extremely long field values

## Support
If you appreciate this library, please consider [buying me a coffee](https://www.buymeacoffee.com/theupsider).
Feel free to create an issue if you have any questions or suggestions. Actively looking for security experts to review the code!

## License

This library is licensed under the [MIT License](LICENSE).