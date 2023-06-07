# JWT - JWKS Verification Library

This is a TypeScript library for verifying JSON Web Tokens (JWTs) using JSON Web Key (JWK) sets URL endpoints in the browser.

#### Note
This library uses the [Web Crypto Subtle API](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle) to verify JWTs. Cryptography is a complex subject, and it is easy to make mistakes. This is a personal project, and should be used with caution or in controlled environments. I am not a cryptography expert, and I cannot guarantee the security of this library. Please use at your own risk.

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

### `verifyTokenByJWKS(jwksUrl: URL, token: Token): Promise<boolean>`

Verifies a JWT using a JWK set at the specified URL.

- `jwksUrl`: The URL of the JWK set to use for verification.
- `token`: The JWT to verify.

Returns a `Promise` that resolves to `true` if the JWT is valid, or `false` otherwise.

### `verifyTokenByJWK(token: Token, jwk: JWK): Promise<boolean>`

Verifies a JWT using a single JWK.

- `token`: The JWT to verify.
- `jwk`: The JWK to use for verification.

Returns a `Promise` that resolves to `true` if the JWT is valid, or `false` otherwise.

## Supported Algorithms

This library currently supports the following algorithms for verifying JSON Web Tokens (JWTs):

- HMAC using SHA-256 (HS256)
- RSASSA-PKCS1-v1_5 using SHA-256 (RS256)
- ECDSA using SHA-256 (ES256)
- ECDSA using SHA-384 (ES384)
- ECDSA using SHA-512 (ES512)

These algorithms are based on the [JSON Web Algorithms (JWA)](https://www.rfc-editor.org/rfc/rfc7518.html) specification. The library currently only supports the Required, Recommended, and Recommended+ algorithms from the specification.

To use the library with a different algorithm, you will need to modify the `algDict` and `hashDict` objects in the `helper.ts` file to include the new algorithm and its corresponding hash algorithm. You will also need to modify the `verifyTokenByJWK` and `verifyTokenByJWKS` functions to support the new algorithm.

## Support
If you appreciate this library, please consider [buying me a coffee](https://www.buymeacoffee.com/theupsider).
Feel free to create an issue if you have any questions or suggestions. Actively looking for security experts to review the code!

## License

This library is licensed under the [MIT License](LICENSE).