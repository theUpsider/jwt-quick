import { beforeAll, describe, expect, it, jest } from '@jest/globals';
import { TextEncoder } from 'util';
import { Token } from '../src/helpers/Token';
import { jwt } from '../src/index';
import { JWK } from '../src/types';

/* Disclaimer: You should use your own jwksUrl and token for testing
 * This is just a dummy token and jwksUrl
 */

// Mock window.crypto.subtle.importKey
// as it is not available in jest
Object.defineProperty(globalThis, 'crypto', {
    value: {
        subtle: {
            importKey: jest.fn(),
            verify: jest.fn()
        }
    }
});

// Add TextEncoder polyfill for jsdom environment
if (typeof globalThis.TextEncoder === 'undefined') {
    globalThis.TextEncoder = TextEncoder;
}

// Mock fetch
beforeAll(() => {
    global.fetch = () =>
        Promise.resolve({
            ok: true,
            json: () => Promise.resolve({
                keys: [
                    {
                        kty: "RSA",
                        n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                        e: "AQAB",
                        alg: "RS256",
                        kid: "2011-04-29",
                    }
                ]
            })
        } as Response)
})

describe("jwt", () => {
    describe("verifyTokenByJWK", () => {
        it("should return true for a valid token", async () => {
            const token: Token = { header: "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9", payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9", signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" };
            const jwk: JWK = {
                kty: "RSA",
                n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                e: "AQAB",
                alg: "RS256",
                kid: "2011-04-29",
            };
            (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
            (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
            const result = await jwt.verifyTokenByJWK(token, jwk);
            expect(result).toBe(true);
        });

        it("should return false for an invalid token", async () => {
            const token: Token = {
                header: "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9",
                payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            };
            const jwk: JWK = {
                kty: "RSA",
                n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                e: "AQAB",
                alg: "RS256",
                kid: "2011-04-29",
            };
            (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
            (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(false);
            const result = await jwt.verifyTokenByJWK(token, jwk);
            expect(result).toBe(false);
        });
    });

    // Use your own jwks.json file to run this test
    describe("verifyTokenByJWKS", () => {
        it("should return true for a valid token", async () => {
            const token: Token = {
                header: "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAiMjAxMS0wNC0yOSJ9",
                payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            };
            const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
            (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
            (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
            const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
            expect(result).toBe(true);
        });

        it("should return false if no keys match", async () => {
            const token: Token = {
                header: "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAibm9uLWV4aXN0ZW50In0=",
                payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            };
            const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
            const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
            expect(result).toBe(false);
        });
    });
});
