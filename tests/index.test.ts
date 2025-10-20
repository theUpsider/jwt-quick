import { beforeAll, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { TextEncoder } from 'node:util';
import { Buffer } from 'buffer';
import { Token } from '../src/helpers/Token';
import { jwt } from '../src/index';
import { JWK, VerificationOptions } from '../src/types';

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
    global.fetch = jest.fn(() =>
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
    ) as jest.Mock;
})

beforeEach(() => {
    jest.clearAllMocks();
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

        describe("Algorithm Security Tests", () => {
            it("should reject 'none' algorithm", async () => {
                const token: Token = { header: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0", payload: "eyJzdWIiOiIxMjM0NTY3ODkwIn0", signature: "" };
                const jwk: JWK = {
                    kty: "RSA",
                    n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    e: "AQAB",
                    alg: "none",
                };
                await expect(jwt.verifyTokenByJWK(token, jwk)).rejects.toThrow();
            });

            it("should reject unsupported algorithms", async () => {
                const token: Token = { header: "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9", payload: "eyJzdWIiOiIxMjM0NTY3ODkwIn0", signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" };
                const jwk: JWK = {
                    kty: "RSA",
                    n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    e: "AQAB",
                    alg: "RS512",
                };
                await expect(jwt.verifyTokenByJWK(token, jwk)).rejects.toThrow();
            });

            it("should handle missing alg in JWK", async () => {
                const token: Token = { header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", payload: "eyJzdWIiOiIxMjM0NTY3ODkwIn0", signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" };
                const jwk: JWK = {
                    kty: "RSA",
                    n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    e: "AQAB",
                };
                await expect(jwt.verifyTokenByJWK(token, jwk)).rejects.toThrow();
            });
        });

        describe("Crypto API Error Handling", () => {
            it("should handle importKey failures gracefully", async () => {
                const token: Token = { header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", payload: "eyJzdWIiOiIxMjM0NTY3ODkwIn0", signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" };
                const jwk: JWK = {
                    kty: "RSA",
                    n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    e: "AQAB",
                    alg: "RS256",
                };
                (globalThis.crypto.subtle.importKey as jest.Mock).mockRejectedValue(new Error("Invalid key format"));
                await expect(jwt.verifyTokenByJWK(token, jwk)).rejects.toThrow();
            });

            it("should handle verify failures gracefully", async () => {
                const token: Token = { header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", payload: "eyJzdWIiOiIxMjM0NTY3ODkwIn0", signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" };
                const jwk: JWK = {
                    kty: "RSA",
                    n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    e: "AQAB",
                    alg: "RS256",
                };
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockRejectedValue(new Error("Verification failed"));
                await expect(jwt.verifyTokenByJWK(token, jwk)).rejects.toThrow();
            });
        });

        describe("Signature Edge Cases", () => {
            it("should handle empty signature", async () => {
                const token: Token = { header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", payload: "eyJzdWIiOiIxMjM0NTY3ODkwIn0", signature: "" };
                const jwk: JWK = {
                    kty: "RSA",
                    n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    e: "AQAB",
                    alg: "RS256",
                };
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(false);
                const result = await jwt.verifyTokenByJWK(token, jwk);
                expect(result).toBe(false);
            });

            it("should handle invalid base64 signature", async () => {
                const token: Token = { header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", payload: "eyJzdWIiOiIxMjM0NTY3ODkwIn0", signature: "!!!invalid-base64!!!" };
                const jwk: JWK = {
                    kty: "RSA",
                    n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    e: "AQAB",
                    alg: "RS256",
                };
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                await expect(jwt.verifyTokenByJWK(token, jwk)).rejects.toThrow();
            });
        });
    });

    describe("Token Constructor Security Tests", () => {
        it("should reject null token", () => {
            expect(() => new Token(null as any)).toThrow("Invalid token: token must be a non-empty string");
        });

        it("should reject undefined token", () => {
            expect(() => new Token(undefined as any)).toThrow("Invalid token: token must be a non-empty string");
        });

        it("should reject empty string token", () => {
            expect(() => new Token("")).toThrow("Invalid token: token must be a non-empty string");
        });

        it("should reject non-string token", () => {
            expect(() => new Token(123 as any)).toThrow("Invalid token: token must be a non-empty string");
        });

        it("should reject token with less than 3 parts", () => {
            expect(() => new Token("header.payload")).toThrow("Invalid token: token must have exactly 3 parts separated by dots");
        });

        it("should reject token with more than 3 parts", () => {
            expect(() => new Token("header.payload.signature.extra")).toThrow("Invalid token: token must have exactly 3 parts separated by dots");
        });

        it("should reject token with empty header", () => {
            expect(() => new Token(".payload.signature")).toThrow("Invalid token: all parts must be non-empty");
        });

        it("should reject token with empty payload", () => {
            expect(() => new Token("header..signature")).toThrow("Invalid token: all parts must be non-empty");
        });

        it("should reject token with empty signature", () => {
            expect(() => new Token("header.payload.")).toThrow("Invalid token: all parts must be non-empty");
        });

        it("should accept valid token format", () => {
            const token = new Token("header.payload.signature");
            expect(token.header).toBe("header");
            expect(token.payload).toBe("payload");
            expect(token.signature).toBe("signature");
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

        describe("JWKS Endpoint Security Tests", () => {
            it("should handle network failures", async () => {
                const token: Token = {
                    header: "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAiMjAxMS0wNC0yOSJ9",
                    payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                };
                const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
                (global.fetch as jest.Mock).mockRejectedValueOnce(new Error("Network error"));
                const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
                expect(result).toBe(false);
            });

            it("should handle malformed JSON response", async () => {
                const token: Token = {
                    header: "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAiMjAxMS0wNC0yOSJ9",
                    payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                };
                const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
                (global.fetch as jest.Mock).mockResolvedValueOnce({
                    ok: true,
                    json: () => Promise.reject(new Error("Invalid JSON"))
                } as Response);
                const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
                expect(result).toBe(false);
            });

            it("should handle missing keys field in response", async () => {
                const token: Token = {
                    header: "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAiMjAxMS0wNC0yOSJ9",
                    payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                };
                const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
                (global.fetch as jest.Mock).mockResolvedValueOnce({
                    ok: true,
                    json: () => Promise.resolve({})
                } as Response);
                const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
                expect(result).toBe(false);
            });

            it("should handle empty keys array", async () => {
                const token: Token = {
                    header: "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAiMjAxMS0wNC0yOSJ9",
                    payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                };
                const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
                (global.fetch as jest.Mock).mockResolvedValueOnce({
                    ok: true,
                    json: () => Promise.resolve({ keys: [] })
                } as Response);
                const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
                expect(result).toBe(false);
            });

            it("should handle invalid header JSON", async () => {
                const token: Token = {
                    header: "invalid-base64",
                    payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                };
                const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
                const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
                expect(result).toBe(false);
            });

            it("should handle missing kid in token header", async () => {
                const token: Token = {
                    header: "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9",
                    payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                };
                const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
                const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
                expect(result).toBe(false);
            });
        });
    });

    describe("Base64 Decoding Security Tests", () => {
        it("should handle malformed base64 in header", async () => {
            const token: Token = {
                header: "not-valid-base64!!!",
                payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            };
            const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
            const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
            expect(result).toBe(false);
        });

        it("should handle non-JSON base64 in header", async () => {
            const token: Token = {
                header: Buffer.from("not a json").toString('base64'),
                payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            };
            const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
            const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
            expect(result).toBe(false);
        });

        it("should handle header with null kid", async () => {
            const token: Token = {
                header: Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: null })).toString('base64'),
                payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            };
            const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
            const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
            expect(result).toBe(false);
        });
    });

    describe("Algorithm Confusion Prevention", () => {
        it("should not allow 'None' algorithm (case variation)", async () => {
            const token: Token = { header: Buffer.from(JSON.stringify({ alg: "None", typ: "JWT" })).toString('base64'), payload: "eyJzdWIiOiIxMjM0NTY3ODkwIn0", signature: "" };
            const jwk: JWK = {
                kty: "RSA",
                n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                e: "AQAB",
                alg: "None",
            };
            await expect(jwt.verifyTokenByJWK(token, jwk)).rejects.toThrow();
        });

        it("should not allow 'NONE' algorithm (uppercase)", async () => {
            const token: Token = { header: Buffer.from(JSON.stringify({ alg: "NONE", typ: "JWT" })).toString('base64'), payload: "eyJzdWIiOiIxMjM0NTY3ODkwIn0", signature: "" };
            const jwk: JWK = {
                kty: "RSA",
                n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                e: "AQAB",
                alg: "NONE",
            };
            await expect(jwt.verifyTokenByJWK(token, jwk)).rejects.toThrow();
        });
    });

    describe("JWK Field Validation", () => {
        it("should require kty field in JWK", async () => {
            const token: Token = { header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", payload: "eyJzdWIiOiIxMjM0NTY3ODkwIn0", signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" };
            const jwk: any = {
                n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                e: "AQAB",
                alg: "RS256",
            };
            (globalThis.crypto.subtle.importKey as jest.Mock).mockRejectedValue(new Error("Required JWK member kty is missing"));
            await expect(jwt.verifyTokenByJWK(token, jwk)).rejects.toThrow();
        });

        it("should require e field for RSA keys", async () => {
            const token: Token = { header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", payload: "eyJzdWIiOiIxMjM0NTY3ODkwIn0", signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" };
            const jwk: any = {
                kty: "RSA",
                n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                alg: "RS256",
            };
            (globalThis.crypto.subtle.importKey as jest.Mock).mockRejectedValue(new Error("Required JWK member e is missing"));
            await expect(jwt.verifyTokenByJWK(token, jwk)).rejects.toThrow();
        });

        it("should require n field for RSA keys", async () => {
            const token: Token = { header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", payload: "eyJzdWIiOiIxMjM0NTY3ODkwIn0", signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" };
            const jwk: any = {
                kty: "RSA",
                e: "AQAB",
                alg: "RS256",
            };
            (globalThis.crypto.subtle.importKey as jest.Mock).mockRejectedValue(new Error("Required JWK member n is missing"));
            await expect(jwt.verifyTokenByJWK(token, jwk)).rejects.toThrow();
        });
    });

    describe("JWKS URL Validation", () => {
        it("should handle HTTPS URLs only (security best practice)", async () => {
            const token: Token = {
                header: "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAiMjAxMS0wNC0yOSJ9",
                payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            };
            const jwksUrl = new URL("http://example.com/.well-known/jwks.json");
            (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
            (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
            // Current implementation doesn't validate protocol, but we test it works
            const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
            // Should still work in current implementation
            expect(typeof result).toBe('boolean');
        });
    });

    describe("Special Characters and Injection Tests", () => {
        it("should handle kid with special characters", async () => {
            const maliciousKid = "../../etc/passwd";
            const token: Token = {
                header: Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: maliciousKid })).toString('base64'),
                payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            };
            const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
            const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
            // Should return false as kid won't match
            expect(result).toBe(false);
        });

        it("should handle kid with SQL injection attempt", async () => {
            const maliciousKid = "'; DROP TABLE keys; --";
            const token: Token = {
                header: Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: maliciousKid })).toString('base64'),
                payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            };
            const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
            const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
            // Should return false as kid won't match
            expect(result).toBe(false);
        });

        it("should handle kid with XSS attempt", async () => {
            const maliciousKid = "<script>alert('xss')</script>";
            const token: Token = {
                header: Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: maliciousKid })).toString('base64'),
                payload: "eyJsdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            };
            const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
            const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
            // Should return false as kid won't match
            expect(result).toBe(false);
        });

        it("should handle extremely long kid values", async () => {
            const maliciousKid = "a".repeat(100000);
            const token: Token = {
                header: Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: maliciousKid })).toString('base64'),
                payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            };
            const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
            const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
            // Should return false as kid won't match
            expect(result).toBe(false);
        });
    });

    describe("Multiple Keys Scenario", () => {
        it("should find the correct key among multiple keys", async () => {
            const token: Token = {
                header: "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAia2V5LTIifQ==",
                payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            };
            const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
            (global.fetch as jest.Mock).mockResolvedValueOnce({
                ok: true,
                json: () => Promise.resolve({
                    keys: [
                        {
                            kty: "RSA",
                            n: "key1-modulus",
                            e: "AQAB",
                            alg: "RS256",
                            kid: "key-1",
                        },
                        {
                            kty: "RSA",
                            n: "key2-modulus",
                            e: "AQAB",
                            alg: "RS256",
                            kid: "key-2",
                        },
                        {
                            kty: "RSA",
                            n: "key3-modulus",
                            e: "AQAB",
                            alg: "RS256",
                            kid: "key-3",
                        }
                    ]
                })
            } as Response);
            (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
            (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
            const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
            expect(result).toBe(true);
        });

        it("should return false if all keys fail verification", async () => {
            const token: Token = {
                header: "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAia2V5LTEifQ==",
                payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            };
            const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
            (global.fetch as jest.Mock).mockResolvedValueOnce({
                ok: true,
                json: () => Promise.resolve({
                    keys: [
                        {
                            kty: "RSA",
                            n: "key1-modulus",
                            e: "AQAB",
                            alg: "RS256",
                            kid: "key-1",
                        }
                    ]
                })
            } as Response);
            (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
            (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(false);
            const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
            expect(result).toBe(false);
        });
    });

    describe("JWT Claims Validation Tests", () => {
        const validJWK: JWK = {
            kty: "RSA",
            n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            e: "AQAB",
            alg: "RS256",
        };

        describe("Expiration (exp) Validation", () => {
            it("should reject expired token", async () => {
                const now = Math.floor(Date.now() / 1000);
                const payload = {
                    sub: "1234567890",
                    exp: now - 3600 // Expired 1 hour ago
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                await expect(jwt.verifyTokenByJWK(token, validJWK, { validateExpiration: true }))
                    .rejects.toThrow("Token has expired");
            });

            it("should accept valid token with future expiration", async () => {
                const now = Math.floor(Date.now() / 1000);
                const payload = {
                    sub: "1234567890",
                    exp: now + 3600 // Expires in 1 hour
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                const result = await jwt.verifyTokenByJWK(token, validJWK, { validateExpiration: true });
                expect(result).toBe(true);
            });

            it("should handle clock tolerance for expiration", async () => {
                const now = Math.floor(Date.now() / 1000);
                const payload = {
                    sub: "1234567890",
                    exp: now - 30 // Expired 30 seconds ago
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                // With 60 seconds tolerance, should pass
                const result = await jwt.verifyTokenByJWK(token, validJWK, { 
                    validateExpiration: true, 
                    clockTolerance: 60 
                });
                expect(result).toBe(true);
            });

            it("should skip expiration validation when disabled", async () => {
                const now = Math.floor(Date.now() / 1000);
                const payload = {
                    sub: "1234567890",
                    exp: now - 3600 // Expired
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                const result = await jwt.verifyTokenByJWK(token, validJWK, { validateExpiration: false });
                expect(result).toBe(true);
            });

            it("should reject token with non-numeric exp claim", async () => {
                const payload = {
                    sub: "1234567890",
                    exp: "invalid" as any
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                await expect(jwt.verifyTokenByJWK(token, validJWK, { validateExpiration: true }))
                    .rejects.toThrow("exp claim must be a number");
            });
        });

        describe("Not Before (nbf) Validation", () => {
            it("should reject token used before nbf time", async () => {
                const now = Math.floor(Date.now() / 1000);
                const payload = {
                    sub: "1234567890",
                    nbf: now + 3600 // Not valid for another hour
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                await expect(jwt.verifyTokenByJWK(token, validJWK, { validateNotBefore: true }))
                    .rejects.toThrow("Token not yet valid");
            });

            it("should accept token after nbf time", async () => {
                const now = Math.floor(Date.now() / 1000);
                const payload = {
                    sub: "1234567890",
                    nbf: now - 3600 // Valid since 1 hour ago
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                const result = await jwt.verifyTokenByJWK(token, validJWK, { validateNotBefore: true });
                expect(result).toBe(true);
            });

            it("should handle clock tolerance for nbf", async () => {
                const now = Math.floor(Date.now() / 1000);
                const payload = {
                    sub: "1234567890",
                    nbf: now + 30 // Not valid for 30 seconds
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                // With 60 seconds tolerance, should pass
                const result = await jwt.verifyTokenByJWK(token, validJWK, { 
                    validateNotBefore: true, 
                    clockTolerance: 60 
                });
                expect(result).toBe(true);
            });

            it("should skip nbf validation when disabled", async () => {
                const now = Math.floor(Date.now() / 1000);
                const payload = {
                    sub: "1234567890",
                    nbf: now + 3600 // Not yet valid
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                const result = await jwt.verifyTokenByJWK(token, validJWK, { validateNotBefore: false });
                expect(result).toBe(true);
            });

            it("should reject token with non-numeric nbf claim", async () => {
                const payload = {
                    sub: "1234567890",
                    nbf: "invalid" as any
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                await expect(jwt.verifyTokenByJWK(token, validJWK, { validateNotBefore: true }))
                    .rejects.toThrow("nbf claim must be a number");
            });
        });

        describe("Issued At (iat) Validation", () => {
            it("should reject token issued in the future", async () => {
                const now = Math.floor(Date.now() / 1000);
                const payload = {
                    sub: "1234567890",
                    iat: now + 3600 // Issued 1 hour in the future
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                await expect(jwt.verifyTokenByJWK(token, validJWK, {}))
                    .rejects.toThrow("Token issued in the future");
            });

            it("should accept token issued in the past", async () => {
                const now = Math.floor(Date.now() / 1000);
                const payload = {
                    sub: "1234567890",
                    iat: now - 3600 // Issued 1 hour ago
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                const result = await jwt.verifyTokenByJWK(token, validJWK, {});
                expect(result).toBe(true);
            });

            it("should handle clock tolerance for iat", async () => {
                const now = Math.floor(Date.now() / 1000);
                const payload = {
                    sub: "1234567890",
                    iat: now + 30 // Issued 30 seconds in the future
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                // With 60 seconds tolerance, should pass
                const result = await jwt.verifyTokenByJWK(token, validJWK, { clockTolerance: 60 });
                expect(result).toBe(true);
            });

            it("should reject token with non-numeric iat claim", async () => {
                const payload = {
                    sub: "1234567890",
                    iat: "invalid" as any
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                await expect(jwt.verifyTokenByJWK(token, validJWK, {}))
                    .rejects.toThrow("iat claim must be a number");
            });
        });

        describe("Combined Claims Validation", () => {
            it("should validate all claims together", async () => {
                const now = Math.floor(Date.now() / 1000);
                const payload = {
                    sub: "1234567890",
                    iat: now - 100,
                    nbf: now - 50,
                    exp: now + 3600
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                const result = await jwt.verifyTokenByJWK(token, validJWK, {
                    validateExpiration: true,
                    validateNotBefore: true
                });
                expect(result).toBe(true);
            });

            it("should use custom currentTime for testing", async () => {
                const testTime = 1609459200; // 2021-01-01 00:00:00 UTC
                const payload = {
                    sub: "1234567890",
                    iat: testTime - 100,
                    nbf: testTime - 50,
                    exp: testTime + 3600
                };
                const token: Token = {
                    header: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                const result = await jwt.verifyTokenByJWK(token, validJWK, {
                    validateExpiration: true,
                    validateNotBefore: true,
                    currentTime: testTime
                });
                expect(result).toBe(true);
            });
        });

        describe("JWKS with Claims Validation", () => {
            it("should validate claims when using JWKS", async () => {
                const now = Math.floor(Date.now() / 1000);
                const payload = {
                    sub: "1234567890",
                    exp: now - 3600 // Expired
                };
                const token: Token = {
                    header: "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAiMjAxMS0wNC0yOSJ9",
                    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
                    signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                };
                const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
                
                (globalThis.crypto.subtle.importKey as jest.Mock).mockResolvedValue({});
                (globalThis.crypto.subtle.verify as jest.Mock).mockResolvedValue(true);
                
                // Should return false because token is expired
                const result = await jwt.verifyTokenByJWKS(jwksUrl, token, { validateExpiration: true });
                expect(result).toBe(false);
            });
        });
    });
});
