import { beforeAll, describe, expect, it, jest } from '@jest/globals';
import { jwt, JWK, Token } from "../src/index";


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
            const result = await jwt.verifyTokenByJWK(token, jwk);
            expect(result).toBe(true);
        });

        it("should return false for an invalid token", async () => {
            const token: Token = {
                header: "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9",
                payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "invalid_signature",
            };
            const jwk: JWK = {
                kty: "RSA",
                n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                e: "AQAB",
                alg: "RS256",
                kid: "2011-04-29",
            };
            const result = await jwt.verifyTokenByJWK(token, jwk);
            expect(result).toBe(false);
        });
    });

    // Use your own jwks.json file to run this test
    describe("verifyTokenByJWKS", () => {
        it("should return true for a valid token", async () => {
            const token: Token = {
                header: "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9",
                payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            };
            const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
            const result = await jwt.verifyTokenByJWKS(jwksUrl, token);
            expect(result).toBe(true);
        });

        it("should throw an error if no keys are found in jwks", async () => {
            const token: Token = {
                header: "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9",
                payload: "eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9",
                signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            };
            const jwksUrl = new URL("https://example.com/.well-known/jwks.json");
            await expect(jwt.verifyTokenByJWKS(jwksUrl, token)).rejects.toThrow(
                "No keys found in jwks"
            );
        });
    });
});
