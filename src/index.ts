import { base64url } from 'rfc4648';
import { decodeBase64toObject, findAlg, findHash, validateClaims } from "./helpers/helper";
import { Token } from './helpers/Token';
import { JWK, JWKSet, DecodedTokenHeader, DecodedTokenPayload, VerificationOptions } from './types';

export { Token } from './helpers/Token';
export type { VerificationOptions, DecodedTokenPayload } from './types';


export namespace jwt {

    export const verifyTokenByJWK = async (token: Token, jwk: JWK, options?: VerificationOptions) => {
        try {
            // Validate JWK has required algorithm field
            if (!jwk.alg) {
                throw new Error("JWK must have an 'alg' field");
            }

            // Validate claims if options are provided
            if (options && (options.validateExpiration !== false || options.validateNotBefore !== false)) {
                const payload = decodeBase64toObject<DecodedTokenPayload>(token.payload);
                validateClaims(payload, options);
            }

            const jwsSigningInput = `${token.header}.${token.payload}`;
            const jwsSignature = token.signature;
            const algorithm = findAlg(jwk.alg);
            // https://developer.mozilla.org/en-US/docs/Web/API/RsaHashedImportParams
            const hash = findHash(jwk.alg);
            // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
            const key = await window.crypto.subtle.importKey('jwk', jwk, {
                name: algorithm,
                hash: hash
            }, true, ['verify'])
            // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify
            const isValid = await window.crypto.subtle.verify(
                algorithm === 'ECDSA' ? { name: algorithm, hash: hash } : algorithm,
                key,
                base64url.parse(jwsSignature, { loose: true }) as BufferSource,
                new TextEncoder().encode(jwsSigningInput))
            return isValid;
        } catch (error) {
            // Re-throw errors for proper error handling
            throw error;
        }
    }


    export const verifyTokenByJWKS = async (jwksUrl: URL, token: Token, options?: VerificationOptions) => {
        try {
            const res = await fetch(jwksUrl.toString());
            const jwkset: JWKSet = await res.json();
            const keys = jwkset?.keys;
            if (keys && keys.length > 0) {
                const tkn = decodeBase64toObject<DecodedTokenHeader>(token.header);
                
                // Validate that kid exists in the token header
                if (!tkn.kid) {
                    return false;
                }

                const keyPromises = keys.map(async (key) => {
                    if (tkn.kid === key.kid) {
                        try {
                            return await jwt.verifyTokenByJWK(token, key, options);
                        } catch (error) {
                            // If verification fails for this key, return false
                            return false;
                        }
                    }
                    return false;
                })
                const results = await Promise.all(keyPromises);
                return results.some((result) => result === true);
            }
            return false;
        } catch (error) {
            return false;
        }
    }

}