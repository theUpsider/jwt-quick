import { base64url } from 'rfc4648';
import { DecodedTokenHeader, Token } from "./helpers/Token";
import { JWK, JWKSet } from "./helpers/JWK";
import { decodeBase64toObject, tokenMatcher } from "./helpers/helper";

export { Token }



export namespace jwt {

    export const verifyTokenByJWK = async (token: Token, jwk: JWK) => {
        const jwsSigningInput = `${token.header}.${token.payload}`;
        const jwsSignature = token.signature;
        const algorithm = jwk.alg || 'RS256';
        const hashAlgorithm = algorithm.includes('256') ? 'SHA-256' : 'SHA-384';
        const key = await window.crypto.subtle.importKey('jwk', jwk, {
            name: algorithm,
            hash: { name: hashAlgorithm }
        }, false, ['verify']);
        const isValid = await window.crypto.subtle.verify(
            { name: algorithm, saltLength: 64 },
            key,
            base64url.parse(jwsSignature, { loose: true }),
            new TextEncoder().encode(jwsSigningInput))
        return isValid;
    }


    export const verifyTokenByJWKS = async (jwksUrl: URL, token: Token) => {
        try {
            const res = await fetch(jwksUrl.toString());
            const jwkset: JWKSet = await res.json();
            const keys = jwkset?.keys;
            if (keys) {
                const promises = keys.map(async (key) => {
                    const tkn = decodeBase64toObject<DecodedTokenHeader>(token.header);
                    if (tokenMatcher(key.kty) === tokenMatcher(tkn.alg)) {
                        const isValid = await jwt.verifyTokenByJWK(token, key);
                        if (isValid) {
                            return true;
                        }
                    }
                    return false;
                });
                const results = await Promise.all(promises);
                return results.includes(true);
            }
            return false;
        } catch (error) {
            return false;
        }
    }

}