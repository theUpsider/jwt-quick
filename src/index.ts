import { base64url } from 'rfc4648';
import { decodeBase64toObject, findAlg, findHash } from "./helpers/helper";
import { Token } from './helpers/Token';
import { JWK, JWKSet, DecodedTokenHeader } from './types';

export { Token } from './helpers/Token';


export namespace jwt {

    export const verifyTokenByJWK = async (token: Token, jwk: JWK) => {

        const jwsSigningInput = `${token.header}.${token.payload}`;
        const jwsSignature = token.signature;
        const algorithm = findAlg(jwk.alg);
        // https://developer.mozilla.org/en-US/docs/Web/API/RsaHashedImportParams
        const hash = findHash(jwk.alg);
        // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
        console.log(jwk);
        console.log(algorithm);
        console.log(hash);
        try {
            window.crypto.subtle.importKey('jwk', jwk, {
                name: algorithm,
                hash: hash
            }, true, ['verify']).then((key) => {
                // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify
                window.crypto.subtle.verify(
                    algorithm === 'ECDSA' ? { name: algorithm, hash: hash } : algorithm,
                    key,
                    base64url.parse(jwsSignature, { loose: true }),
                    new TextEncoder().encode(jwsSigningInput))
                    .then((isValid) => {
                        return isValid;
                    }
                    ).catch((error) => {
                        console.log(error);
                        return false;
                    }
                    );
            }).catch((error) => {
                console.log(error);
                return false;
            });
        } catch (error) {
            console.log(error);
            return false;
        }
    }


    export const verifyTokenByJWKS = async (jwksUrl: URL, token: Token) => {
        try {
            const res = await fetch(jwksUrl.toString());
            const jwkset: JWKSet = await res.json();
            const keys = jwkset?.keys;
            if (keys) {
                for (const key of keys) {
                    const tkn = decodeBase64toObject<DecodedTokenHeader>(token.header);
                    if (tkn.kid === key.kid) {
                        const isValid = await jwt.verifyTokenByJWK(token, key);
                        if (isValid) {
                            return true;
                        }
                    }
                    return false;
                }
            }
            return false;
        } catch (error) {
            console.log(error);
            return false;
        }
    }

}