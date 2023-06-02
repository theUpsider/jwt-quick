import { Buffer } from 'buffer';

// helper methods for jwt
const tokenDict: { [id: string]: string; } = {
    "RS256": "RSA",
    "RSA": "RSA"
}
const tokenMatcher = (token: string): string => {
    return token in tokenDict ? tokenDict[token] : token;
}

const decodeBase64toObject = <T>(base64: string): T => {
    return JSON.parse(decodeBase64(base64));
}
const decodeBase64 = (b64Encoded: string): string => {
    return Buffer.from(b64Encoded, 'base64').toString()
}

export { tokenMatcher, decodeBase64toObject, decodeBase64 }