

/**
 * Represents a JSON Web Token (JWT) and provides methods for decoding and verifying its contents.
 */
export class Token {
    header: string;
    payload: string;
    signature: string;
    constructor(token: string) {
        if (!token || typeof token !== 'string') {
            throw new Error("Invalid token: token must be a non-empty string");
        }
        const parts = token.split(".");
        if (parts.length !== 3) {
            throw new Error("Invalid token: token must have exactly 3 parts separated by dots");
        }
        this.header = parts[0];
        this.payload = parts[1];
        this.signature = parts[2];
        if (!this.header || !this.payload || !this.signature) {
            throw new Error("Invalid token: all parts must be non-empty");
        }
    }
}
