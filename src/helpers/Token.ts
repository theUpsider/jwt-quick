

/**
 * Represents a JSON Web Token (JWT) and provides methods for decoding and verifying its contents.
 */
export class Token {
    header: string;
    payload: string;
    signature: string;
    constructor(token: string) {
        this.header = token.split(".")[0];
        this.payload = token.split(".")[1];
        this.signature = token.split(".")[2];
    }
}
