// Properties are base64url encoded
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

export type DecodedTokenHeader = {
    alg: string;
    typ: string;
}