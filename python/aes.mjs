import crypto from "crypto";

class AES {
    constructor() {
        this.keyLength = 32;
    }

    set_keylen(k) {
        if (k !== 16 && k !== 24 && k !== 32) {
            throw new Error("AES key length must be 16, 24, or 32 bytes");
        }

        this.keyLength = k;
    }

    variant_name() {
        return `AES${this.keyLength * 8}`;
    }

    variants() {
        return [
            {
                cipher: "AES",
                lengths: {
                    block: 16,
                    key: 16
                }
            },
            {
                cipher: "AES",
                lengths: {
                    block: 16,
                    key: 24
                }
            },
            {
                cipher: "AES",
                lengths: {
                    block: 16,
                    key: 32
                }
            }
        ];
    }

    encrypt(pt, key) {
        if (!Buffer.isBuffer(pt)) {
            pt = Buffer.from(pt);
        }

        if (!Buffer.isBuffer(key)) {
            key = Buffer.from(key);
        }

        if (key.length !== this.keyLength) {
            throw new Error("Invalid AES key length");
        }

        if (pt.length % 16 !== 0) {
            throw new Error("Plaintext must be a multiple of 16 bytes");
        }

        let cipher;

        if (this.keyLength === 16) {
            cipher = crypto.createCipheriv("aes-128-ecb", key, null);
        } else if (this.keyLength === 24) {
            cipher = crypto.createCipheriv("aes-192-ecb", key, null);
        } else {
            cipher = crypto.createCipheriv("aes-256-ecb", key, null);
        }

        cipher.setAutoPadding(false);

        return Buffer.concat([
            cipher.update(pt),
            cipher.final()
        ]);
    }

    decrypt(ct, key) {
        if (!Buffer.isBuffer(ct)) {
            ct = Buffer.from(ct);
        }

        if (!Buffer.isBuffer(key)) {
            key = Buffer.from(key);
        }

        if (key.length !== this.keyLength) {
            throw new Error("Invalid AES key length");
        }

        if (key.length !== this.keyLength) {
            throw new Error("Invalid AES key length");
        }

        if (ct.length % 16 !== 0) {
            throw new Error("Ciphertext must be a multiple of 16 bytes");
        }

        let decipher;

        if (this.keyLength === 16) {
            decipher = crypto.createDecipheriv("aes-128-ecb", key, null);
        } else if (this.keyLength === 24) {
            decipher = crypto.createDecipheriv("aes-192-ecb", key, null);
        } else {
            decipher = crypto.createDecipheriv("aes-256-ecb", key, null);
        }

        decipher.setAutoPadding(false);

        return Buffer.concat([
            decipher.update(ct),
            decipher.final()
        ]);
    }
}

export default AES;
