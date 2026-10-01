const crypto = require("crypto");

class AES {
    constructor() {
        this.keyLength = 16;
    }

    set_keylen(k) {
        if (![16, 24, 32].includes(k)) {
            throw new Error("Invalid AES key length");
        }
        this.keyLength = k;
    }

    variant_name() {
        return `AES${this.keyLength * 8}`;
    }

    variants() {
        return [16, 24, 32].map((kl) => ({
            cipher: "AES",
            lengths: {
                block: 16,
                key: kl
            }
        }));
    }

    algorithm() {
        return `aes-${this.keyLength * 8}-ecb`;
    }

    encrypt(pt, key) {
        if (key.length !== this.keyLength) {
            throw new Error("Invalid key length");
        }

        if (pt.length % 16 !== 0) {
            throw new Error("Plaintext length must be a multiple of 16");
        }

        const cipher = crypto.createCipheriv(
            this.algorithm(),
            key,
            null
        );

        cipher.setAutoPadding(false);

        return Buffer.concat([
            cipher.update(pt),
            cipher.final()
        ]);
    }

    decrypt(ct, key) {
        if (key.length !== this.keyLength) {
            throw new Error("Invalid key length");
        }

        if (ct.length % 16 !== 0) {
            throw new Error("Ciphertext length must be a multiple of 16");
        }

        const decipher = crypto.createDecipheriv(
            this.algorithm(),
            key,
            null
        );

        decipher.setAutoPadding(false);

        return Buffer.concat([
            decipher.update(ct),
            decipher.final()
        ]);
    }
}

module.exports = AES;
