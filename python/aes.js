/*
 * aes.js
 *
 * AES-128 / AES-192 / AES-256
 * AES-ECB mode
 *
 * Equivalent to:
 *
 * AES.new(key, AES.MODE_ECB)
 *
 * Node.js version
 */

const crypto = require("crypto");

class AES {

    constructor() {
        // Default: AES-128
        this.keyLength = 16;
    }

    /*
     * Set AES key length
     *
     * 16 = AES-128
     * 24 = AES-192
     * 32 = AES-256
     */
    setKeyLen(k) {
        if (k !== 16 && k !== 24 && k !== 32) {
            throw new Error(
                "AES key length must be 16, 24, or 32 bytes"
            );
        }

        this.keyLength = k;
    }

    /*
     * Get variant name
     */
    variantName() {
        return `AES${this.keyLength * 8}`;
    }

    /*
     * Get supported AES variants
     */
    variants() {
        return [16, 24, 32];
    }

    /*
     * Get AES algorithm name
     */
    algorithm() {
        switch (this.keyLength) {
            case 16:
                return "aes-128-ecb";

            case 24:
                return "aes-192-ecb";

            case 32:
                return "aes-256-ecb";

            default:
                throw new Error("Invalid AES key length");
        }
    }

    /*
     * Encrypt using AES-ECB.
     *
     * No padding.
     *
     * Plaintext length must be
     * a multiple of 16 bytes.
     */
    encrypt(plaintext, key) {

        if (!Buffer.isBuffer(plaintext)) {
            plaintext = Buffer.from(plaintext);
        }

        if (!Buffer.isBuffer(key)) {
            key = Buffer.from(key);
        }

        if (key.length !== this.keyLength) {
            throw new Error(
                `Invalid key length: expected ${this.keyLength} bytes, ` +
                `got ${key.length} bytes`
            );
        }

        if (plaintext.length % 16 !== 0) {
            throw new Error(
                "Plaintext length must be a multiple of 16 bytes"
            );
        }

        const cipher = crypto.createCipheriv(
            this.algorithm(),
            key,
            null
        );

        /*
         * Disable PKCS#7 padding.
         *
         * This matches the Python code.
         */
        cipher.setAutoPadding(false);

        return Buffer.concat([
            cipher.update(plaintext),
            cipher.final()
        ]);
    }

    /*
     * Decrypt using AES-ECB.
     *
     * No padding.
     */
    decrypt(ciphertext, key) {

        if (!Buffer.isBuffer(ciphertext)) {
            ciphertext = Buffer.from(ciphertext);
        }

        if (!Buffer.isBuffer(key)) {
            key = Buffer.from(key);
        }

        if (key.length !== this.keyLength) {
            throw new Error(
                `Invalid key length: expected ${this.keyLength} bytes, ` +
                `got ${key.length} bytes`
            );
        }

        if (ciphertext.length % 16 !== 0) {
            throw new Error(
                "Ciphertext length must be a multiple of 16 bytes"
            );
        }

        const decipher = crypto.createDecipheriv(
            this.algorithm(),
            key,
            null
        );

        /*
         * Disable PKCS#7 padding.
         */
        decipher.setAutoPadding(false);

        return Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
        ]);
    }
}


/*
 * Example
 */
function main() {

    const aes = new AES();

    /*
     * AES-128
     */
    aes.setKeyLen(16);

    console.log("Variant:", aes.variantName());

    /*
     * 16-byte key
     */
    const key = Buffer.from("1234567890123456");

    /*
     * Exactly 16 bytes.
     */
    const plaintext = Buffer.from("Hello AES World!");

    /*
     * Encrypt
     */
    const encrypted = aes.encrypt(
        plaintext,
        key
    );

    console.log(
        "Encrypted:",
        encrypted.toString("hex")
    );

    /*
     * Decrypt
     */
    const decrypted = aes.decrypt(
        encrypted,
        key
    );

    console.log(
        "Decrypted:",
        decrypted.toString()
    );
}


/*
 * Run example
 */
main();


// Export class if used as a module
module.exports = AES;
