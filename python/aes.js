/*
 * aes.js
 *
 * AES-128 / AES-192 / AES-256
 * AES-ECB mode
 *
 * Equivalent to Python:
 *
 * AES.new(key, AES.MODE_ECB)
 */

const crypto = require("crypto");

class AES {

    constructor() {
        // Default: AES-128
        this.keyLength = 16;
    }

    /*
     * Set AES key length.
     *
     * 16 = AES-128
     * 24 = AES-192
     * 32 = AES-256
     */
    set_keylen(k) {
        if (k !== 16 && k !== 24 && k !== 32) {
            throw new Error(
                "AES key length must be 16, 24, or 32 bytes"
            );
        }

        this.keyLength = k;
    }

    /*
     * Returns:
     *
     * AES128
     * AES192
     * AES256
     */
    variant_name() {
        return `AES${this.keyLength * 8}`;
    }

    /*
     * Supported AES variants.
     */
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

    /*
     * AES encryption.
     *
     * ECB mode.
     * No padding.
     */
    encrypt(pt, key) {

        if (!Buffer.isBuffer(pt)) {
            pt = Buffer.from(pt);
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

        if (pt.length % 16 !== 0) {
            throw new Error(
                "Plaintext length must be a multiple of 16 bytes"
            );
        }

        let cipher;

        /*
         * IMPORTANT:
         *
         * Keep the actual AES algorithm names here.
         * This allows static crypto scanners to detect
         * the exact algorithm and exact source line.
         */

        if (this.keyLength === 16) {

            // AES-128-ECB
            cipher = crypto.createCipheriv(
                "aes-128-ecb",
                key,
                null
            );

        } else if (this.keyLength === 24) {

            // AES-192-ECB
            cipher = crypto.createCipheriv(
                "aes-192-ecb",
                key,
                null
            );

        } else if (this.keyLength === 32) {

            // AES-256-ECB
            cipher = crypto.createCipheriv(
                "aes-256-ecb",
                key,
                null
            );

        } else {
            throw new Error("Unsupported AES key length");
        }

        /*
         * Python PyCryptodome AES.MODE_ECB does not
         * automatically add PKCS#7 padding.
         */
        cipher.setAutoPadding(false);

        return Buffer.concat([
            cipher.update(pt),
            cipher.final()
        ]);
    }

    /*
     * AES decryption.
     *
     * ECB mode.
     * No padding.
     */
    decrypt(ct, key) {

        if (!Buffer.isBuffer(ct)) {
            ct = Buffer.from(ct);
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

        if (ct.length % 16 !== 0) {
            throw new Error(
                "Ciphertext length must be a multiple of 16 bytes"
            );
        }

        let decipher;

        /*
         * IMPORTANT:
         * Concrete algorithm names are used so that
         * crypto scanners can identify AES usage.
         */

        if (this.keyLength === 16) {

            // AES-128-ECB
            decipher = crypto.createDecipheriv(
                "aes-128-ecb",
                key,
                null
            );

        } else if (this.keyLength === 24) {

            // AES-192-ECB
            decipher = crypto.createDecipheriv(
                "aes-192-ecb",
                key,
                null
            );

        } else if (this.keyLength === 32) {

            // AES-256-ECB
            decipher = crypto.createDecipheriv(
                "aes-256-ecb",
                key,
                null
            );

        } else {
            throw new Error("Unsupported AES key length");
        }

        /*
         * Disable automatic padding.
         */
        decipher.setAutoPadding(false);

        return Buffer.concat([
            decipher.update(ct),
            decipher.final()
        ]);
    }
}

module.exports = AES;
