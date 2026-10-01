import crypto from "crypto";

export class AES {
    private keyLength: 16 | 24 | 32 = 32;

    set_keylen(k: 16 | 24 | 32): void {
        if (k !== 16 && k !== 24 && k !== 32) {
            throw new Error("AES key length must be 16, 24, or 32 bytes");
        }

        this.keyLength = k;
    }

    variant_name(): string {
        return `AES${this.keyLength * 8}`;
    }

    encrypt(plaintext: Buffer, key: Buffer): Buffer {
        if (key.length !== this.keyLength) {
            throw new Error("Invalid AES key length");
        }

        if (plaintext.length % 16 !== 0) {
            throw new Error("Plaintext must be a multiple of 16 bytes");
        }

        let cipher: crypto.Cipher;

        if (this.keyLength === 16) {
            cipher = crypto.createCipheriv("aes-128-ecb", key, null);
        } else if (this.keyLength === 24) {
            cipher = crypto.createCipheriv("aes-192-ecb", key, null);
        } else {
            cipher = crypto.createCipheriv("aes-256-ecb", key, null);
        }

        cipher.setAutoPadding(false);

        return Buffer.concat([
            cipher.update(plaintext),
            cipher.final()
        ]);
    }

    decrypt(ciphertext: Buffer, key: Buffer): Buffer {
        if (key.length !== this.keyLength) {
            throw new Error("Invalid AES key length");
        }

        if (ciphertext.length % 16 !== 0) {
            throw new Error("Ciphertext must be a multiple of 16 bytes");
        }

        let decipher: crypto.Decipher;

        if (this.keyLength === 16) {
            decipher = crypto.createDecipheriv("aes-128-ecb", key, null);
        } else if (this.keyLength === 24) {
            decipher = crypto.createDecipheriv("aes-192-ecb", key, null);
        } else {
            decipher = crypto.createDecipheriv("aes-256-ecb", key, null);
        }

        decipher.setAutoPadding(false);

        return Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
        ]);
    }
}

export default function AESDemo(): JSX.Element {
    return <div>AES encryption module</div>;
}
