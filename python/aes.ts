import * as crypto from "crypto";

interface AESVariant {
    cipher: string;
    lengths: {
        block: number;
        key: number;
    };
}

class AES {
    private keyLength: number = 16;

    set_keylen(k: number): void {
        if (![16, 24, 32].includes(k)) {
            throw new Error("Invalid AES key length");
        }

        this.keyLength = k;
    }

    variant_name(): string {
        return `AES${this.keyLength * 8}`;
    }

    variants(): AESVariant[] {
        return [16, 24, 32].map((kl) => ({
            cipher: "AES",
            lengths: {
                block: 16,
                key: kl
            }
        }));
    }

    private algorithm(): string {
        return `aes-${this.keyLength * 8}-ecb`;
    }

    encrypt(pt: Buffer, key: Buffer): Buffer {
        if (key.length !== this.keyLength) {
            throw new Error("Invalid AES key length");
        }

        if (pt.length % 16 !== 0) {
            throw new Error(
                "Plaintext length must be a multiple of 16"
            );
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

    decrypt(ct: Buffer, key: Buffer): Buffer {
        if (key.length !== this.keyLength) {
            throw new Error("Invalid AES key length");
        }

        if (ct.length % 16 !== 0) {
            throw new Error(
                "Ciphertext length must be a multiple of 16"
            );
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

export default AES;
