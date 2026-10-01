/*
 * aes.c
 *
 * AES-128 / AES-192 / AES-256
 * AES-ECB mode
 *
 * Equivalent to:
 *
 * AES.new(key, AES.MODE_ECB)
 *
 * Requires OpenSSL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/aes.h>

/*
 * AES structure
 */
typedef struct {
    int key_length;
} AES;


/*
 * Create AES object
 *
 * Default: AES-128
 */
void AES_init(AES *aes)
{
    aes->key_length = 16;
}


/*
 * Set AES key length
 *
 * 16 = AES-128
 * 24 = AES-192
 * 32 = AES-256
 */
int AES_set_keylen(AES *aes, int key_length)
{
    if (key_length != 16 &&
        key_length != 24 &&
        key_length != 32) {

        return 0;
    }

    aes->key_length = key_length;

    return 1;
}


/*
 * Get variant name
 *
 * AES128
 * AES192
 * AES256
 */
const char *AES_variant_name(const AES *aes)
{
    switch (aes->key_length) {

        case 16:
            return "AES128";

        case 24:
            return "AES192";

        case 32:
            return "AES256";

        default:
            return "Unknown";
    }
}


/*
 * Encrypt using AES-ECB
 *
 * No padding is added.
 *
 * Input length must be a multiple of 16 bytes.
 */
int AES_encrypt(
    const AES *aes,
    const unsigned char *plaintext,
    int plaintext_len,
    const unsigned char *key,
    unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    int len;
    int ciphertext_len;

    if (plaintext_len % AES_BLOCK_SIZE != 0) {
        return 0;
    }

    if (aes->key_length == 16) {
        cipher = EVP_aes_128_ecb();
    }
    else if (aes->key_length == 24) {
        cipher = EVP_aes_192_ecb();
    }
    else if (aes->key_length == 32) {
        cipher = EVP_aes_256_ecb();
    }
    else {
        return 0;
    }

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        return 0;
    }

    /*
     * Initialize AES-ECB.
     */
    if (EVP_EncryptInit_ex(
            ctx,
            cipher,
            NULL,
            key,
            NULL) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /*
     * Disable padding.
     *
     * This matches PyCryptodome AES.MODE_ECB
     * behavior used in the original code.
     */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /*
     * Encrypt.
     */
    if (EVP_EncryptUpdate(
            ctx,
            ciphertext,
            &len,
            plaintext,
            plaintext_len) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    ciphertext_len = len;

    /*
     * Finish encryption.
     */
    if (EVP_EncryptFinal_ex(
            ctx,
            ciphertext + len,
            &len) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


/*
 * Decrypt using AES-ECB
 *
 * No padding is used.
 */
int AES_decrypt(
    const AES *aes,
    const unsigned char *ciphertext,
    int ciphertext_len,
    const unsigned char *key,
    unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    int len;
    int plaintext_len;

    if (ciphertext_len % AES_BLOCK_SIZE != 0) {
        return 0;
    }

    if (aes->key_length == 16) {
        cipher = EVP_aes_128_ecb();
    }
    else if (aes->key_length == 24) {
        cipher = EVP_aes_192_ecb();
    }
    else if (aes->key_length == 32) {
        cipher = EVP_aes_256_ecb();
    }
    else {
        return 0;
    }

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        return 0;
    }

    /*
     * Initialize AES-ECB.
     */
    if (EVP_DecryptInit_ex(
            ctx,
            cipher,
            NULL,
            key,
            NULL) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /*
     * Disable padding.
     */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /*
     * Decrypt.
     */
    if (EVP_DecryptUpdate(
            ctx,
            plaintext,
            &len,
            ciphertext,
            ciphertext_len) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    plaintext_len = len;

    /*
     * Finish decryption.
     */
    if (EVP_DecryptFinal_ex(
            ctx,
            plaintext + len,
            &len) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


/*
 * Print bytes as hexadecimal.
 */
void print_hex(
    const unsigned char *data,
    int length)
{
    int i;

    for (i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }

    printf("\n");
}


/*
 * Example
 */
int main(void)
{
    AES aes;

    /*
     * Initialize AES.
     */
    AES_init(&aes);

    /*
     * AES-128
     */
    if (!AES_set_keylen(&aes, 16)) {
        printf("Invalid key length\n");
        return 1;
    }

    printf("Variant: %s\n",
           AES_variant_name(&aes));

    /*
     * 16-byte AES-128 key.
     */
    unsigned char key[16] =
        "1234567890123456";

    /*
     * Exactly 16 bytes.
     *
     * ECB + NoPadding requires
     * a multiple of 16 bytes.
     */
    unsigned char plaintext[16] =
        "Hello AES World!";

    unsigned char ciphertext[16];
    unsigned char decrypted[16];

    int encrypted_len;
    int decrypted_len;

    /*
     * Encrypt.
     */
    encrypted_len = AES_encrypt(
        &aes,
        plaintext,
        sizeof(plaintext),
        key,
        ciphertext
    );

    if (encrypted_len <= 0) {
        printf("Encryption failed\n");
        return 1;
    }

    printf("Encrypted: ");
    print_hex(ciphertext, encrypted_len);

    /*
     * Decrypt.
     */
    decrypted_len = AES_decrypt(
        &aes,
        ciphertext,
        encrypted_len,
        key,
        decrypted
    );

    if (decrypted_len <= 0) {
        printf("Decryption failed\n");
        return 1;
    }

    printf("Decrypted: ");

    for (int i = 0; i < decrypted_len; i++) {
        printf("%c", decrypted[i]);
    }

    printf("\n");

    return 0;
}
