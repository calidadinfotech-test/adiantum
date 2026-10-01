import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public class AES {

    private int keyLength;

    public AES() {
        this.keyLength = 16; // AES-128 by default
    }

    public void setKeyLen(int k) {
        if (k != 16 && k != 24 && k != 32) {
            throw new IllegalArgumentException(
                "AES key length must be 16, 24, or 32 bytes"
            );
        }

        this.keyLength = k;
    }

    public String variantName() {
        return "AES" + (keyLength * 8);
    }

    public int[] variants() {
        return new int[]{16, 24, 32};
    }

    public byte[] encrypt(byte[] plaintext, byte[] key)
            throws GeneralSecurityException {

        if (key.length != keyLength) {
            throw new IllegalArgumentException(
                "Invalid key length. Expected " + keyLength +
                " bytes, got " + key.length + " bytes"
            );
        }

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        return cipher.doFinal(plaintext);
    }

    public byte[] decrypt(byte[] ciphertext, byte[] key)
            throws GeneralSecurityException {

        if (key.length != keyLength) {
            throw new IllegalArgumentException(
                "Invalid key length. Expected " + keyLength +
                " bytes, got " + key.length + " bytes"
            );
        }

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        return cipher.doFinal(ciphertext);
    }
}
