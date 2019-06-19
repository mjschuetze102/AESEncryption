package SymmetricKey;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Implements AES 128 Encryption
 * Private key encryption
 *   Fast and efficient algorithm
 *   Key must remain a secret, and both parties require the key
 * Uses Cipher Block Chaining (CBC)
 *   Block C depends not only on the outcome of Block B, but also Block A
 * Uses a random initialization vector to xor with the first Block of data
 *   This causes the same plaintext to output a different cipher text
 *   Does not have to remain secret as it should only be used once
 * Written by Michael Schuetze on 6/16/2019.
 */
public class AESEncryption {

    private final int BLOCK_LENGTH = 128;
    private final int KEY_LENGTH = 128; // 192, 256

    private SecureRandom secRand = new SecureRandom();
    private SecretKey secKey;

    public AESEncryption() {
        // Only need to generate secret key once
        secKey = generateSecretKey();
    }

    /////////////////////////////////////////////////////
    //              Class Functionality
    /////////////////////////////////////////////////////

    public byte[] encode(String plainText) {
        // Need to generate initialization vector for every encoding
        IvParameterSpec ivSpec = generateInitializationVector();
        Cipher cipher = generateCipher(Cipher.ENCRYPT_MODE, secKey, ivSpec);

        try {
            byte[] input = plainText.getBytes(StandardCharsets.UTF_8);
            byte[] encoded = cipher.doFinal(input);

            // Attach the initialization vector to the encoding so the decoding process has access to it
            byte[] ivAndEncoded = Arrays.copyOf(ivSpec.getIV(), ivSpec.getIV().length + encoded.length);
            System.arraycopy(encoded, 0, ivAndEncoded, ivSpec.getIV().length, encoded.length);
            return Base64.getEncoder().encode(ivAndEncoded);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Could Not Encode Message");
        }

        return null;
    }

    public byte[] decode(byte[] ivAndCipher) {
        ivAndCipher = Base64.getDecoder().decode(ivAndCipher);

        // Remove initialization vector from the front of the cipher text
        IvParameterSpec ivSpec = new IvParameterSpec(Arrays.copyOf(ivAndCipher, BLOCK_LENGTH / 8)); // Division converts bits to bytes
        byte[] cipherText = Arrays.copyOfRange(ivAndCipher, BLOCK_LENGTH / 8, ivAndCipher.length);

        Cipher cipher = generateCipher(Cipher.DECRYPT_MODE, secKey, ivSpec);

        try {
            return cipher.doFinal(cipherText);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Could Not Decode Message");
        }

        return null;
    }

    /////////////////////////////////////////////////////
    //              Getters and Setters
    /////////////////////////////////////////////////////

    /////////////////////////////////////////////////////
    //               Helper Functions
    /////////////////////////////////////////////////////

    /**
     * Generate Initialization Vector used in the first round of Encryption/Decryption
     * @return initialization vector of size 16 bytes (128 bits)
     */
    private IvParameterSpec generateInitializationVector() {
        byte[] iv = new byte[BLOCK_LENGTH / 8]; // Division converts bits to bytes
        secRand.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * Generates Secret Key used to Encrypt/ Decrypt data
     * @return secret key of size 16 bytes (128 bits)
     */
    private SecretKey generateSecretKey() {
        SecretKey secKey = null;
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(KEY_LENGTH);
            secKey = keyGen.generateKey();
        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("Encryption Algorithm Not Found");
        }

        return secKey;
    }

    /**
     * Generates Cipher for Encryption/ Decryption
     * @param cipherMode - Cipher.ENCRYPT or Cipher.DECRYPT
     * @param secKey - Secret Key used for the Encryption/ Decryption
     * @param ivSpec - Initialization Vector used for the first round of Encryption/ Decryption
     * @return cipher which is used to encrypt/ decrypt messages
     */
    private Cipher generateCipher(int cipherMode, SecretKey secKey, IvParameterSpec ivSpec) {
        Cipher cipher = null;
        try {
            // AES - Advanced Encryption Standard
            // CBC - Cipher Block Chaining
            // PKCS5 - Padding Standard to pad data to an 8 byte (64 bit) block
            //         1 byte missing: 0x01 is added
            //         2 byte missing: 0x0202 is added
            //         ...
            //         8 byte missing: 0x0808080808080808 is added
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(cipherMode, secKey, ivSpec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException nse) {
            System.out.println("Encryption Algorithm / Padding Scheme Not Found");
        } catch (InvalidKeyException | InvalidAlgorithmParameterException ie) {
            // If you are receive this error after changing the KEY_LENGTH,
            // download the Java Cryptography Extension to enable larger key sizes
            // https://www.oracle.com/technetwork/java/javase/downloads/jce-all-download-5170447.html
            System.out.println("Invalid Secret Key / Initialization Vector");
        }

        return cipher;
    }

    /////////////////////////////////////////////////////
    //               Testing Purposes
    /////////////////////////////////////////////////////

    public static void main(String[] args) {
        AESEncryption encryption = new AESEncryption();
        SecretKey secKey = encryption.secKey;

        String plainText = "Hello World!";

        for (int rounds = 0; rounds < 3; rounds++) {
            byte[] encoded = encryption.encode(plainText);
            byte[] decoded = encryption.decode(encoded);

            // Remove initialization vector from the front of the cipher text
            encoded = Base64.getDecoder().decode(encoded);
            IvParameterSpec ivSpec = new IvParameterSpec(Arrays.copyOf(encoded, encryption.BLOCK_LENGTH / 8)); // Division converts bits to bytes
            byte[] cipherText = Arrays.copyOfRange(encoded, encryption.BLOCK_LENGTH / 8, encoded.length);
            byte[] cipherTextB64 = Base64.getEncoder().encode(cipherText);

            System.out.println("-------------------------------------------");
            System.out.println("Init Vector:" + Arrays.toString(ivSpec.getIV()));
            System.out.println("Secret Key: " + Arrays.toString(secKey.getEncoded()));
            System.out.println("Encrypted:  " + Arrays.toString(cipherText));
            System.out.println("Decrypted:  " + Arrays.toString(decoded));
            System.out.println("-------------------------------------------");
            System.out.println("Plain Text: " + plainText);
            System.out.println("Encrypted:  " + new String(cipherTextB64, StandardCharsets.UTF_8));
            System.out.println("Decrypted:  " + new String(decoded, StandardCharsets.UTF_8));
            System.out.println("-------------------------------------------");
        }
    }
}
