package org.example;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.Base64;

public class RSAHybridEncryption {

    public static void main(String[] args) throws Exception {
        // Generate RSA Key Pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Original large text to encrypt
        String largeText = "This is a very large text that needs to be encrypted using RSA hybrid encryption. " +
                "Hybrid encryption combines RSA and symmetric encryption for efficient and secure communication.";
        System.out.println("Original Text: " + largeText);

        // Step 1: Generate a Symmetric Key (AES)
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(256); // AES key size
        SecretKey symmetricKey = aesKeyGen.generateKey();

        // Step 2: Encrypt the large text using the symmetric key (AES)
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
        byte[] encryptedLargeText = aesCipher.doFinal(largeText.getBytes());
        System.out.println("Encrypted Large Text (AES): " + Base64.getEncoder().encodeToString(encryptedLargeText));

        // Step 3: Encrypt the symmetric key using RSA public key
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = rsaCipher.doFinal(symmetricKey.getEncoded());
        System.out.println("Encrypted Symmetric Key (RSA): " + Base64.getEncoder().encodeToString(encryptedSymmetricKey));

        // Step 4: Decrypt the symmetric key using RSA private key
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKeyBytes = rsaCipher.doFinal(encryptedSymmetricKey);
        SecretKey decryptedSymmetricKey = new SecretKeySpec(decryptedSymmetricKeyBytes, "AES");

        // Step 5: Decrypt the large text using the decrypted symmetric key (AES)
        aesCipher.init(Cipher.DECRYPT_MODE, decryptedSymmetricKey);
        byte[] decryptedLargeTextBytes = aesCipher.doFinal(encryptedLargeText);
        String decryptedLargeText = new String(decryptedLargeTextBytes);
        System.out.println("Decrypted Large Text: " + decryptedLargeText);
    }
}

