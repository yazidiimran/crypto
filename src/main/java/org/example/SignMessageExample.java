package org.example;

import java.security.*;
import java.util.Base64;

public class SignMessageExample {

    public static void main(String[] args) throws Exception {
        // Step 1: Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);  // 2048-bit key size
        KeyPair keyPair = keyGen.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Step 2: Create the message to sign
        String message = "This is a secret message";

        // Step 3: Sign the message using the private key
        byte[] signedMessage = signMessage(message, privateKey);

        // Step 4: Verify the signature using the public key
        boolean isVerified = verifySignature(message, signedMessage, publicKey);

        // Output results
        System.out.println("Original Message: " + message);
        System.out.println("Signed Message: " + Base64.getEncoder().encodeToString(signedMessage));
        System.out.println("Is the signature valid? " + isVerified);
    }

    // Method to sign the message using the private key
    public static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    // Method to verify the signature using the public key
    public static boolean verifySignature(String message, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        return signature.verify(signatureBytes);
    }
}
