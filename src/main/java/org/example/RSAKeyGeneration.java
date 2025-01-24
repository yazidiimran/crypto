package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAKeyGeneration {

    public static void main(String[] args) {
        try {
            int keySize = 2048; // Key size in bits
            SecureRandom random = new SecureRandom();

            // Step 1: Generate two large random primes, p and q
            BigInteger p = BigInteger.probablePrime(keySize / 2, random);
            BigInteger q = BigInteger.probablePrime(keySize / 2, random);

            // Step 2: Compute n = p * q
            BigInteger n = p.multiply(q);

            // Step 3: Compute ϕ(n) = (p - 1) * (q - 1)
            BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

            // Step 4: Choose public exponent e such that 1 < e < ϕ(n) and gcd(e, ϕ(n)) = 1
            BigInteger e = BigInteger.valueOf(65537); // Commonly used public exponent
            if (!phi.gcd(e).equals(BigInteger.ONE)) {
                throw new IllegalArgumentException("e and ϕ(n) are not coprime!");
            }

            // Step 5: Compute private exponent d such that e * d ≡ 1 (mod ϕ(n))
            BigInteger d = e.modInverse(phi);

            // Output the keys
            System.out.println("Public Key: (e = " + e + ", n = " + n + ")");
            System.out.println("Private Key: (d = " + d + ", n = " + n + ")");

            // Example message to encrypt and decrypt
            String message = "Hello, RSA!";
            System.out.println("Original Message: " + message);

            // Encrypt the message
            BigInteger plaintext = new BigInteger(message.getBytes());
            BigInteger ciphertext = plaintext.modPow(e, n);
            System.out.println("Encrypted Message: " + ciphertext);

            // Decrypt the message
            BigInteger decrypted = ciphertext.modPow(d, n);
            String decryptedMessage = new String(decrypted.toByteArray());
            System.out.println("Decrypted Message: " + decryptedMessage);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
