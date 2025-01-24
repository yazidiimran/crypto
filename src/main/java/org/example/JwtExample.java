package org.example;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class JwtExample {

    // Method to generate JWT
    public static String generateJwt(String headerJson, String payloadJson, String secret) throws Exception {
        // Encode Header
        String header = base64UrlEncode(headerJson.getBytes());

        // Encode Payload
        String payload = base64UrlEncode(payloadJson.getBytes());

        // Create Signature
        String signature = createHmacSha256Signature(header + "." + payload, secret);

        // Combine all parts
        return header + "." + payload + "." + signature;
    }

    // Method to validate JWT
    public static boolean validateJwt(String token, String secret) throws Exception {
        // Split JWT into parts
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return false;
        }

        String header = parts[0];
        String payload = parts[1];
        String signature = parts[2];

        // Recalculate signature
        String expectedSignature = createHmacSha256Signature(header + "." + payload, secret);

        // Compare signatures
        return expectedSignature.equals(signature);
    }

    // Helper method to create HMAC-SHA256 signature
    private static String createHmacSha256Signature(String data, String secret) throws Exception {
        Mac hmacSha256 = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
        hmacSha256.init(keySpec);

        byte[] signatureBytes = hmacSha256.doFinal(data.getBytes());
        return base64UrlEncode(signatureBytes);
    }

    // Helper method for Base64 URL encoding
    private static String base64UrlEncode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // Helper method for Base64 URL decoding
    private static String base64UrlDecode(String str) {
        return new String(Base64.getUrlDecoder().decode(str));
    }

    public static void main(String[] args) throws Exception {
        // Define header and payload
        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}";

        // Secret key
        String secret = "your-256-bit-secret";

        // Generate JWT
        String jwt = generateJwt(headerJson, payloadJson, secret);
        System.out.println("Generated JWT: " + jwt);

        // Validate JWT
        boolean isValid = validateJwt(jwt, secret);
        System.out.println("Is JWT valid? " + isValid);
    }
}
