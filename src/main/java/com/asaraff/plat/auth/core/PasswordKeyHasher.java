package com.asaraff.plat.auth.core;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * This class encapsulates Hashing strategy for sample Auth. Encapsulating in this library helps multiple
 * projects share the same library. Any change in the algorithm is likewise propagated to the dependent services.
 * This code is largely based on:CrackStation Java Implementation}
 */
public final class PasswordKeyHasher {
    private static final int SALT_BYTE_SIZE = 16;

    private final int keyspecIterationCount;
    private final String secretKeyAlgorithm;
    private final String secureRandomAlgorithm;
    private final int keyspecKeyLength;

    private PasswordKeyHasher(Builder builder) {
        this.secretKeyAlgorithm = builder.secretKeyAlgorithm;
        this.keyspecIterationCount = builder.keyspecIterationCount;
        secureRandomAlgorithm = builder.secureRandomAlgorithm;
        keyspecKeyLength = builder.keyspecKeyLength;
    }

    public static Builder builder() {return new Builder();}
    /**
     * Generates a Hash on the input plain text (Password) String. The implementation uses
     * Salt+Password+IterationCount+Algorithm to concoct the Hash.
     * @param plainTextPassword Password entered by the user/agent (Plain text representation)
     * @param salt
     * @return Hash-String
     */
    public final String generatePasswordHash(String plainTextPassword, String salt) throws IllegalStateException {
        char[] chars = plainTextPassword.toCharArray();
        byte[] saltByte = salt.getBytes();
        // for now only fixed-size PBE ciphers are used as opposed to variable length given in the last argument
        PBEKeySpec spec = new PBEKeySpec(chars, saltByte, keyspecIterationCount, keyspecKeyLength);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(secretKeyAlgorithm);
            byte[] hash;
            hash = skf.generateSecret(spec).getEncoded();
            return String.format("%s:%s", toHex(saltByte), toHex(hash));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Error in Hashing", e);
        }
    }
    /**
     * This is a helper method that validates a password with  salt in the input password.
     * First, we convert the plain password to the hash. Next, we validate (Compare) against the stored password
     * If both matches, we have a hit. Else, it is a miss.
     * @param plainTextPassword Password entered by the user (Plain text representation)
     * @param hashedPassword Password we have stored (Hash representation)
     * @return boolean True if the password-hash matches. False else.
     */
    public final boolean isPasswordHashMatch(String plainTextPassword, String hashedPassword) {
        // Hash has a Salt+Password (Salt is in "prefix" position)
        String[] parts = hashedPassword.split(":");
        if(parts.length != 2) {
            return false; // invalid hash
        }
        byte[] salt = fromHex(parts[0]);
        byte[] hash = fromHex(parts[1]);
        // Compute the hash on the provided (web/input)password using the same salt which we got from the prefix
        // We don't use the Hashlength
        PBEKeySpec pbeKeySpec = new PBEKeySpec(plainTextPassword.toCharArray(), salt, keyspecIterationCount, keyspecKeyLength);
        SecretKeyFactory skf;
        try {
            // use the inject algorithm
            skf = SecretKeyFactory.getInstance(secretKeyAlgorithm);
            // this is the generated hash from the input password
            byte[] testHash = skf.generateSecret(pbeKeySpec).getEncoded();
            // Compare the two hashes, length and all
            int diff = hash.length ^ testHash.length;
            for(int i = 0; i < hash.length && i < testHash.length; i++)
            {
                diff |= hash[i] ^ testHash[i];
            }
            return diff == 0;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return false;
        }
    }

    /**
     * Generates a String out of a byte array
     * @param array
     * @return
     * @throws NoSuchAlgorithmException
     */
    private String toHex(byte[] array) throws NoSuchAlgorithmException
    {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0)
        {
            return String.format("%0"  +paddingLength + "d", 0) + hex;
        }else{
            return hex;
        }
    }

    /**
     * Returns a byte array from the input hexadecimal text
     * @param hex hexadecimal String input
     * @return array of byte
     */
    private byte[] fromHex(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for(int i = 0; i<bytes.length ;i++)
        {
            bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

    /**
     * Generates a salt for variable byte.
     * @return
     * @throws NoSuchAlgorithmException
     */
    public String generateSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance(secureRandomAlgorithm);
        byte[] salt = new byte[SALT_BYTE_SIZE];
        sr.nextBytes(salt);
        return Arrays.toString(salt);
    }

    public static class Builder {
        private int keyspecIterationCount;
        private String secretKeyAlgorithm;
        private String secureRandomAlgorithm;
        private int keyspecKeyLength;

        private Builder() {}

        public Builder keyspecIterationCount(int keyspecIterationCount) {
            this.keyspecIterationCount = keyspecIterationCount;
            return this;
        }

        public Builder secretKeyAlgorithm(String secretKeyAlgorithm) {
            this.secretKeyAlgorithm = secretKeyAlgorithm;
            return this;
        }

        public Builder secureRandomAlgorithm(String randomAlgorithm) {
            this.secureRandomAlgorithm = randomAlgorithm;
            return this;
        }

        public Builder keyspecKeyLength(int keyspecLength) {
            this.keyspecKeyLength = keyspecLength;
            return this;
        }

        public PasswordKeyHasher build() {
            return new PasswordKeyHasher(this);
        }
    }
}
