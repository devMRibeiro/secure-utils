package com.devmribeiro.secureutils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class HashUtils {
	
	private static final SecureRandom RANDOM = new SecureRandom();
	
	private static String hash(String input, String algorithm) {
		try {

			MessageDigest md = MessageDigest.getInstance(algorithm);
			byte[] hashBytes = md.digest(input.getBytes(StandardCharsets.UTF_8));

			return Base64.getEncoder().encodeToString(hashBytes);

		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage(), e);
		}	
	}

	public static String sha256(String input) {
		return hash(input, "sha-256");
	}

	public static String sha512(String input) {
		return hash(input, "sha-512");
	}

	private static String hashSalt(String input, byte[] salt, String algorithm) {
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			md.update(salt);

			byte[] bytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
			byte[] hashSalt = new byte[bytes.length + salt.length];

			System.arraycopy(salt, 0, hashSalt, 0, salt.length);
      System.arraycopy(bytes, 0, hashSalt, salt.length, bytes.length);
      
      return Base64.getEncoder().encodeToString(hashSalt);

		} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("Error when generating hash with salt " + e.getMessage(), e);
		}
	}

	private static byte[] getSalt() {
    byte[] salt = new byte[16];
    RANDOM.nextBytes(salt);
    return salt;
	}

	public static String sha256Salt(String input) {
		return hashSalt(input, getSalt(), "SHA-256"); 
	}

	public static String sha512Salt(String input) {
		return hashSalt(input, getSalt(), "SHA-512"); 
	}
}