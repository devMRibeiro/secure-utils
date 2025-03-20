package com.devmribeiro.secureutils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class HashUtils {

	private static final SecureRandom RANDOM = new SecureRandom();

	/**
	 * <p>Generates a hash with a specific algorithm.</p>
	 * 
	 * @param content Content to be hashed.
	 * @param algorithm Hash algorithm(SHA-256, SHA-512).
	 * @return Base64 encoded hash.
	 * 
	 * @throws NoSuchAlgorithmException
	 */
	private static String hash(String content, String algorithm) {
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			byte[] hashBytes = md.digest(content.getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(hashBytes);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("HashUtils: error when generating hash " + e.getMessage(), e);
		}	
	}

	/**
	 * <p>Generates a SHA-256 hash of the provided content.</p>
	 * 
	 * @param content Content to be hashed.
	 * @return Base64 encoded SHA-256 hash.
	 */
	public static String sha256(String content) {
		return hash(content, "SHA-256");
	}

	/**
	 * <p>Generates a SHA-512 hash of the provided content.</p>
	 * 
	 * @param content Content to be hashed.
	 * @return Base64 encoded SHA-512 hash.
	 */
	public static String sha512(String content) {
		return hash(content, "SHA-512");
	}

	/**
	 * @return Random byte array of size 16.
	 */
	public static byte[] getSalt() {
		byte[] salt = new byte[16];
    RANDOM.nextBytes(salt);
    return salt;
	}

	private static String hashSalt(String content, byte[] salt, String algorithm) {
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			md.update(salt);
			byte[] bytes = md.digest(content.getBytes(StandardCharsets.UTF_8));
			byte[] hashSalt = new byte[bytes.length + salt.length];
			System.arraycopy(salt, 0, hashSalt, 0, salt.length);
      System.arraycopy(bytes, 0, hashSalt, salt.length, bytes.length);
      return Base64.getEncoder().encodeToString(hashSalt);
		} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("HashUtils: error when generating hash with salt " + e.getMessage(), e);
		}
	}

	public static String sha256Salt(String content, byte[] salt) {
		return hashSalt(content, salt, "SHA-256"); 
	}

	public static String sha512Salt(String content, byte[] salt) {
		return hashSalt(content, salt, "SHA-512"); 
	}
}