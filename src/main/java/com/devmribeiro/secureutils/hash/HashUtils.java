package com.devmribeiro.secureutils.hash;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.devmribeiro.secureutils.SecureUtils;

/**
 * <p>
 * Utility class providing cryptographic hashing functionalities, including SHA-256 and SHA-512
 * algorithms with optional salting for enhanced security. This class simplifies the process
 * of generating secure hashes.
 * </p>
 * 
 * <p>
 * It is particularly useful for integrity verification of data.
 * </p>
 * 
 * <p>
 * Features:
 * <ul>
 *   <li>Generate SHA-256 and SHA-512 hashes.</li>
 *   <li>Support for random salt generation to increase hash uniqueness.</li>
 *   <li>Ability to validate a content against a given hash.</li>
 *   <li>Utilizes Base64 encoding for better storage and transmission.</li>
 * </ul>
 * </p>
 * 
 * <p><strong>Note:</strong> This class is designed for general-purpose hashing and should not be used 
 * as a replacement for more advanced password-hashing algorithms like BCrypt or Argon2 for authentication.</p>
 * 
 * @author Michael D. Ribeiro
 * @version 1.0 (March 2025)
 * @since 1.0
 */
public class HashUtils {

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
			return SecureUtils.base64Enconder(hashBytes);
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
	 * <p>Generates a hash with a specific algorithm and random salt.</p>
	 * 
	 * @param content Content to be hashed.
	 * @param salt Salt to add randomness.
	 * @param algorithm Hash algorithm(SHA-256, SHA-512).
	 * @return Hash with Salt concatenated and encoded in Base64.
	 */
	private static String hashSalt(String content, byte[] salt, String algorithm) {
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			md.update(salt);
			byte[] bytes = md.digest(content.getBytes(StandardCharsets.UTF_8));
			byte[] hashSalt = new byte[bytes.length + salt.length];
			System.arraycopy(salt, 0, hashSalt, 0, salt.length);
      System.arraycopy(bytes, 0, hashSalt, salt.length, bytes.length);
      return SecureUtils.base64Enconder(hashSalt);
		} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("HashUtils: error when generating hash with salt " + e.getMessage(), e);
		}
	}

	/**
	 * @param content Content to be hashed.
	 * @param salt Salt to add randomness.
	 * @return Base64 encoded SHA-256 hash with salt.
	 */
	public static String sha256Salt(String content, byte[] salt) {
		return hashSalt(content, salt, "SHA-256"); 
	}

	/**
	 * @param content Content to be hashed.
	 * @param salt Salt to add randomness.
	 * @return Base64 encoded SHA-512 hash with salt.
	 */
	public static String sha512Salt(String content, byte[] salt) {
		return hashSalt(content, salt, "SHA-512"); 
	}
}