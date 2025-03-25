package com.devmribeiro.secureutils;

import java.security.SecureRandom;
import java.util.Base64;

public abstract class SecureUtils {

	protected static final SecureRandom RANDOM = new SecureRandom();

	/**
	 * Generates a random salt of the specified size.
	 * 
	 * @param size The size (in bytes) of the salt to generate.
	 * @return A random byte array of the specified size, which can be used as a salt.
	 */
	public static byte[] generateSalt(int size) {
		byte[] salt = new byte[size];
		RANDOM.nextBytes(salt);
		return salt;
	}
	
	/**
	 * Encodes a byte array into a Base64-encoded string.
	 * 
	 * @param input The byte array to be encoded in Base64.
	 * @return A string containing the Base64-encoded representation of the input byte array.
	 */
	public static String base64Enconder(byte[] input) {
		return Base64.getEncoder().encodeToString(input);
	}
	
	/**
	 * Decodes a Base64-encoded byte array.
	 * 
	 * @param input The byte array encoded in Base64.
	 * @return A byte array containing the decoded data.
	 */
	public static byte[] base64Decoder(byte[] input) {
		return Base64.getDecoder().decode(input);
	}
}