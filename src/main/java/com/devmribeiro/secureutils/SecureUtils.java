package com.devmribeiro.secureutils;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility class providing cryptographic-related helper methods.  
 * <p>  
 * This class includes methods for generating secure random salts and encoding/decoding data  
 * using the Base64 format. It serves as a utility for handling basic cryptographic operations  
 * in a secure manner.  
 * </p>  
 * <p>  
 * This class is abstract and cannot be instantiated. All methods are static and should be  
 * accessed directly.  
 * </p>  
 *  
 * @author Michael D. Ribeiro  
 * @version 1.1 (March 2025)  
 * @since 1.0  
 */
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
	 * @since 1.1
	 */
	public static String base64Enconder(byte[] input) {
		return Base64.getEncoder().encodeToString(input);
	}
	
	/**
	 * Decodes a Base64-encoded byte array.
	 * 
	 * @param input The byte array encoded in Base64.
	 * @return A byte array containing the decoded data.
	 * @since 1.1
	 */
	public static byte[] base64Decoder(byte[] input) {
		return Base64.getDecoder().decode(input);
	}
}