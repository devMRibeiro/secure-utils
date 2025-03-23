package com.devmribeiro.secureutils;

import java.security.SecureRandom;

public abstract class SecureUtils {

	protected static final String DEFAULT_CHARSET = "UTF-8";
	protected static final SecureRandom RANDOM = new SecureRandom();

	/**
	 * @return Random byte array of size.
	 */
	public static byte[] generateSalt(int size) {
		byte[] salt = new byte[size];
		RANDOM.nextBytes(salt);
		return salt;
	}
}