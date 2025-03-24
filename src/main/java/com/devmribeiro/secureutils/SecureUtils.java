package com.devmribeiro.secureutils;

import java.security.SecureRandom;

public abstract class SecureUtils {

	protected static final SecureRandom RANDOM = new SecureRandom();

	/**
	 * @param size The size to salt.
	 * @return Random byte array of size {@code size}.
	 */
	public static byte[] generateSalt(int size) {
		byte[] salt = new byte[size];
		RANDOM.nextBytes(salt);
		return salt;
	}
}