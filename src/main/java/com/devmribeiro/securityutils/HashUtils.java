package com.devmribeiro.securityutils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HashUtils {
	public static String sha256(String input) {
		return hash(input, "sha-256");
	}

	private static String hash(String input, String algorithm) {
		try {

			MessageDigest md = MessageDigest.getInstance(algorithm);
			byte[] hashBytes = md.digest(input.getBytes(StandardCharsets.UTF_8));

			return Base64.getEncoder().encodeToString(hashBytes);

		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage(), e);
		}	
	}
}