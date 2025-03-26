package com.devmribeiro.secureutils;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Utility class for hashing and validating passwords using the Argon2 algorithm.
 * This class provides methods to generate secure password hashes and validate them.
 * 
 * <p>
 * The Argon2 hashing algorithm is used with predefined parameters such as:
 * </p>
 * <ul>
 *     <li>Iterations: {@value #ITERATIONS_LIMIT}</li>
 *     <li>Memory: {@value #MEMOMRY_LIMIT} KB</li>
 *     <li>Hash length: {@value #HASH_LENGTH} bytes</li>
 *     <li>Parallelism: {@value #PARALLELISM}</li>
 * </ul>
 * 
 * <p>
 * This class should be used to securely store and verify passwords in applications
 * that require strong password protection.
 * </p>
 * 
 * @author Michael D. Ribeiro
 * @version 1.2 (March 2025)
 * @since 1.1
 */
public class PasswordUtils {

	private static final int ITERATIONS_LIMIT = 3;
	private static final int MEMOMRY_LIMIT = 262144;
	private static final int HASH_LENGTH = 32;
	private static final int OUTPUT_LENGTH = 32;
	private static final int PARALLELISM = 1;

	/**
   * Generates a hashed password using the Argon2 algorithm.
   *
   * @param builder      The Argon2 parameters builder.
   * @param outputLength The desired length of the output hash.
   * @param pass         The password to be hashed.
   * @return A byte array containing the hashed password.
   */
	private static byte[] generator(Argon2Parameters.Builder builder, int outputLength, String pass) {
		Argon2BytesGenerator generate = new Argon2BytesGenerator();
		generate.init(builder.build());
		byte[] result = new byte[HASH_LENGTH];
		generate.generateBytes(pass.getBytes(StandardCharsets.UTF_8), result, 0, result.length);
		return result;
	}

	/**
   * Builds an {@link Argon2Parameters.Builder} with predefined security settings.
   *
   * @param password The password to be hashed (not used in the builder but included for reference).
   * @param salt     The salt value to enhance password security.
   * @return An {@link Argon2Parameters.Builder} instance with predefined settings.
   */
	private static Argon2Parameters.Builder builder(String password, byte[] salt) {
		return new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
				.withVersion(Argon2Parameters.ARGON2_VERSION_13)
				.withIterations(ITERATIONS_LIMIT)
				.withMemoryAsKB(MEMOMRY_LIMIT)
				.withParallelism(PARALLELISM)
				.withSalt(salt);
	}

	/**
   * Hashes a password using the Argon2 algorithm and returns the result as a Base64-encoded string.
   *
   * @param password The password to be hashed.
   * @param salt     The salt value to be used in hashing.
   * @return A Base64-encoded string representing the hashed password.
   */
	public static String hashPassword(String password, byte[] salt) {
		return SecureUtils.base64Enconder(generator(builder(password, salt), OUTPUT_LENGTH, password));
	}

	/**
   * Validates an input password against a stored hash using the same salt.
   *
   * @param inputPassword The password entered by the user.
   * @param storedHash    The stored Base64-encoded hashed password.
   * @param salt          The salt used during the original password hashing.
   * @return {@code true} if the input password matches the stored hash, {@code false} otherwise.
   * @since 1.2
   */
	public static boolean validate(String inputPassword, String storedHash, byte[] salt) {
		return hashPassword(inputPassword, salt).equals(storedHash);
	}
}