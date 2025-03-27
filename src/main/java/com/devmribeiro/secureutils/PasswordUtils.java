package com.devmribeiro.secureutils;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * 
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
 * @version 1.3 (March 2025)
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
	
	private static char[] SYMBOLS = "^$*.[]{}()?-\"!@#%&/\\,><':;|_~`".toCharArray();
	private static char[] LOWERCASE = "abcdefghijklmnopqrstuvwxyz".toCharArray();
	private static char[] UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
	private static char[] NUMBERS = "0123456789".toCharArray();
	private static char[] ALL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789^$*.[]{}()?-\"!@#%&/\\,><':;|_~`".toCharArray();

	 /**
   * Generates a random password based on specific complexity requirements.
   * The generated password will contain at least one lowercase character, one uppercase character,
   * one number, and one special symbol, ensuring that these types of characters are included.
   * The remaining characters will be filled randomly from a broader set of characters.
   *
   * <p>The generated password is shuffled to ensure that the characters do not follow a predictable order.</p>
   * 
   * @param length The desired length of the password. It must be an integer greater than or equal to 4.
   *         If the length is less than 4, an {@link IllegalArgumentException} will be thrown.
   * 
   * @return The generated password as a {@link String}.
   * 
   * @throws IllegalArgumentException If the length of the password is less than 4.
   * 
   * @since 1.3
   */
  public static String getPassword(int length) {

  	if (length < 4)
  		throw new IllegalArgumentException("Length must be greater than or equals to 4");
      
  	char[] password = new char[length];

    // get the requirements out of the way
    password[0] = LOWERCASE[SecureUtils.RANDOM.nextInt(LOWERCASE.length)];
    password[1] = UPPERCASE[SecureUtils.RANDOM.nextInt(UPPERCASE.length)];
    password[2] = NUMBERS[SecureUtils.RANDOM.nextInt(NUMBERS.length)];
    password[3] = SYMBOLS[SecureUtils.RANDOM.nextInt(SYMBOLS.length)];

    // populate rest of the password with random chars
    for (int i = 4; i < length; i++)
    	password[i] = ALL_CHARS[SecureUtils.RANDOM.nextInt(ALL_CHARS.length)];

    // shuffle it up
    for (int i = 0; i < password.length; i++) {
        int randomPosition = SecureUtils.RANDOM.nextInt(password.length);
        char temp = password[i];
        password[i] = password[randomPosition];
        password[randomPosition] = temp;
    }
    return new String(password);
  }
}