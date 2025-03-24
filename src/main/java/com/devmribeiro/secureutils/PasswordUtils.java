package com.devmribeiro.secureutils;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public class PasswordUtils {

	private static final int ITERATIONS_LIMIT = 3;
	private static final int MEMOMRY_LIMIT = 262144;
	private static final int HASH_LENGTH = 32;
	private static final int PARALLELISM = 1;
	
	public static byte[] hashPassword(String password, byte[] salt) {
		Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
				.withVersion(Argon2Parameters.ARGON2_VERSION_13)
				.withIterations(ITERATIONS_LIMIT)
				.withMemoryAsKB(MEMOMRY_LIMIT)
				.withParallelism(PARALLELISM)
				.withSalt(salt);

		Argon2BytesGenerator generate = new Argon2BytesGenerator();
		generate.init(builder.build());
		byte[] result = new byte[HASH_LENGTH];
		generate.generateBytes(password.getBytes(StandardCharsets.UTF_8), result, 0, result.length);
		return result;
	}
}