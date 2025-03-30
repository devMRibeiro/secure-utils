package com.devmribeiro.secureutils.cryptography;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.devmribeiro.secureutils.SecureUtils;
import com.devmribeiro.secureutils.interfaces.Encryptable;

/**
 * <p>
 * This class implements the {@link Encryptable} interface and
 * provides AES encryption and decryption functionalities.
 * </p>
 * 
 * <p>
 * It uses the Advanced Encryption Standard (AES) algorithm with a key size of 128 bits.
 * </p>
 * 
 * <p>
 * The encryption key is generated using the {@link KeyGenerator} class.
 * The class provides methods to encrypt and decrypt data using the AES algorithm,
 * and the encrypted data is encoded and decoded in Base64 format.
 * </p>
 *
 * @author Michael D. Ribeiro
 * @since 1.3
 */
public class AES implements Encryptable {

	private static final String AES_ALGORITHM = "AES";
	private static final int KEY_SIZE = 128;
	
	private SecretKey key;
	
	/**
	 * Constructor that initializes the encryption key using the AES algorithm.
   * 
   * The key is generated using the {@link KeyGenerator} 
   * class with the specified {@link #KEY_SIZE}.
   */
	public AES() {
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
			keyGen.init(KEY_SIZE);
			key = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	/**
   * Encrypts the provided data using the AES algorithm.
   * The data is first converted to bytes and then encrypted with the generated AES key.
   * The encrypted bytes are then encoded to a Base64 string.
   * 
   * @param data The plaintext data to be encrypted
   * @return The encrypted data as a Base64 encoded string
   */
	@Override
	public String encrypt(String data) {
		try {
			Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] encryptedBytes = cipher.doFinal(data.getBytes());
			return SecureUtils.base64Enconder(encryptedBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
   * Decrypts the provided encrypted data using the AES algorithm.
   * The encrypted data is first decoded from Base64 and then decrypted with the AES key.
   * 
   * @param encryptData The encrypted data as a Base64 encoded string
   * @return The decrypted plaintext data
   */
	@Override
	public String decrypt(String encryptData) {
		try {
			byte[] encryptedBytes = SecureUtils.base64Decoder(encryptData.getBytes());
			Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, key);
			return new String (cipher.doFinal(encryptedBytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}