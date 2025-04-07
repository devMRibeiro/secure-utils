package com.devmribeiro.secureutils.cryptography;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import com.devmribeiro.secureutils.SecureUtils;
import com.devmribeiro.secureutils.interfaces.Encryptable;

/**
 * <p>This class implements the {@link Encryptable} interface and
 * provides RSA encryption and decryption functionalities.</p>
 * 
 * <p>It uses the RSA algorithm with a key size of 2048 bits to encrypt and decrypt data.</p>
 * 
 * <p>A key pair (public and private keys) is generated using the {@link KeyPairGenerator} class.
 * The encrypted data is encoded and decoded in Base64 format.
 * RSA encryption uses a public key for encryption and a private key for decryption.
 * </p>
 * 
 * @author Michael D. Ribeiro
 * @since 1.3
 */
public class RsaUtils implements Encryptable {

	private static final int KEY_SIZE = 2048;
	private static KeyPair KEY_PAIR;

	/**
	 * Constructor that initializes the key pair using the RSA algorithm.
	 * The key pair is generated using the {@link KeyPairGenerator} class with the specified {@link #KEY_SIZE}. 
	 */
	public RsaUtils() {
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(SecureUtils.RSA_ALGORITHM);
			keyPairGen.initialize(KEY_SIZE);
			KEY_PAIR = keyPairGen.generateKeyPair();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Encrypts the provided data using the RSA algorithm.
	 * The data is first converted to bytes and then encrypted using the RSA public key.
	 * The encrypted bytes are then encoded to a Base64 string.
	 * @param data The plaintext data to be encrypted
	 * @return The encrypted data as a Base64 encoded string
	 */
	public String encrypt(String data) {
		try {
			PublicKey publicKey = KEY_PAIR.getPublic();
			Cipher cipher = Cipher.getInstance(SecureUtils.RSA_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] encryptedBytes = cipher.doFinal(data.getBytes());
			return SecureUtils.base64Enconder(encryptedBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Decrypts the provided encrypted data using the RSA algorithm.
	 * The encrypted data is first decoded from Base64 and then decrypted using the RSA private key.
	 *
	 * @param encryptData The encrypted data as a Base64 encoded string
	 * @return The decrypted plaintext data
	 */
	public String decrypt(String encryptData) {
		try {
			PrivateKey privateKey = KEY_PAIR.getPrivate();
			byte[] encryptedBytes = SecureUtils.base64Decoder(encryptData.getBytes());
			Cipher cipher = Cipher.getInstance(SecureUtils.RSA_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
			return new String(decryptedBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Returns a reference to the public key component of this key pair.
	 * 
	 * @return a reference to the public key.
	 */
	public String getPublicKey() {
		return SecureUtils.base64Enconder(KEY_PAIR.getPublic().getEncoded());
	}

	/**
	 * Returns a reference to the private key component of this key pair.
	 *
	 * @return a reference to the private key.
	 */
	public String getPrivateKey() {
		return SecureUtils.base64Enconder(KEY_PAIR.getPrivate().getEncoded());
	}
}