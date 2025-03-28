package com.devmribeiro.secureutils.cryptography;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.devmribeiro.secureutils.SecureUtils;
import com.devmribeiro.secureutils.interfaces.Encryptable;

public class AES implements Encryptable {

	private static final String AES_ALGORITHM = "AES";
	private static final int KEY_SIZE = 2048;
	
	private SecretKey key;
	
	// Constructor to initialize the encryption key
	AES() {
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
			keyGen.init(KEY_SIZE);
			key = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
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

	@Override
	public String decrypt(String encryptData) {
		try {
			byte[] encryptedBytes = SecureUtils.base64Decoder(null);
			Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, key);
			return new String (cipher.doFinal(encryptedBytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}