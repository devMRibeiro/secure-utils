package com.devmribeiro.secureutils.cryptography;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import com.devmribeiro.secureutils.SecureUtils;
import com.devmribeiro.secureutils.interfaces.Encryptable;

public class RSA implements Encryptable {

	private static final String RSA_ALGORITHM = "RSA";
	private static final int KEY_SIZE = 2048;

	private KeyPair keyPair;

	RSA() {
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
			keyPairGen.initialize(KEY_SIZE);
			keyPair = keyPairGen.generateKeyPair();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public String encrypt(String data) {
		
		try {
			PublicKey publicKey = keyPair.getPublic();
			Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
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
			PrivateKey privateKey = keyPair.getPrivate();
			byte[] encryptedBytes = SecureUtils.base64Decoder(encryptData.getBytes());
			Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
			return new String(decryptedBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}