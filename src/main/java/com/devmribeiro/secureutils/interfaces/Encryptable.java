package com.devmribeiro.secureutils.interfaces;

/**
 * <p>The Encryptable interface defines methods for encrypting and decrypting data.
 * Implementing classes should provide their own encryption and decryption logic.</p>
 * 
 * @since 1.3
 * @author Michael D. Ribeiro
 */
public interface Encryptable {

	/**
     * Encrypts the given data.
     * 
     * @param data The data to be encrypted.
     * @return The encrypted data as a string.
     */
	String encrypt(String data);

	/**
     * Decrypts the given encrypted data.
     * 
     * @param encryptData The encrypted data to be decrypted.
     * @return The original data as a string.
     */
	String decrypt(String encryptData);
}