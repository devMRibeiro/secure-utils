package com.devmribeiro.secureutils.interfaces;

public interface Encryptable {

	String encrypt(String data);

	String decrypt(String encryptData);
}