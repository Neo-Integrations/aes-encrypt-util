package org.neointegration.crypto;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtil {
	private static Decoder decoder  = Base64.getDecoder();
	private static Encoder encoder  = Base64.getEncoder();

	public static String encrypt(String plainKey, String plainText,  String mode, String algo) {
		
		String cypherText = null;
		try {
			Cipher cipher = Cipher.getInstance(algo + "/" + mode + "/PKCS5PADDING");
			SecureRandom secureRandom = new SecureRandom();

			byte[] ivInByteArray = new byte[cipher.getBlockSize()];
			Key key = new SecretKeySpec(plainKey.getBytes("UTF-8"), algo);
			ivInByteArray = Arrays.copyOfRange(key.getEncoded(), 0, ivInByteArray.length);
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivInByteArray),
					secureRandom);

			byte[] result = cipher.doFinal(plainText.getBytes("UTF-8"));
			cypherText = encoder.encodeToString(result);

		} catch (Exception e) {
			System.out.println("Unable to encrypt the text [" + plainText + "]");
			e.printStackTrace();
		}

		return cypherText;
	}
	
	public static String decrypt(final String plainKey, 
			final String encodedCypherText, 
			final String mode, final String algo) {
		
		String plainText = null;
		try {
			byte[] decodedCypherText = decoder.decode(encodedCypherText.getBytes());
			Cipher cipher = Cipher.getInstance(algo + "/" + mode + "/PKCS5PADDING");
			SecureRandom secureRandom = new SecureRandom();

			byte[] ivInByteArray = new byte[cipher.getBlockSize()];
			Key key = new SecretKeySpec(plainKey.getBytes("UTF-8"), algo);
			ivInByteArray = Arrays.copyOfRange(key.getEncoded(), 0, ivInByteArray.length);
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivInByteArray),
					secureRandom);

			byte[] result = cipher.doFinal(decodedCypherText);
			plainText = new String(result);

		} catch (Exception e) {
			System.out.println("Unable to decypt the cypher [" + encodedCypherText + "]");
			e.printStackTrace();
		}

		return plainText;
	}
	
	public static void main(String[] args) {
		System.out.println(encrypt("1234567812345678", "Hello", "CBC", "AES"));
	}

}
