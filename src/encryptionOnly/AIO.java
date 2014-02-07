package encryptionOnly;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class AIO {

	private static String encryptedString;
	private static String input;
	private static String inputString;
	private static byte[] key = { 0x74, 0x68, 0x69, 0x73, 0x49, 0x73, 0x41,
			0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4b, 0x65, 0x79 };// "thisIsASecretKey";
	private static String keyString = "averylongtext!@$@#$#@$#*&(*&}{23432432432dsfsdf";

	public void encryptor(String input) {
	}

	public static void main(String[] args) throws Exception {

		encryptedString = new String(encrypt(readFromFile()));
		writingToFile();

	}

	private static void writingToFile() {
		try {

			String content = encryptedString;
			File file = new File("C:/Users/Xelnect/Desktop/encrypted.txt");
			// if file doesnt exists, then create it
			if (!file.exists()) {
				file.createNewFile();
			}

			FileWriter fw = new FileWriter(file.getAbsoluteFile());
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(content);
			bw.close();

			System.out.println("Done");

		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private static String readFromFile() {

		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(
					"C:/Users/Xelnect/Desktop/messageToBeDecrypted.txt"));
			while ((input = br.readLine()) != null) {
				inputString = input;
				System.out.println(input);
			}

		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (br != null)
					br.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}
		return inputString;
	}

	public static String encrypt(String input) throws InvalidKeyException,
			InvalidAlgorithmParameterException, GeneralSecurityException,
			BadPaddingException, UnsupportedEncodingException {
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		byte[] iv = new byte[cipher.getBlockSize()];
		new SecureRandom().nextBytes(iv);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(keyString.getBytes());
		System.arraycopy(digest.digest(), 0, key, 0, key.length);
		SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
		
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
		String encryptedString = Base64.encodeBase64String(cipher.doFinal(input.getBytes()));
		return encryptedString;
	}

}
