package es.mesa;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {
	
	private static final int IV_LENGTH=16;
	/**
	 * Encrypt using the Cipher with AES/CFB8/NoPadding
	 * @param in, InputStream with the bytes to encrypt
	 * @param out, OutputStream with the encrypted bytes
	 * @param password, The password used to encrypt/decrypt
	 * @throws Exception
	 */
	public static void encrypt(InputStream in, OutputStream out, String password) throws Exception{

		SecureRandom r = new SecureRandom();
		byte[] iv = new byte[IV_LENGTH];
		r.nextBytes(iv);
		out.write(iv); //write IV as a prefix
		out.flush();
		//System.out.println(">>>>>>>>written"+Arrays.toString(iv));

		Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding"); //"DES/ECB/PKCS5Padding";"AES/CBC/PKCS5Padding"
		SecretKeySpec keySpec = new SecretKeySpec(password.getBytes(), "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);    	

		out = new CipherOutputStream(out, cipher);
		byte[] buf = new byte[1024];
		int numRead = 0;
		while ((numRead = in.read(buf)) >= 0) {
			out.write(buf, 0, numRead);
		}
		out.close();		
	}

	/**
	 * Decrypt using the Cipher with AES/CFB8/NoPadding
	 * @param in, InputStream with the bytes to decrypt
	 * @param out, OutputStream with the decrypted bytes
	 * @param password, The password used to encrypt/decrypt
	 * @throws Exception
	 */
	public static void decrypt(InputStream in, OutputStream out, String password) throws Exception{

		byte[] iv = new byte[IV_LENGTH];
		in.read(iv);
		//System.out.println(">>>>>>>>red"+Arrays.toString(iv));

		Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding"); //"DES/ECB/PKCS5Padding";"AES/CBC/PKCS5Padding"
		SecretKeySpec keySpec = new SecretKeySpec(password.getBytes(), "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

		in = new CipherInputStream(in, cipher);
		byte[] buf = new byte[1024];
		int numRead = 0;
		while ((numRead = in.read(buf)) >= 0) {
			out.write(buf, 0, numRead);
		}
		out.close();
	}
	
	/**
	 * ENCRYPT/DECRYPT a file into another file
	 * @param mode, for encrypt mode: javax.crypto.Cipher.ENCRYPT_MODE = 1 \n
	 * 		  for decrypt mode: int javax.crypto.Cipher.DECRYPT_MODE = 2
	 * @param inputFile, the route of the input file
	 * @param outputFile, the route of the output file
	 * @param password, The password used to encrypt/decrypt
	 * @throws Exception
	 */
	public static void copy(int mode, String inputFile, String outputFile, String password) throws Exception {
		/* For Android
		  BufferedInputStream is = new BufferedInputStream(new FileInputStream(Environment.getExternalStorageDirectory().getAbsolutePath()+"/"+inputFile));
		  BufferedOutputStream os = new BufferedOutputStream(new FileOutputStream(Environment.getExternalStorageDirectory().getAbsolutePath()+"/"+outputFile));
		 */
		BufferedInputStream is = new BufferedInputStream(new FileInputStream(inputFile));
		BufferedOutputStream os = new BufferedOutputStream(new FileOutputStream(outputFile));
		if(mode==Cipher.ENCRYPT_MODE){
			encrypt(is, os, password);
		}
		else if(mode==Cipher.DECRYPT_MODE){
			decrypt(is, os, password);
		}
		else throw new Exception("unknown mode");
		is.close();
		os.close();
	}
}
