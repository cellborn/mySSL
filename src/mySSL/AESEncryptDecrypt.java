package mySSL;

import java.nio.ByteBuffer;
import java.security.spec.KeySpec;

import javax.crypto.*;
import javax.crypto.spec.*;

public class AESEncryptDecrypt {
	
	public AESEncryptDecrypt()
	{
		
	}
	public SecretKey CreateAESKeys(String password, long master_secret)
	{
		SecretKey secret = null;
		try
		{
		final byte[] master_key_Bytes = ByteBuffer.allocate(8).putLong(master_secret).array();
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec spec = new PBEKeySpec(password.toCharArray(), master_key_Bytes, 65536, 128);
		SecretKey tmp = factory.generateSecret(spec);
		secret = new SecretKeySpec(tmp.getEncoded(), "AES");
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		return secret;
	}
	public byte [] AESEncrypt(byte [] message, SecretKey secret) throws Exception {


		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		final IvParameterSpec iv = new IvParameterSpec(new byte[16]);
		cipher.init(Cipher.ENCRYPT_MODE, secret,iv);
		byte[] encrypted = cipher.doFinal(message);
		//System.out.println("encrypted string:" + (encrypted.toString()));
		return (encrypted);

	}
	public byte [] AESDecrypt(byte [] message, SecretKey secret) throws Exception {


		//SecretKeySpec skeySpec = new SecretKeySpec(secret.getBytes(), "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		final IvParameterSpec iv = new IvParameterSpec(new byte[16]);

		cipher.init(Cipher.DECRYPT_MODE, secret,iv);
		byte[] original = cipher.doFinal(message);

		return original;
	}
	

}
