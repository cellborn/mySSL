package mySSL;

import java.nio.ByteBuffer;
import java.security.*;
import javax.crypto.*;
import sun.security.x509.CertAndKeyGen;

public class CertEncryptDecrypt {
	
	CertAndKeyGen keys;
	
	public CertEncryptDecrypt(String keyType, String sigType)
	{
		
		try {
			keys = new CertAndKeyGen(keyType,sigType,null);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	public CertAndKeyGen CreateKeys(int keysize)
	{
		try {
			keys.generate(keysize);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return keys;
	}
	public byte[] CertEncrypt(PublicKey pubKey, long message)
	{
		Cipher cipher;
		byte[] cipherTextBytes = null;
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			final byte[] plainTextBytes = ByteBuffer.allocate(8).putLong(message).array();
			cipherTextBytes = cipher.doFinal(plainTextBytes);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cipherTextBytes;
	}
	public long CertDecrypt(PrivateKey privKey, byte[] message )
	{
		Cipher cipher;
		long plainText = 0;
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, privKey);

			final byte[] plainTextBytes = cipher.doFinal(message);
			final ByteBuffer byteBuffer = ByteBuffer.wrap(plainTextBytes);
			plainText = byteBuffer.getLong(0);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		return plainText;
	}

}
