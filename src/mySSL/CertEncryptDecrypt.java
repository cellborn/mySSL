package mySSL;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.*;

import javax.crypto.*;

import sun.security.x509.*;

public class CertEncryptDecrypt {
	
	CertAndKeyGen keys;
	KeyStore keyStore;
	
	/**
	 * Constructor used to generate Cert and Keys
	 * @param keyType
	 * @param sigType
	 */
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
	/**
	 * Generate RSA keys based on key size passed
	 * @param keysize
	 * @return
	 */
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
	/**
	 * Create RSA certificate and get Public and Private keys and store in keystore
	 * @param keyStoreAlias
	 * @param keyStoreName
	 * @param password
	 * @param keys
	 */
	public void CertCreate(String keyStoreAlias, String keyStoreName, String password, CertAndKeyGen keys)
	{
		try{
		String commonName = "MattHunsaker"; //entity name
		String organizationalUnit = "cs5490";
		String organization = "Matt";
		String city = "SLC";
		String state = "UT";
		String country = "USA";
		long validity = 1096; // 3 years
		//String alias = "CERT";
		char[] keyPass = password.toCharArray();

		//create an empty keystore
		keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, null);

		//define entity holding certificate name and attributes
		X500Name x500Name = new X500Name(commonName, organizationalUnit, organization, city, state, country);

		//get the private key part
		PrivateKey privKey = keys.getPrivateKey();

		//creating the certificate
		X509Certificate[] chain = new X509Certificate[1];
		chain[0] = keys.getSelfCertificate(x500Name, new Date(), (long) validity * 24 * 60 * 60);

		//assigns the given private key to the given alias, protecting it with the given password and associating it with the given certificate . 
		keyStore.setKeyEntry(keyStoreAlias, privKey, keyPass, chain);

		//Stores this keystore to the given output stream, and protects its integrity with the given password.
		keyStore.store(new FileOutputStream(keyStoreName), keyPass);

		//Loads this KeyStore from the given input stream. 
		keyStore.load(new FileInputStream(keyStoreName), keyPass);
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

	}
	/**
	 * Get the generated certificate by looking up in keystore based on keystore alias name
	 * @param keyStoreAlias
	 * @return
	 */
	public X509Certificate getCert(String keyStoreAlias)
	{
		X509Certificate cert = null;
		try {
			cert = (X509Certificate) keyStore.getCertificate(keyStoreAlias);
			
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cert;
		
	}
	/**
	 * return the private key from kestore 
	 * @return
	 */
	public PrivateKey getPrivateKey()
	{
		PrivateKey keyPriv = null;
		try {
			keyPriv = keys.getPrivateKey();
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return keyPriv;
		
	}
	/**
	 * Encrypt a message using the Public key from certificate
	 * @param pubKey
	 * @param message
	 * @return
	 */
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
	/**
	 * Decrypt a RSA message using supplied Private key
	 * @param privKey
	 * @param message
	 * @return
	 */
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
	/**
	 * Create a SHA1 message digest 
	 * @param messageToHash
	 * @return
	 */
	public byte[] Hash(byte[] messageToHash)
	{
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		md.update(messageToHash, 0, messageToHash.length);

		byte[] mdbytes = md.digest();
		return mdbytes;
	}

}
