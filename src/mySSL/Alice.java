package mySSL;

import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.crypto.SecretKey;

import sun.security.x509.CertAndKeyGen;

import org.apache.commons.lang3.*;

public class Alice {
	
	String encryptType =  "RSA";
	String integType = "SHA1WithRSA";
	String supportedCipher = "AESxSHA1";
	SecureRandom ranNum = new SecureRandom();
	Socket 	bSocket;
	OutputStream bOutStream;
	InputStream bInStream;
	PrintWriter sendBob;
	BufferedReader recieveBob;
	ObjectOutputStream bOOStream;
	ObjectInputStream bOIStream;
	ArrayList<Byte> bobMessages = new ArrayList<Byte>();
	Util output;
	String filename = "alice_output.txt";
	
	CertEncryptDecrypt certEd;
	int keySize = 1024;
	X509Certificate alice_cert;
	X509Certificate bob_cert;
	PublicKey bob_cert_pub;
	
	CertAndKeyGen keypair;
	
	long randomAlice, randomBob, master_secret;
	AESEncryptDecrypt AesEd;
	SecretKey aesSecret;
	
	public Alice(int port)
	{
		output = new Util(filename);
		GenerateCert(encryptType,integType);
		OpenSocket(port);
		StartHandShake();
		GetBobCert();
		SendReceiveRandom();
		SendReceiveMAC();
		RSAKeys();
	}
	
	private void OpenSocket(int port)
	{
		try {
			bSocket = new Socket("localhost", port);
			bOutStream = bSocket.getOutputStream();
			bInStream = new DataInputStream(bSocket.getInputStream());
			sendBob = new PrintWriter(bOutStream, true);
			recieveBob = new BufferedReader(new InputStreamReader(bSocket.getInputStream()));
			bOOStream = new ObjectOutputStream(bOutStream);
			bOIStream = new ObjectInputStream(bInStream);
			
			
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private void GenerateCert(String keyType, String sigType)
	{
		certEd = new CertEncryptDecrypt(keyType, sigType);
		
		keypair = certEd.CreateKeys(keySize);
		
		certEd.CertCreate("alice_cert", "alice_keystore", "123456", keypair);
		
		alice_cert = certEd.getCert("alice_cert");
		
		output.Output("Alice generating certificate\n");
		output.Output("Alice Cert= " + alice_cert.toString() + "\n");
		
	}
	private void StartHandShake()
	{
		output.Output("Alice starting communication\n");
		output.Output("Sending supported cipher " + supportedCipher + " and Alices certificate\n" );
		
		try {
			bOOStream.writeObject(1);
			bOOStream.writeObject(supportedCipher);
			bOOStream.writeObject(alice_cert);
			System.out.flush();
			
			byte[] talk_Req_b =ByteBuffer.allocate(4).putInt(1).array();
			bobMessages.addAll(Arrays.asList(ArrayUtils.toObject(talk_Req_b)));
			byte[] cipher_supported_b= supportedCipher.getBytes();
			bobMessages.addAll(Arrays.asList(ArrayUtils.toObject(cipher_supported_b)));
			byte[] aliceBob_cert = alice_cert.getEncoded();
			bobMessages.addAll(Arrays.asList(ArrayUtils.toObject(aliceBob_cert)));
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	private void GetBobCert()
	{
		output.Output("Getting Bob's certificate and Verifying\n");
		
		try {
			bob_cert = (X509Certificate)bOIStream.readObject();
			output.Output("Recieved Bob's cert " + bob_cert.toString());
			
			output.Output("Verifying Bob's Cert\n");
			bob_cert.checkValidity();
			bob_cert.verify(bob_cert.getPublicKey());
			output.Output("Bob's certificate valid and verified\n");
			
			bob_cert_pub = bob_cert.getPublicKey();
			output.Output("Got Bob public key from certificate\n");
			
			byte[] bob_cert_bytes = bob_cert.getEncoded();
			bobMessages.addAll(Arrays.asList(ArrayUtils.toObject(bob_cert_bytes)));
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}
	private void SendReceiveRandom()
	{
		output.Output("Generating Random number nonce for Alice\n");
		
		randomAlice = Math.abs(ranNum.nextLong());
		output.Output("Alice random nonce is: " + Long.toString(randomAlice) + "\n");
		
		output.Output("Encrypting Alice nonce with Bob public key\n");
		byte[] encryptRA = certEd.CertEncrypt(bob_cert_pub, randomAlice);
		
		try{
		output.Output("Sending encrypted nonce to Bob\n");
		bOOStream.writeObject(encryptRA);
		
		byte[] encrypted_R_A_b = encryptRA;
		bobMessages.addAll(Arrays.asList(ArrayUtils.toObject(encrypted_R_A_b)));
		
		output.Output("Receiving random nonce from Bob\n");
		byte [] encrypted_R_B = (byte[])bOIStream.readObject();  
		byte[] encrypted_R_B_b = encrypted_R_B;
		bobMessages.addAll(Arrays.asList(ArrayUtils.toObject(encrypted_R_B_b)));
		
		output.Output("Decrypting random nonce received from Bob\n");
		randomBob = certEd.CertDecrypt(certEd.getPrivateKey(), encrypted_R_B_b);
		output.Output("Decrypted random nonce from Bob with Alice private key is: " + Long.toString(randomBob)+"\n");
		
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
	private void SendReceiveMAC()
	{
		output.Output("Alice starting to hash messages with SHA1\n");
		ArrayList<Byte> msg_bytes_B= new ArrayList<Byte>(bobMessages);
		byte[] strClient = "Client".getBytes();
		byte [] msg = ArrayUtils.toPrimitive(bobMessages.toArray(new Byte[bobMessages.size()]));
		byte[] aliceMAC = certEd.Hash(msg);
		
		try {
			output.Output("Alice sending hashed MAC message to Bob\n");
			bOOStream.writeObject(aliceMAC);
			
			output.Output("Alice receiving hashed MAC message from Bob\n");
			byte [] bobMAC = (byte[])bOIStream.readObject();  
			
			output.Output("Alice verfiying Bob's hashed MAC");
			byte[] strServer = "Server".getBytes();
			msg_bytes_B.addAll(Arrays.asList(ArrayUtils.toObject(strServer)));
			byte [] msg_B=  ArrayUtils.toPrimitive(msg_bytes_B.toArray(new Byte[msg_bytes_B.size()]));
			//hashing all exchanged messages+"Server" using SHA-1
			byte [] computedBobMac = certEd.Hash(msg_B);
			
			//Verfiy computer MAC and recieved MAC are same
			if(Arrays.equals(bobMAC, computedBobMac))
			{
				output.Output("Alice computed MAC and recieved MAC from Bob match");
			}
			else
			{
				output.Output("The Alice computed MAC and recieved MAC from Bob do not match, handshake failed");
				System.exit(0);
			}
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	private void RSAKeys()
	{
		output.Output("Creating master secret for AES from OR of R alice and R Bob\n");
		master_secret = randomAlice ^ randomBob;
		output.Output("Master Secret to generate AES keys is " + Long.toString(master_secret) + "\n");
		
		AesEd = new AESEncryptDecrypt();
		SecretKey toBob = AesEd.CreateAESKeys("123456", master_secret);
		SecretKey fromBob = AesEd.CreateAESKeys("234567", master_secret);
		SecretKey hashToBob = AesEd.CreateAESKeys("654321", master_secret);
		SecretKey hashFromBob = AesEd.CreateAESKeys("765432", master_secret);
		
		output.Output("Alice generated AES keys for encrypted communication\n");	
	}
}
