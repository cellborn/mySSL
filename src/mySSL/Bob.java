package mySSL;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.crypto.SecretKey;

import org.apache.commons.lang3.ArrayUtils;

import sun.security.provider.*;
import sun.security.x509.CertAndKeyGen;

public class Bob {
	
	ServerSocket socket;
	Util output;
	Socket aliceSocket;
	
	OutputStream aOutStream;
	InputStream aInStream;
	ObjectOutputStream  aOOStream;
	ObjectInputStream aOIStream;
	
	PrintWriter sendAlice;
	BufferedReader recieveAlice;
	
	String filename = "bob_output.txt";
	
	CertEncryptDecrypt certEd;
	X509Certificate alice_cert;
	X509Certificate bob_cert;
	PublicKey alice_cert_pub;
	String encryptType =  "AES";
	String integType = "SHA1WithRSA";
	CertAndKeyGen keypair;
	int keySize = 1024;
	
	ArrayList<Byte> aliceMessages = new ArrayList<Byte>();
	
	public Bob(int port)
	{
		Util output = new Util(filename);
		StartServer(port);
		GetAliceCert();
		GenerateCert(encryptType, integType);
		
	}
	private void StartServer(int port)
	{
		try {
			ServerSocket socket = new ServerSocket(port);
			SecureRandom rand = new SecureRandom(); 
			
			aliceSocket = socket.accept();
			aOutStream = aliceSocket.getOutputStream();
			aInStream = new DataInputStream(aliceSocket.getInputStream());
			sendAlice = new PrintWriter(aOutStream, true);
			recieveAlice = new BufferedReader(new InputStreamReader(aliceSocket.getInputStream()));

			aOOStream = new ObjectOutputStream(aOutStream);  
			aOIStream= new ObjectInputStream(aInStream);  
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	private void GetAliceCert()
	{
		output.Output("Bob receiving Alice request and getting Alice's certificate and verifying\n");
		
		try {
			int request = (int)aOIStream.readObject();
			String supportCipher = (String)aOIStream.readObject();
			alice_cert = (X509Certificate)aOIStream.readObject();
			output.Output("Recieved Alice request with supported cipher " + supportCipher + " and certificate " + alice_cert.toString()+"\n");
			
			output.Output("Verifying Alice's Certificate\n");
			alice_cert.checkValidity();
			alice_cert.verify(alice_cert.getPublicKey());
			output.Output("Alice's certificate valid and verified\n");
			
			alice_cert_pub = alice_cert.getPublicKey();
			output.Output("Got Alices public key from certificate\n" + alice_cert_pub.toString()+"\n");
			
			byte[] alice_cert_bytes = alice_cert.getEncoded();
			aliceMessages.addAll(Arrays.asList(ArrayUtils.toObject(alice_cert_bytes)));
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}
	private void GenerateCert(String keyType, String sigType)
	{
		certEd = new CertEncryptDecrypt(keyType, sigType);
		
		keypair = certEd.CreateKeys(keySize);
		
		certEd.CertCreate("bob_cert", "bob_keystore", "123456", keypair);
		
		bob_cert = certEd.getCert("bob_cert");
		
		output.Output("Bob generating certificate\n");
		output.Output("Bob Cert= " + bob_cert.toString() + "\n");
		
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
			output.Output("Alice sending hashed message to Bob\n");
			bOOStream.writeObject(aliceMAC);
			
			output.Output("Alice receiving hashed message from Bob\n");
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
