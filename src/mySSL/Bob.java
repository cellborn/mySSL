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
	String encryptType =  "RSA";
	String integType = "SHA1WithRSA";
	CertAndKeyGen keypair;
	int keySize = 1024;
	SecureRandom ranNum = new SecureRandom();
	long randomAlice, randomBob, master_secret;
	AESEncryptDecrypt AesEd;
	
	SecretKey toAlice; 
	SecretKey fromAlice;
	SecretKey hashToAlice; 
	SecretKey hashFromAlice; 
	
	ArrayList<Byte> aliceMessages = new ArrayList<Byte>();
	/**
	 * Constructor used to call all private methods to run program
	 * @param port
	 */
	public Bob(int port)
	{
		output = new Util(filename);
		StartServer(port);
		GetAliceCert();
		GenerateCert(encryptType, integType);
		 SendReceiveRandom();
		 SendReceiveMAC();
		 RSAKeys();
		 SendFile();
	}
	/**
	 * Start the BOb Server and creates all the input and output strem objects for transfering messages over sockets
	 * @param port
	 */
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
	/**
	 * Method to accept Alices request to talk and extracts 
	 * certificate public key and verifies and validates the certificate
	 */
	private void GetAliceCert()
	{
		output.Output("Bob receiving Alice request and getting Alice's certificate and verifying\n");
		
		try {
			int request = (int)aOIStream.readObject();
			String supportCipher = (String)aOIStream.readObject();
			alice_cert = (X509Certificate)aOIStream.readObject();
			output.Output("Recieved Alice request with supported cipher " + supportCipher + " and certificate " + alice_cert.toString()+"\n");
			
			byte[] talk_Req_b =ByteBuffer.allocate(4).putInt(request).array();
			aliceMessages.addAll(Arrays.asList(ArrayUtils.toObject(talk_Req_b)));
			byte[] cipher_supported_b= supportCipher.getBytes();
			aliceMessages.addAll(Arrays.asList(ArrayUtils.toObject(cipher_supported_b)));
			byte[] cert_A_b = alice_cert.getEncoded();
			aliceMessages.addAll(Arrays.asList(ArrayUtils.toObject(cert_A_b)));
			
			output.Output("Verifying Alice's Certificate\n");
			alice_cert.checkValidity();
			alice_cert.verify(alice_cert.getPublicKey());
			output.Output("Alice's certificate valid and verified\n");
			
			alice_cert_pub = alice_cert.getPublicKey();
			output.Output("Got Alices public key from certificate\n" + alice_cert_pub.toString()+"\n");
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}
	/**
	 * Method to generate a certificate with public and private keys for bob to use 
	 * to communication with ALice
	 * @param keyType
	 * @param sigType
	 */
	private void GenerateCert(String keyType, String sigType)
	{
		output.Output("Bob generating certificate\n");
		
		certEd = new CertEncryptDecrypt(keyType, sigType);
		
		keypair = certEd.CreateKeys(keySize);
		
		certEd.CertCreate("bob_cert", "bob_keystore", "123456", keypair);
		
		bob_cert = certEd.getCert("bob_cert");
	
		output.Output("Bob Cert= " + bob_cert.toString() + "\n");
		
		try {
			aOOStream.writeObject(bob_cert);
			System.out.flush();
			output.Output("Bob sending certificate to Alice\n");
			byte[] cert_B_b = bob_cert.getEncoded();
			aliceMessages.addAll(Arrays.asList(ArrayUtils.toObject(cert_B_b)));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	/**
	 * Reads the random nonce and decrypts from alice and then generates a random nonce
	 * and encrypts to send to alice
	 */
	private void SendReceiveRandom()
	{
		output.Output("Receiving encrypted random number nonce from Alice\n");
		
		try
		{
			byte [] encrypted_R_A = (byte[])aOIStream.readObject();
			byte[] encrypted_R_A_b = encrypted_R_A;
			aliceMessages.addAll(Arrays.asList(ArrayUtils.toObject(encrypted_R_A_b)));
			
			randomAlice = certEd.CertDecrypt(certEd.getPrivateKey(), encrypted_R_A);
			output.Output("Bob decrypted Alices random nonce: " + Long.toString(randomAlice)+ "\n");
			
			output.Output("Bob generating random nonce to encrypt with Alice public key\n");
			randomBob = Math.abs(ranNum.nextLong());
			output.Output("Bob random nonce is: " + Long.toString(randomBob) + "\n");
			
			byte [] encrypted_R_B= certEd.CertEncrypt(alice_cert_pub, randomBob);
			aOOStream.writeObject(encrypted_R_B);
			byte[] encrypted_R_B_b = encrypted_R_B;
			aliceMessages.addAll(Arrays.asList(ArrayUtils.toObject(encrypted_R_B_b)));
			output.Output("Bob encrypted and sent random nonce to Alice");
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		
		
	}
	/**
	 * Gets alices MAC and generates a MAC for authentication
	 */
	private void SendReceiveMAC()
	{
		output.Output("Bob starting to hash messages with SHA1\n");
		ArrayList<Byte> msg_bytes_A= new ArrayList<Byte>(aliceMessages);
		byte[] strServer  = "Server".getBytes();
		aliceMessages.addAll(Arrays.asList(ArrayUtils.toObject(strServer)));
		
		byte[] msg = ArrayUtils.toPrimitive(aliceMessages.toArray(new Byte[aliceMessages.size()]));
		byte[] bobMAC = certEd.Hash(msg);
		
		try {
			output.Output("Bob receiving hashed message from Alice\n");
			byte[] aliceMAC = (byte[])aOIStream.readObject();
			
			output.Output("Bob verfiying Alices hashed MAC");
			byte[] strClient = "Client".getBytes();
			msg_bytes_A.addAll(Arrays.asList(ArrayUtils.toObject(strClient)));
			byte [] msg_A=  ArrayUtils.toPrimitive(msg_bytes_A.toArray(new Byte[msg_bytes_A.size()]));
			//hashing all exchanged messages+"Server" using SHA-1
			byte [] computedAliceMac = certEd.Hash(msg_A);
			
			//Verfiy computer MAC and recieved MAC are same
			if(Arrays.equals(aliceMAC, computedAliceMac))
			{
				output.Output("Bob computed MAC and recieved MAC from Alice match");
			}
			else
			{
				output.Output("The Bob computed MAC and recieved MAC from Alice do not match, handshake failed");
				System.exit(0);
			}
			
			aOOStream.writeObject(bobMAC);
			output.Output("Bob sent MAC hash to Alice ");
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	/**
	 * Generates AES keys to be used mistakenly named method RSA 
	 */
	private void RSAKeys()
	{
		output.Output("Creating master secret for AES from OR of R alice and R Bob\n");
		master_secret = randomAlice ^ randomBob;
		output.Output("Master Secret to generate AES keys is " + Long.toString(master_secret) + "\n");
		
		String password = Long.toString(master_secret);
		
		password = password.substring(0, 15);
		
		AesEd = new AESEncryptDecrypt();
		toAlice = AesEd.CreateAESKeys(password, master_secret);
		fromAlice = AesEd.CreateAESKeys(password, master_secret);
		hashToAlice = AesEd.CreateAESKeys(password, master_secret);
		hashFromAlice = AesEd.CreateAESKeys(password, master_secret);
		
		output.Output("Bob generated AES keys for encrypted communication\n");	
	}
	/**
	 * Sends the file to ALice in the SSL format using AES encryption
	 */
	private void SendFile()
	{
		output.Output("==============================================================================\n");
		output.Output("Data Exchange Phase started at Bob ");
		output.Output("==============================================================================\n");


		//Bob reading a file with size > 50Kbytes
		output.Output("Bob dividing the file into chunks and formulating these chunks into SSL blocks ");


		FileInputStream in = null;

		try {
			in = new FileInputStream("2015SecondPA.pdf");

			int seq=0;
			byte[] RH= new byte[8];


			int count=0;
			byte [] tohash=new byte[1036];
			byte[] chunk = new byte[1024];
			int chunkLen = 0;
			while ((chunkLen = in.read(chunk)) != -1) {
				// formulate that chunk into SSL block

				//adding seq to SSL block to be hashed
				byte [] seq_b= ByteBuffer.allocate(4).putInt(seq).array();
				System.arraycopy(seq_b, 0, tohash, 0, seq_b.length);

				//adding RH to SSL block to be hashed
				//add the record type = 1 for data exchange
				RH[0]= 1;

				//add the SSL version = 3 
				RH[1]=3;

				//add the end of file indicator=0 meaning it is not the end of file yet
				RH[2]=0;
				if (chunkLen!=1024)
					//add the end of file indicator=1 meaning it is  the end of file 
					RH[2]=1;

				//add chunk length 
				byte [] chunkLen_b= ByteBuffer.allocate(4).putInt(chunkLen).array();
				System.arraycopy(chunkLen_b, 0, RH, 3, chunkLen_b.length);

				//add the record header length= 8
				RH[7]=8;

				System.arraycopy(RH, 0, tohash, seq_b.length,RH.length );

				//adding data to SSL block to be hashed
				System.arraycopy(chunk, 0, tohash, seq_b.length+RH.length,chunk.length );

				//hashing seq,record header, data
				byte [] HMAC = certEd.Hash(tohash);

				byte[] toencrypt = new byte [chunk.length+HMAC.length];

				//adding data to SSL block to be encrypted
				System.arraycopy(chunk, 0, toencrypt, 0,chunk.length );

				//adding HMAC to SSL block to be encrypted
				System.arraycopy(HMAC, 0, toencrypt, chunk.length,HMAC.length );

				//encrypting data and HMAC
				byte [] encrypted = AesEd.AESEncrypt(toencrypt, toAlice);

				byte [] tosend = new byte [RH.length+encrypted.length];

				//adding RH to SSL block to send
				System.arraycopy(RH, 0, tosend, 0,RH.length );

				//adding encrypted data to SSL block to send
				System.arraycopy(encrypted, 0, tosend, RH.length,encrypted.length );

				//adding HMAC to SSL block to send
				//System.arraycopy(HMAC, 0, tosend, RH.length+encrypted.length, HMAC.length );



				//sending the SSL block to Bob
				aOOStream.writeObject(tosend);

				seq++;

			}
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		finally {
			if (in != null) {
				try{
				in.close();
				}
				catch (Exception e)
				{
					e.printStackTrace();
				}
			}

		}

	}

}
