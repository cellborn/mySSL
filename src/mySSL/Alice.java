package mySSL;

import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.SecureRandom;

public class Alice {
	
	String encryptType =  "AES";
	String integType = "SHA1";
	SecureRandom ranNum = new SecureRandom();
	Socket 	bSocket;
	OutputStream bOutStream;
	InputStream bInStream;
	PrintWriter sendBob;
	BufferedReader recieveBob;
	ObjectOutputStream bOOStream;
	ObjectInputStream bOIStream;
	Util output;
	String filename = "alice_output.txt";
	
	
	public Alice(int port)
	{
		OpenSocket(port);
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
			bInStream = new ObjectInputStream(bInStream);
			output = new Util(filename);
			
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	
	
	
	
	

}
