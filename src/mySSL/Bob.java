package mySSL;

import java.io.*;
import java.net.*;
import java.util.*;

import sun.security.provider.*;

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
	
	ArrayList<Byte> messageArray = new ArrayList<Byte>();
	
	public Bob()
	{
		try {
			ServerSocket socket = new ServerSocket(8888);
			SecureRandom rand = new SecureRandom(); 
			
			aliceSocket = socket.accept();
			aOutStream = aliceSocket.getOutputStream();
			aInStream = new DataInputStream(aliceSocket.getInputStream());
			sendAlice = new PrintWriter(aOutStream, true);
			recieveAlice = new BufferedReader(new InputStreamReader(aliceSocket.getInputStream()));

			aOOStream = new ObjectOutputStream(aOutStream);  
			aOIStream= new ObjectInputStream(aInStream);  
			
			Util output = new Util(filename);
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
