package mySSL;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;


public class Util {

	File file;
	
	public Util(String filename)
	{
		try {

		      file = new File(filename);
		      if (!file.exists()) {
		        file.createNewFile();
		      }
		}
		      catch (IOException e) {
			      e.printStackTrace();
		      }
	}
	public void Output(String content) {
	    

	      FileWriter fw;
		try {
			fw = new FileWriter(file.getAbsoluteFile(), true);
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(content + "\n\r");
		      bw.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	      System.out.println(content);
	    } 
	}
