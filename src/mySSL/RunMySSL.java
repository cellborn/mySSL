package mySSL;

public class RunMySSL {

	public static void main(String[] args) {
		Thread aliceThread = new Thread()
		{
			public void run()
			{
				try
				{
					Alice alice = new Alice(8888);
				}
				catch (Exception e)
				{
					e.printStackTrace();
				}
			}
		};
		aliceThread.start();
	}

}
