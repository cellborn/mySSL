package mySSL;

public class RunMySSL {

	public static void main(String[] args) {
		
		Thread bobThread = new Thread()
		{
			public void run()
			{
				try
				{
					Bob bob = new Bob();
				}
				catch (Exception e)
				{
					e.printStackTrace();
				}
			}
		};
		
		
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
		bobThread.start();

		try {
			Thread.sleep(010000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		
		aliceThread.start();
	}

}
