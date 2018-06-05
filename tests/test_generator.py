import logging
from unittest import mock
import unittest
import chunkytuna


class TestAsync(unittest.TestCase):
    def setUp(self):
        # chunkytuna.log.setLevel(logging.DEBUG)
        self.mock_socket = mock.Mock()
        # the \n is implied in the carriage return of the string
        # also, sending the full HTTP preamble (async means first
        # message comes back in full)
        self.mock_socket.recv.return_value = b"""
HTTP/1.1 200 OK\r
Cache-Control: private\r
Transfer-Encoding: chunked\r
Content-Type: application/octet-stream\r
Server: Microsoft-IIS/8.5\r
X-AspNet-Version: 4.0.30319\r
X-Powered-By: ASP.NET\r
Date: Mon, 14 May 2018 17:12:37 GMT\r
\r
4\r
Wiki\r
5\r
pedia\r
E\r
 in\r
\r
chunks.\r
0\r
\r\n"""

    def tearDown(self):
        chunkytuna.log.setLevel(logging.INFO)

    def test_baseline(self):
        g = chunkytuna.read_chunks(self.mock_socket, is_async=True)
        keep_running = True
        s = b""
        while keep_running:
            _s = next(g, b'XXX')
            if _s == b'XXX':
                break
            s += _s
        self.assertEqual(s, b"Wikipedia in\r\n\r\nchunks.")


class TestSync(unittest.TestCase):
    def setUp(self):
        # chunkytuna.log.setLevel(logging.DEBUG)
        self.mock_socket = mock.Mock()
        # the \n is implied in the carriage return of the string
        self.mock_socket.recv.return_value = b"""4\r
Wiki\r
5\r
pedia\r
E\r
 in\r
\r
chunks.\r
0\r
\r\n"""

    def tearDown(self):
        chunkytuna.log.setLevel(logging.INFO)

    def test_baseline(self):
        g = chunkytuna.read_chunks(self.mock_socket, is_async=False)
        keep_running = True
        s = bytes()
        while keep_running:
            _s = next(g, b'XXX')
            if _s == b'XXX':
                break
            s += _s
        self.assertEqual(s, b"Wikipedia in\r\n\r\nchunks.")


if __name__ == '__main__':
    unittest.main()
