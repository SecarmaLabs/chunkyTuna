import logging
import unittest
from chunkytuna import split_headers, log, bake_cookies


class TestCookie(unittest.TestCase):
    def setUp(self):
        # log.setLevel(logging.DEBUG)
        # the \n is implied in the carriage return of the string
        # also, sending the full HTTP preamble (async means first
        # message comes back in full)
        self.expected_body = b"""4\r
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
        log.setLevel(logging.INFO)

    def test_baseline(self):
        resp = b"""HTTP/1.1 200 OK\r
Cache-Control: private\r
Transfer-Encoding: chunked\r
Content-Type: application/octet-stream\r
Server: Microsoft-IIS/8.5\r
X-AspNet-Version: 4.0.30319\r
Set-Cookie: ASP.NET_SessionId=2ydy2bqgzqutn1dq1fawqfni; path=/; HttpOnly\r
X-Powered-By: ASP.NET\r
Date: Mon, 14 May 2018 17:12:37 GMT\r
\r\n""" + self.expected_body
        headers, body, cookies = split_headers(resp)
        expected_headers = b"""HTTP/1.1 200 OK\r
Cache-Control: private\r
Transfer-Encoding: chunked\r
Content-Type: application/octet-stream\r
Server: Microsoft-IIS/8.5\r
X-AspNet-Version: 4.0.30319\r
Set-Cookie: ASP.NET_SessionId=2ydy2bqgzqutn1dq1fawqfni; path=/; HttpOnly\r
X-Powered-By: ASP.NET\r
Date: Mon, 14 May 2018 17:12:37 GMT"""
        expected_cookies = [b"ASP.NET_SessionId=2ydy2bqgzqutn1dq1fawqfni"]
        self.assertEqual(headers, expected_headers)
        self.assertEqual(body, self.expected_body)
        self.assertEqual(cookies, expected_cookies)

    def test_many_cookies(self):
        resp = b"""HTTP/1.1 200 OK\r
Cache-Control: private\r
Transfer-Encoding: chunked\r
Content-Type: application/octet-stream\r
Server: Microsoft-IIS/8.5\r
X-AspNet-Version: 4.0.30319\r
Set-Cookie: ASP.NET_SessionId=2ydy2bqgzqutn1dq1fawqfni; path=/; HttpOnly\r
Set-Cookie: foo=bar; path=/; HttpOnly\r
X-Powered-By: ASP.NET\r
Date: Mon, 14 May 2018 17:12:37 GMT\r
\r\n""" + self.expected_body
        headers, body, cookies = split_headers(resp)
        expected_headers = b"""HTTP/1.1 200 OK\r
Cache-Control: private\r
Transfer-Encoding: chunked\r
Content-Type: application/octet-stream\r
Server: Microsoft-IIS/8.5\r
X-AspNet-Version: 4.0.30319\r
Set-Cookie: ASP.NET_SessionId=2ydy2bqgzqutn1dq1fawqfni; path=/; HttpOnly\r
Set-Cookie: foo=bar; path=/; HttpOnly\r
X-Powered-By: ASP.NET\r
Date: Mon, 14 May 2018 17:12:37 GMT"""
        expected_cookies = [
            b"ASP.NET_SessionId=2ydy2bqgzqutn1dq1fawqfni",
            b"foo=bar"
        ]
        self.assertEqual(headers, expected_headers)
        self.assertEqual(body, self.expected_body)
        self.assertEqual(cookies, expected_cookies)

    def test_many_cookies_no_secure(self):
        resp = b"""HTTP/1.1 200 OK\r
Cache-Control: private\r
Transfer-Encoding: chunked\r
Content-Type: application/octet-stream\r
Server: Microsoft-IIS/8.5\r
X-AspNet-Version: 4.0.30319\r
Set-Cookie: ASP.NET_SessionId=2ydy2bqgzqutn1dq1fawqfni; path=/; HttpOnly\r
Set-Cookie: foo=bar\r
X-Powered-By: ASP.NET\r
Date: Mon, 14 May 2018 17:12:37 GMT\r
\r\n""" + self.expected_body
        headers, body, cookies = split_headers(resp)
        expected_headers = b"""HTTP/1.1 200 OK\r
Cache-Control: private\r
Transfer-Encoding: chunked\r
Content-Type: application/octet-stream\r
Server: Microsoft-IIS/8.5\r
X-AspNet-Version: 4.0.30319\r
Set-Cookie: ASP.NET_SessionId=2ydy2bqgzqutn1dq1fawqfni; path=/; HttpOnly\r
Set-Cookie: foo=bar\r
X-Powered-By: ASP.NET\r
Date: Mon, 14 May 2018 17:12:37 GMT"""
        expected_cookies = [
            b"ASP.NET_SessionId=2ydy2bqgzqutn1dq1fawqfni",
            b"foo=bar"
        ]
        self.assertEqual(headers, expected_headers)
        self.assertEqual(body, self.expected_body)
        self.assertEqual(cookies, expected_cookies)

    def test_no_cookie(self):
        resp = b"""HTTP/1.1 200 OK\r
Cache-Control: private\r
Transfer-Encoding: chunked\r
Content-Type: application/octet-stream\r
Server: Microsoft-IIS/8.5\r
X-AspNet-Version: 4.0.30319\r
X-Powered-By: ASP.NET\r
Date: Mon, 14 May 2018 17:12:37 GMT\r
\r\n""" + self.expected_body
        headers, body, cookies = split_headers(resp)
        expected_headers = b"""HTTP/1.1 200 OK\r
Cache-Control: private\r
Transfer-Encoding: chunked\r
Content-Type: application/octet-stream\r
Server: Microsoft-IIS/8.5\r
X-AspNet-Version: 4.0.30319\r
X-Powered-By: ASP.NET\r
Date: Mon, 14 May 2018 17:12:37 GMT"""
        expected_cookies = []
        self.assertEqual(headers, expected_headers)
        self.assertEqual(body, self.expected_body)
        self.assertEqual(cookies, expected_cookies)


class TestCookieBaking(unittest.TestCase):
    def test_baseline(self):
        cookies = [b"foo=bar", b"baz=1"]
        baked = bake_cookies(cookies)
        self.assertEqual(baked, b"Cookie: foo=bar; baz=1\r\n")
