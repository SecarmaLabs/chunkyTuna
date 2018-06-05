# import logging
# from unittest import mock
import unittest
from chunkytuna import to_chunk


class TestChunks(unittest.TestCase):
    def test_baseline(self):
        what = b"hello"
        c = to_chunk(what)
        self.assertEqual(c, b"""5\r\nhello\r\n""")
