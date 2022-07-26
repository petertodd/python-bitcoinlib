import unittest

from bitcoin.core.contrib.ripemd160 import ripemd160


class Test_ripemd160(unittest.TestCase):
    def test_ripemd160(self):
        """RIPEMD-160 test vectors."""
        # See https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
        for msg, hexout in [
            (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
            (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
            (b"abcdefghijklmnopqrstuvwxyz",
                "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
            (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "b0e20b6e3116640286ed3a87a5713079b21f5189"),
            (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
            (b"a" * 1000000, "52783243c1697bdbe16d37f97f68f08325dc1528")
        ]:
            self.assertEqual(ripemd160(msg).hex(), hexout)