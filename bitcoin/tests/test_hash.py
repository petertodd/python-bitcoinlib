# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from __future__ import absolute_import, division, print_function, unicode_literals

import json
import os
import unittest

from binascii import unhexlify

from bitcoin.hash import *

class Test_MurmurHash3(unittest.TestCase):
    def test(self):
        def T(expected, seed, data):
            self.assertEqual(MurmurHash3(seed, unhexlify(data)), expected)

        T(0x00000000, 0x00000000, b"");
        T(0x6a396f08, 0xFBA4C795, b"");
        T(0x81f16f39, 0xffffffff, b"");

        T(0x514e28b7, 0x00000000, b"00");
        T(0xea3f0b17, 0xFBA4C795, b"00");
        T(0xfd6cf10d, 0x00000000, b"ff");

        T(0x16c6b7ab, 0x00000000, b"0011");
        T(0x8eb51c3d, 0x00000000, b"001122");
        T(0xb4471bf8, 0x00000000, b"00112233");
        T(0xe2301fa8, 0x00000000, b"0011223344");
        T(0xfc2e4a15, 0x00000000, b"001122334455");
        T(0xb074502c, 0x00000000, b"00112233445566");
        T(0x8034d2a0, 0x00000000, b"0011223344556677");
        T(0xb4698def, 0x00000000, b"001122334455667788");
