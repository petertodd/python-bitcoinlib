# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from __future__ import absolute_import, division, print_function, unicode_literals

import unittest

from bitcoin.wallet import *

class Test_CBitcoinAddress(unittest.TestCase):
    def test(self):
        a = CBitcoinAddress('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
        self.assertEqual(a.to_bytes(), b"b\xe9\x07\xb1\\\xbf'\xd5BS\x99\xeb\xf6\xf0\xfbP\xeb\xb8\x8f\x18")
        self.assertEqual(a.nVersion, 0)

        a = CBitcoinAddress('mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt')
        self.assertEqual(a.to_bytes(), b"b\xe9\x07\xb1\\\xbf'\xd5BS\x99\xeb\xf6\xf0\xfbP\xeb\xb8\x8f\x18")
        self.assertEqual(a.nVersion, 111)

        a = CBitcoinAddress('37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP')
        self.assertEqual(a.to_bytes(), b'Bf\xfco,(a\xd7\xfe"\x9b\'\x9ay\x80:\xfc\xa7\xba4')
        self.assertEqual(a.nVersion, 5)

        a = CBitcoinAddress('2MyJKxYR2zNZZsZ39SgkCXWCfQtXKhnWSWq')
        self.assertEqual(a.to_bytes(), b'Bf\xfco,(a\xd7\xfe"\x9b\'\x9ay\x80:\xfc\xa7\xba4')
        self.assertEqual(a.nVersion, 196)
