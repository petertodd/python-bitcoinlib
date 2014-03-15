# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from __future__ import absolute_import, division, print_function, unicode_literals

import unittest

from bitcoin.core import b2x, x
from bitcoin.core.script import CScript
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


    def test_from_scriptPubKey(self):
        def T(hex_scriptpubkey, expected_str_address):
            scriptPubKey = CScript(x(hex_scriptpubkey))
            self.assertEqual(str(CBitcoinAddress.from_scriptPubKey(scriptPubKey)),
                             expected_str_address)

        T('a914000000000000000000000000000000000000000087', '31h1vYVSYuKP6AhS86fbRdMw9XHieotbST')
        T('76a914000000000000000000000000000000000000000088ac', '1111111111111111111114oLvT2')

        # Missing a byte
        scriptPubKey = CScript(x('76a914000000000000000000000000000000000000000088'))
        with self.assertRaises(ValueError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # One extra byte
        scriptPubKey = CScript(x('76a914000000000000000000000000000000000000000088acac'))
        with self.assertRaises(ValueError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # One byte changed
        scriptPubKey = CScript(x('76a914000000000000000000000000000000000000000088ad'))
        with self.assertRaises(ValueError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)


class Test_CBitcoinSecret(unittest.TestCase):
    def test(self):
        def T(base58_privkey, expected_hex_pubkey, expected_is_compressed_value):
            key = CBitcoinSecret(base58_privkey)
            self.assertEqual(b2x(key.pub), expected_hex_pubkey)
            self.assertEqual(key.is_compressed, expected_is_compressed_value)

        T('5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS',
          '0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455',
          False)
        T('L3p8oAcQTtuokSCRHQ7i4MhjWc9zornvpJLfmg62sYpLRJF9woSu',
          '0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71',
          True)

    def test_sign(self):
        key = CBitcoinSecret('5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS')
        hash = b'\x00' * 32
        sig = key.sign(hash)

        # FIXME: need better tests than this
        self.assertTrue(key.pub.verify(hash, sig))
        self.assertFalse(key.pub.verify(b'\xFF'*32, sig))
        self.assertFalse(key.pub.verify(hash, sig[0:-1] + b'\x00'))
