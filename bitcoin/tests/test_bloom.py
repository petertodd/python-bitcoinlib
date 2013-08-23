# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from __future__ import absolute_import, division, print_function, unicode_literals

import json
import os
import unittest

from binascii import unhexlify

from bitcoin.bloom import *

class Test_CBloomFilter(unittest.TestCase):
    def test_create_insert_serialize(self):
        filter = CBloomFilter(3, 0.01, 0, CBloomFilter.UPDATE_ALL)

        def T(elem):
            """Filter contains elem"""
            elem = unhexlify(elem)
            filter.insert(elem)
            self.assertTrue(filter.contains(elem))

        def F(elem):
            """Filter does not contain elem"""
            elem = unhexlify(elem)
            self.assertFalse(filter.contains(elem))

        T(b'99108ad8ed9bb6274d3980bab5a85c048f0950c8')
        F(b'19108ad8ed9bb6274d3980bab5a85c048f0950c8')
        T(b'b5a2c786d9ef4658287ced5914b37a1b4aa32eee')
        T(b'b9300670b4c5366e95b2699e8b18bc75e5f729c5')

        self.assertEqual(filter.serialize(), unhexlify(b'03614e9b050000000000000001'))

    def test_create_insert_serialize_with_tweak(self):
        # Same test as bloom_create_insert_serialize, but we add a nTweak of 100
        filter = CBloomFilter(3, 0.01, 2147483649, CBloomFilter.UPDATE_ALL)

        def T(elem):
            """Filter contains elem"""
            elem = unhexlify(elem)
            filter.insert(elem)
            self.assertTrue(filter.contains(elem))

        def F(elem):
            """Filter does not contain elem"""
            elem = unhexlify(elem)
            self.assertFalse(filter.contains(elem))

        T(b'99108ad8ed9bb6274d3980bab5a85c048f0950c8')
        F(b'19108ad8ed9bb6274d3980bab5a85c048f0950c8')
        T(b'b5a2c786d9ef4658287ced5914b37a1b4aa32eee')
        T(b'b9300670b4c5366e95b2699e8b18bc75e5f729c5')

        self.assertEqual(filter.serialize(), unhexlify(b'03ce4299050000000100008001'))

    def test_bloom_create_insert_key(self):
        filter = CBloomFilter(2, 0.001, 0, CBloomFilter.UPDATE_ALL)

        pubkey = unhexlify(b'045B81F0017E2091E2EDCD5EECF10D5BDD120A5514CB3EE65B8447EC18BFC4575C6D5BF415E54E03B1067934A0F0BA76B01C6B9AB227142EE1D543764B69D901E0')
        pubkeyhash = ser_uint160(Hash160(pubkey))

        filter.insert(pubkey)
        filter.insert(pubkeyhash)

        self.assertEqual(filter.serialize(), unhexlify(b'038fc16b080000000000000001'))
