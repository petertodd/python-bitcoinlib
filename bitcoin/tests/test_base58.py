# Copyright (C) 2013-2014 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from __future__ import absolute_import, division, print_function, unicode_literals

import json
import os
import unittest

from binascii import unhexlify

from bitcoin.base58 import *


def load_test_vectors(name):
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        for testcase in json.load(fd):
            yield testcase

class Test_base58(unittest.TestCase):
    def test_encode_decode(self):
        for exp_bin, exp_base58 in load_test_vectors('base58_encode_decode.json'):
            exp_bin = unhexlify(exp_bin.encode('utf8'))

            act_base58 = encode(exp_bin)
            act_bin = decode(exp_base58)

            self.assertEqual(act_base58, exp_base58)
            self.assertEqual(act_bin, exp_bin)

class Test_minikey(unittest.TestCase):

    valid_minikeys = [
        ('S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy', '5JPy8Zg7z4P7RSLsiqcqyeAF1935zjNUdMxcDeVrtU1oarrgnB7'),
        ('SVY4eSFCF4tMtMohEkpXkoN9FHxDV7', '5JSyovgwfVcuFZBAp8LAta2tMsmscxXv3FvzvJWeKBfycLAmjuZ'),
        ('S6c56bnXQiBjk9mqSYEa30', '5KM4V1haDBMEcgzPuAWdHSBAVAEJNp4he2meirV3JNvZz9aWBNH')
    ]
    invalid_minikeys = [
        ('', 'Minikey length 0 is not 22 or 30'),
        ('S6c56bnXQiBjk9mqSYE7ykVQ7NzrR', 'Minikey length 29 is not 22 or 30'),
        ('S6c56bnXQiBjk9mqSYE7ykVQ7NzrRyz', 'Minikey length 31 is not 22 or 30'),
        ('S6c56bnXQiBjk9mqSYE7ykVQ7NzrRz', 'Minikey checksum 213 is not 0'),
        ('S6c56bnXQiBjk9mqSYE7yk', 'Minikey checksum 46 is not 0')
    ]

    def test_decode_minikey_bytes(self):
        for minikey, exp_base58_key in self.valid_minikeys:
            base58_key2 = decode_minikey(minikey.encode('ascii'))
            self.assertEqual(base58_key2, exp_base58_key)

    def test_decode_minikey_str(self):
        for minikey, exp_base58_key in self.valid_minikeys:
            base58_key = decode_minikey(minikey)
            self.assertEqual(base58_key, exp_base58_key)

    def test_invalid(self):
        for minikey, msg in self.invalid_minikeys:
            with self.assertRaises(InvalidMinikeyError) as cm:
                decode_minikey(minikey)
            self.assertEqual(str(cm.exception), msg)

class Test_CBase58Data(unittest.TestCase):
    def test_from_data(self):
        b = CBase58Data.from_bytes(b"b\xe9\x07\xb1\\\xbf'\xd5BS\x99\xeb\xf6\xf0\xfbP\xeb\xb8\x8f\x18", 0)
        self.assertEqual(b.nVersion, 0)
        self.assertEqual(str(b), '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')

        b = CBase58Data.from_bytes(b'Bf\xfco,(a\xd7\xfe"\x9b\'\x9ay\x80:\xfc\xa7\xba4', 196)
        self.assertEqual(b.nVersion, 196)
        self.assertEqual(str(b), '2MyJKxYR2zNZZsZ39SgkCXWCfQtXKhnWSWq')

    def test_invalid_base58_exception(self):
        invalids = ('', # missing everything
                    '#', # invalid character
                    '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb', # invalid checksum
                    )

        for invalid in invalids:
            msg = '%r should have raised InvalidBase58Error but did not' % invalid
            with self.assertRaises(Base58Error, msg=msg):
                CBase58Data(invalid)
