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

import unittest

from bitcoin.minikey import *
from bitcoin.wallet import CBitcoinSecret

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
            secret_key = decode_minikey(minikey.encode('ascii'))
            self.assertIsInstance(secret_key, CBitcoinSecret)
            self.assertEqual(str(secret_key), exp_base58_key)

    def test_decode_minikey_str(self):
        for minikey, exp_base58_key in self.valid_minikeys:
            secret_key = decode_minikey(minikey)
            self.assertIsInstance(secret_key, CBitcoinSecret)
            self.assertEqual(str(secret_key), exp_base58_key)

    def test_invalid(self):
        for minikey, msg in self.invalid_minikeys:
            with self.assertRaises(InvalidMinikeyError) as cm:
                decode_minikey(minikey)
            self.assertEqual(str(cm.exception), msg)
