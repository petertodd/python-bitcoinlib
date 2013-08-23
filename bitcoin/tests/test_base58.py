# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from __future__ import absolute_import, division, print_function, unicode_literals

import json
import os
import unittest

from binascii import unhexlify

from bitcoin.base58 import *


def load_test_vector(name):
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        for testcase in json.load(fd):
            yield testcase

class Test_base58(unittest.TestCase):
    def test_encode_decode(self):
        for exp_bin, exp_base58 in load_test_vector('base58_encode_decode.json'):
            exp_bin = unhexlify(exp_bin.encode('utf8'))

            act_base58 = encode(exp_bin)
            act_bin = decode(exp_base58)

            self.assertEqual(act_base58, exp_base58)
            self.assertEqual(act_bin, exp_bin)

    def test_invalid_base58_exception(self):
        with self.assertRaises(InvalidBase58Error):
            decode('#')

    # FIXME: need to test CBitcoinAddress
