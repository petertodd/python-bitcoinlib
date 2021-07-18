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

import unittest
import bitcoin

from bitcoin.messages import msg_addr

class Test_params(unittest.TestCase):
    def tearDown(self):
        bitcoin.SelectParams('mainnet')

    def test_mainnet_magic_byte(self):
        bitcoin.SelectParams('mainnet')
        self.assertEquals(bitcoin.MainParams().MESSAGE_START, msg_addr().to_bytes()[0:4])

    def test_testnet_magic_byte(self):
        bitcoin.SelectParams('testnet')
        self.assertEquals(bitcoin.TestNetParams().MESSAGE_START, msg_addr().to_bytes()[0:4])

    def test_mainnet_params_magic_byte(self):
        bitcoin.SelectParams('testnet')
        self.assertEquals(bitcoin.MainParams().MESSAGE_START, msg_addr().to_bytes(params=bitcoin.MainParams())[0:4])

    def test_testnet_params_magic_byte(self):
        bitcoin.SelectParams('mainnet')
        self.assertEquals(bitcoin.TestNetParams().MESSAGE_START, msg_addr().to_bytes(params=bitcoin.TestNetParams())[0:4])
