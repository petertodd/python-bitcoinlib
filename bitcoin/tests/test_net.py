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

from bitcoin.net import CAddress

class Test_CAddress(unittest.TestCase):
    def test_serialization(self):
        c = CAddress()
        cSerialized = c.serialize()
        cDeserialized = CAddress.deserialize(cSerialized)
        cSerializedTwice = cDeserialized.serialize()
        self.assertEqual(cSerialized, cSerializedTwice)
