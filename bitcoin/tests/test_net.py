# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import unittest

from bitcoin.net import CAddress

class Test_CAddress(unittest.TestCase):
    def test_serialization(self):
        c = CAddress()
        cSerialized = c.serialize()
        cDeserialized = CAddress.deserialize(cSerialized)
        cSerializedTwice = cDeserialized.serialize()
        self.assertEqual(cSerialized, cSerializedTwice)
