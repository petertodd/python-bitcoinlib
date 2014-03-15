# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from __future__ import absolute_import, division, print_function, unicode_literals

import unittest

from bitcoin.core.key import *
from bitcoin.core import x, b2x

class Test_CPubKey(unittest.TestCase):
    def test(self):
        def T(hex_pubkey, is_valid, is_fullyvalid, is_compressed):
            key = CPubKey(x(hex_pubkey))
            self.assertEqual(key.is_valid, is_valid)
            self.assertEqual(key.is_fullyvalid, is_fullyvalid)
            self.assertEqual(key.is_compressed, is_compressed)

        T('', False, False, False)
        T('00', True, True, False) # why is this valid?
        T('01', True, False, False)
        T('02', True, False, False)

        T('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71',
          True, True, True)
        T('0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71',
          True, False, True)

        T('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71',
          True, True, True)

        T('0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455',
          True, True, False)
