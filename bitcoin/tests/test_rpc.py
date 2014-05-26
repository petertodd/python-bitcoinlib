# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from __future__ import absolute_import, division, print_function, unicode_literals

import unittest

from bitcoin.rpc import Proxy

class Test_RPC(unittest.TestCase):
    def test_can_validate(self):
        working_address = '1CB2fxLGAZEzgaY4pjr4ndeDWJiz3D3AT7'
        p = Proxy()
        r = p.validateAddress(working_address)
        self.assertEqual(r['address'], working_address)
        self.assertEqual(r['isvalid'], True)
    
    def test_cannot_validate(self):
        non_working_address = 'LTatMHrYyHcxhxrY27AqFN53bT4TauR86h'
        p = Proxy()
        r = p.validateAddress(non_working_address)
        self.assertEqual(r['isvalid'], False)
