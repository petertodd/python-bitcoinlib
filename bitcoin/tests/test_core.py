# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from __future__ import absolute_import, division, print_function, unicode_literals

import unittest

from bitcoin.core import *

class Test_str_value(unittest.TestCase):
    def test(self):
        def T(value, expected):
            actual = str_money_value(value)
            self.assertEqual(actual, expected)

        T(         0,  '0.0')
        T(         1,  '0.00000001')
        T(  12345678,  '0.12345678')
        T(        10,  '0.0000001')
        T(  10000000,  '0.1')
        T( 100000000,  '1.0')
        T(1000000000, '10.0')
        T(1010000000, '10.1')
        T(1001000000, '10.01')
        T(1012345678, '10.12345678')
