# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from __future__ import absolute_import, division, print_function, unicode_literals

import unittest
import os

from binascii import unhexlify

from bitcoin.core import COutPoint, CTxIn, CTxOut, CTransaction, lx

class Test_COutPoint(unittest.TestCase):
    def test_is_null(self):
        self.assertTrue(COutPoint().is_null())
        self.assertTrue(COutPoint(hash=b'\x00'*32,n=0xffffffff).is_null())
        self.assertFalse(COutPoint(hash=b'\x00'*31 + b'\x01').is_null())
        self.assertFalse(COutPoint(n=1).is_null())

    def test_repr(self):
        def T(outpoint, expected):
            actual = repr(outpoint)
            self.assertEqual(actual, expected)
        T( COutPoint(),
          'COutPoint()')
        T( COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0),
          "COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0)")

class Test_CTxIn(unittest.TestCase):
    def test_is_final(self):
        self.assertTrue(CTxIn().is_final())
        self.assertTrue(CTxIn(nSequence=0xffffffff).is_final())
        self.assertFalse(CTxIn(nSequence=0).is_final())

    def test_repr(self):
        def T(txin, expected):
            actual = repr(txin)
            self.assertEqual(actual, expected)
        T( CTxIn(),
          'CTxIn(COutPoint(), CScript([]), 0xffffffff)')

class Test_CTransaction(unittest.TestCase):
    def test_is_coinbase(self):
        tx = CTransaction()
        self.assertFalse(tx.is_coinbase())

        tx.vin.append(CTxIn())

        # IsCoinBase() in reference client doesn't check if vout is empty
        self.assertTrue(tx.is_coinbase())

        tx.vin[0].prevout.n = 0
        self.assertFalse(tx.is_coinbase())

        tx.vin[0] = CTxIn()
        tx.vin.append(CTxIn())
        self.assertFalse(tx.is_coinbase())
