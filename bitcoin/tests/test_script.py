# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from __future__ import absolute_import, division, print_function, unicode_literals

import unittest
import os

from binascii import unhexlify

from bitcoin.core import b2x,x
from bitcoin.core.script import *

class Test_CScriptOp(unittest.TestCase):
    def test_pushdata(self):
        def T(data, expected):
            data = unhexlify(data)
            expected = unhexlify(expected)
            serialized_data = CScriptOp.encode_op_pushdata(data)
            self.assertEqual(serialized_data, expected)

        T(b'', b'00')
        T(b'00', b'0100')
        T(b'0011223344556677', b'080011223344556677')
        T(b'ff'*0x4b, b'4b' + b'ff'*0x4b)
        T(b'ff'*0x4c, b'4c4c' + b'ff'*0x4c)
        T(b'ff'*0x4c, b'4c4c' + b'ff'*0x4c)
        T(b'ff'*0xff, b'4cff' + b'ff'*0xff)
        T(b'ff'*0x100, b'4d0001' + b'ff'*0x100)
        T(b'ff'*0xffff, b'4dffff' + b'ff'*0xffff)
        T(b'ff'*0x10000, b'4e00000100' + b'ff'*0x10000)

    def test_is_singleton(self):
        self.assertTrue(OP_0 is CScriptOp(0x00))
        self.assertTrue(OP_1 is CScriptOp(0x51))
        self.assertTrue(OP_16 is CScriptOp(0x60))
        self.assertTrue(OP_CHECKSIG is CScriptOp(0xac))

        for i in range(0x0, 0x100):
            self.assertTrue(CScriptOp(i) is CScriptOp(i))

    def test_encode_decode_op_n(self):
        def t(n, op):
            actual = CScriptOp.encode_op_n(n)
            self.assertEqual(actual, op)
            self.assertTrue(isinstance(actual, CScriptOp))

            actual = op.decode_op_n()
            self.assertEqual(actual, n)
            self.assertTrue(isinstance(actual, int))

        t(0, OP_0)
        t(1, OP_1)
        t(2, OP_2)
        t(3, OP_3)
        t(4, OP_4)
        t(5, OP_5)
        t(6, OP_6)
        t(7, OP_7)
        t(8, OP_8)
        t(9, OP_9)
        t(9, OP_9)
        t(10, OP_10)
        t(11, OP_11)
        t(12, OP_12)
        t(13, OP_13)
        t(14, OP_14)
        t(15, OP_15)
        t(16, OP_16)

        with self.assertRaises(ValueError):
            OP_CHECKSIG.decode_op_n()

        with self.assertRaises(ValueError):
            CScriptOp(1).decode_op_n()

class Test_CScript(unittest.TestCase):
    def test_tokenize_roundtrip(self):
        def T(serialized_script, expected_tokens, test_roundtrip=True):
            serialized_script = unhexlify(serialized_script)
            script_obj = CScript(serialized_script)
            actual_tokens = list(script_obj)
            self.assertEqual(actual_tokens, expected_tokens)

            if test_roundtrip:
                recreated_script = CScript(actual_tokens)
                self.assertEqual(recreated_script, serialized_script)

        T(b'', [])

        # standard pushdata
        T(b'00', [b''])
        T(b'0100', [b'\x00'])
        T(b'4b' + b'ff'*0x4b, [b'\xff'*0x4b])

        # non-optimal pushdata
        T(b'4c00', [b''], False)
        T(b'4c04deadbeef', [unhexlify(b'deadbeef')], False)
        T(b'4d0000', [b''], False)
        T(b'4d0400deadbeef', [unhexlify(b'deadbeef')], False)
        T(b'4e00000000', [b''], False)
        T(b'4e04000000deadbeef', [unhexlify(b'deadbeef')], False)

        # numbers
        T(b'4f', [OP_1NEGATE])
        T(b'51', [0x1])
        T(b'52', [0x2])
        T(b'53', [0x3])
        T(b'54', [0x4])
        T(b'55', [0x5])
        T(b'56', [0x6])
        T(b'57', [0x7])
        T(b'58', [0x8])
        T(b'59', [0x9])
        T(b'5a', [0xa])
        T(b'5b', [0xb])
        T(b'5c', [0xc])
        T(b'5d', [0xd])
        T(b'5e', [0xe])
        T(b'5f', [0xf])

        # some opcodes
        T(b'9b', [OP_BOOLOR])
        T(b'9a9b', [OP_BOOLAND, OP_BOOLOR])
        T(b'ff', [OP_INVALIDOPCODE])
        T(b'fafbfcfd', [CScriptOp(0xfa), CScriptOp(0xfb), CScriptOp(0xfc), CScriptOp(0xfd)])

        # all three types
        T(b'512103e2a0e6a91fa985ce4dda7f048fca5ec8264292aed9290594321aa53d37fdea32410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc345552ae',
          [1,
           unhexlify(b'03e2a0e6a91fa985ce4dda7f048fca5ec8264292aed9290594321aa53d37fdea32'),
           unhexlify(b'0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455'),
           2,
           OP_CHECKMULTISIG])

    def test_invalid_scripts(self):
        def T(serialized):
            with self.assertRaises(CScriptInvalidError):
                list(CScript(unhexlify(serialized)))

        T(b'01')
        T(b'02')
        T(b'0201')
        T(b'4b')
        T(b'4b' + b'ff'*0x4a)
        T(b'4c')
        T(b'4cff' + b'ff'*0xfe)
        T(b'4d')
        T(b'4dff')
        T(b'4dffff' + b'ff'*0xfffe)
        T(b'4e')
        T(b'4effffff')
        T(b'4effffffff' + b'ff'*0xfffe) # not going to test with 4GiB-1...

    def test_equality(self):
        # Equality is on the serialized script, not the logical meaning.
        # This is important for P2SH.
        def T(serialized1, serialized2, are_equal):
            script1 = CScript(unhexlify(serialized1))
            script2 = CScript(unhexlify(serialized2))
            if are_equal:
                self.assertEqual(script1, script2)
            else:
                self.assertNotEqual(script1, script2)

        T(b'', b'', True)
        T(b'', b'00', False)
        T(b'00', b'00', True)
        T(b'00', b'01', False)
        T(b'01ff', b'01ff', True)
        T(b'fc01ff', b'01ff', False)

        # testing equality on an invalid script is legal, and evaluates based
        # on the serialization
        T(b'4e', b'4e', True)
        T(b'4e', b'4e00', False)

    def test_add(self):
        script = CScript()
        script2 = script + 1

        # + operator must create a new instance
        self.assertIsNot(script, script2)

        script = script2
        self.assertEqual(script, b'\x51')

        script += 2
        # += should not be done in place
        self.assertIsNot(script, script2)
        self.assertEqual(script, b'\x51\x52')

        script += OP_CHECKSIG
        self.assertEqual(script, b'\x51\x52\xac')

        script += b'deadbeef'
        self.assertEqual(script, b'\x51\x52\xac\x08deadbeef')

        script = CScript() + 1 + 2 + OP_CHECKSIG + b'deadbeef'
        self.assertEqual(script, b'\x51\x52\xac\x08deadbeef')

        # big number
        script = CScript() + 2**64
        self.assertEqual(script, b'\x09\x00\x00\x00\x00\x00\x00\x00\x00\x01')

        # some stuff we can't add
        with self.assertRaises(TypeError):
            script += None
        self.assertEqual(script, b'\x09\x00\x00\x00\x00\x00\x00\x00\x00\x01')

        with self.assertRaises(TypeError):
            script += [1, 2, 3]
        self.assertEqual(script, b'\x09\x00\x00\x00\x00\x00\x00\x00\x00\x01')

        with self.assertRaises(TypeError):
            script = script + None
        self.assertEqual(script, b'\x09\x00\x00\x00\x00\x00\x00\x00\x00\x01')

    def test_repr(self):
        def T(script, expected_repr):
            actual_repr = repr(script)
            self.assertEqual(actual_repr, expected_repr)

        T( CScript([]),
          'CScript([])')

        T( CScript([1]),
          'CScript([1])')

        T( CScript([1, 2, 3]),
          'CScript([1, 2, 3])')

        T( CScript([1, x('7ac977d8373df875eceda362298e5d09d4b72b53'), OP_DROP]),
          "CScript([1, x('7ac977d8373df875eceda362298e5d09d4b72b53'), OP_DROP])")

        T(CScript(unhexlify(b'0001ff515261ff')),
          "CScript([x(''), x('ff'), 1, 2, OP_NOP, OP_INVALIDOPCODE])")

        # truncated scripts
        T(CScript(unhexlify(b'6101')),
          "CScript([OP_NOP, x('')...<ERROR: PUSHDATA(1): truncated data>])")

        T(CScript(unhexlify(b'614bff')),
          "CScript([OP_NOP, x('ff')...<ERROR: PUSHDATA(75): truncated data>])")

        T(CScript(unhexlify(b'614c')),
          "CScript([OP_NOP, <ERROR: PUSHDATA1: missing data length>])")

        T(CScript(unhexlify(b'614c0200')),
          "CScript([OP_NOP, x('00')...<ERROR: PUSHDATA1: truncated data>])")

    def test_is_p2sh(self):
        def T(serialized, b):
            script = CScript(unhexlify(serialized))
            self.assertEqual(script.is_p2sh(), b)

        # standard P2SH
        T(b'a9146567e91196c49e1dffd09d5759f6bbc0c6d4c2e587', True)

        # NOT a P2SH txout due to the non-optimal PUSHDATA encoding
        T(b'a94c146567e91196c49e1dffd09d5759f6bbc0c6d4c2e587', False)

    def test_is_push_only(self):
        def T(serialized, b):
            script = CScript(unhexlify(serialized))
            self.assertEqual(script.is_push_only(), b)

        T(b'', True)
        T(b'00', True)
        T(b'0101', True)
        T(b'4c00', True)
        T(b'4d0000', True)
        T(b'4e00000000', True)
        T(b'4f', True)

        # OP_RESERVED *is* considered to be a pushdata op by is_push_only!
        # Or specifically, the IsPushOnly() used in P2SH validation.
        T(b'50', True)

        T(b'51', True)
        T(b'52', True)
        T(b'53', True)
        T(b'54', True)
        T(b'55', True)
        T(b'56', True)
        T(b'57', True)
        T(b'58', True)
        T(b'59', True)
        T(b'5a', True)
        T(b'5b', True)
        T(b'5c', True)
        T(b'5d', True)
        T(b'5e', True)
        T(b'5f', True)
        T(b'60', True)

        T(b'61', False)

    def test_is_unspendable(self):
        def T(serialized, b):
            script = CScript(unhexlify(serialized))
            self.assertEqual(script.is_unspendable(), b)

        T(b'', False)
        T(b'00', False)
        T(b'006a', False)
        T(b'6a', True)
        T(b'6a6a', True)
        T(b'6a51', True)

    def test_is_valid(self):
        def T(serialized, b):
            script = CScript(unhexlify(serialized))
            self.assertEqual(script.is_valid(), b)

        T(b'', True)
        T(b'00', True)
        T(b'01', False)

        # invalid opcodes do not by themselves make a script invalid
        T(b'ff', True)

    def test_to_p2sh_scriptPubKey(self):
        def T(redeemScript, expected_hex_bytes):
            redeemScript = CScript(redeemScript)
            actual_script = redeemScript.to_p2sh_scriptPubKey()
            self.assertEqual(b2x(actual_script), expected_hex_bytes)

        T([],
          'a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87')

        T([1,x('029b6d2c97b8b7c718c325d7be3ac30f7c9d67651bce0c929f55ee77ce58efcf84'),1,OP_CHECKMULTISIG],
          'a91419a7d869032368fd1f1e26e5e73a4ad0e474960e87')

        T([b'\xff'*517],
          'a9140da7fa40ebf248dfbca363c79921bdd665fed5ba87')

        with self.assertRaises(ValueError):
            CScript([b'a' * 518]).to_p2sh_scriptPubKey()
