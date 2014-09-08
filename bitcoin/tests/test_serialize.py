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
import os

from binascii import unhexlify

from bitcoin.core.serialize import *

class Test_Serializable(unittest.TestCase):
    def test_extra_data(self):
        """Serializable.deserialize() fails if extra data is present"""

        class FooSerializable(Serializable):
            @classmethod
            def stream_deserialize(cls, f):
                return cls()

            def stream_serialize(self, f):
                pass

        try:
            FooSerializable.deserialize(b'\x00')
        except DeserializationExtraDataError as err:
            self.assertEqual(err.obj, FooSerializable())
            self.assertEqual(err.padding, b'\x00')

        else:
            self.fail("DeserializationExtraDataError not raised")

        FooSerializable.deserialize(b'\x00', allow_padding=True)

class Test_VarIntSerializer(unittest.TestCase):
    def test(self):
        def T(value, expected):
            expected = unhexlify(expected)
            actual = VarIntSerializer.serialize(value)
            self.assertEqual(actual, expected)
            roundtrip = VarIntSerializer.deserialize(actual)
            self.assertEqual(value, roundtrip)
        T(0x0, b'00')
        T(0xfc, b'fc')
        T(0xfd, b'fdfd00')
        T(0xffff, b'fdffff')
        T(0x10000, b'fe00000100')
        T(0xffffffff, b'feffffffff')
        T(0x100000000, b'ff0000000001000000')
        T(0xffffffffffffffff, b'ffffffffffffffffff')

    def test_non_optimal(self):
        def T(serialized, expected_value):
            serialized = unhexlify(serialized)
            actual_value = VarIntSerializer.deserialize(serialized)
            self.assertEqual(actual_value, expected_value)
        T(b'fd0000', 0)
        T(b'fd3412', 0x1234)
        T(b'fe00000000', 0)
        T(b'fe67452301', 0x1234567)
        T(b'ff0000000000000000', 0)
        T(b'ffefcdab8967452301', 0x123456789abcdef)

    def test_truncated(self):
        def T(serialized):
            serialized = unhexlify(serialized)
            with self.assertRaises(SerializationTruncationError):
                VarIntSerializer.deserialize(serialized)
        T(b'')
        T(b'fd')
        T(b'fd00')
        T(b'fe')
        T(b'fe00')
        T(b'fe0000')
        T(b'fe000000')
        T(b'ff')
        T(b'ff00000000000000')

class Test_BytesSerializer(unittest.TestCase):
    def test(self):
        def T(value, expected):
            value = unhexlify(value)
            expected = unhexlify(expected)
            actual = BytesSerializer.serialize(value)
            self.assertEqual(actual, expected)
            roundtrip = BytesSerializer.deserialize(actual)
            self.assertEqual(value, roundtrip)
        T(b'', b'00')
        T(b'00', b'0100')
        T(b'00'*0xffff, b'fdffff' + b'00'*0xffff)

    def test_truncated(self):
        def T(serialized, ex_cls=SerializationTruncationError):
            serialized = unhexlify(serialized)
            with self.assertRaises(ex_cls):
                BytesSerializer.deserialize(serialized)
        T(b'')
        T(b'01')
        T(b'0200')
        T(b'ff00000000000000ff11223344', SerializationError) # > max_size
