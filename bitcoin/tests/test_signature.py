# Copyright (C) The python-bitcoinlib developers
# This file is subject to the license terms in the LICENSE file.

import unittest
from io import BytesIO

from bitcoin.core.key import CECKey
from bitcoin.signature import DERSignature


class Test_DERSignature(unittest.TestCase):
    def test_serialize_known_vectors(self):
        # ECDSA integers can require a leading zero to preserve their sign.
        for r, s in [(b'\x01', b'\x01'),
                     (b'\x7f' * 32, b'\x01'),
                     (b'\x00\x80' + b'\x00' * 31, b'\x7f' * 32),
                     (b'\x00\xff' + b'\x00' * 31,
                      b'\x00\x80' + b'\x00' * 31)]:
            with self.subTest(r=r, s=s):
                body = b'\x02' + bytes([len(r)]) + r
                body += b'\x02' + bytes([len(s)]) + s
                expected = b'\x30' + bytes([len(body)]) + body
                signature = DERSignature.deserialize(expected)
                self.assertEqual(signature.serialize(), expected)
                restored = DERSignature.deserialize(signature.serialize())
                self.assertEqual((restored.r, restored.s), (r, s))

    def test_stream_serialize(self):
        stream = BytesIO()
        signature = DERSignature(b'\x01', b'\x02', 2)
        signature.stream_serialize(stream)
        self.assertEqual(stream.getvalue(), bytes.fromhex('3006020101020102'))

    def test_generated_signatures_verify_after_roundtrip(self):
        key = CECKey()
        key.set_secretbytes(b'\x01' * 32)
        for digest in (b'\x02' * 32, b'\x03' * 32, b'\xff' * 32):
            with self.subTest(digest=digest):
                encoded = key.sign(digest)
                restored = DERSignature.deserialize(encoded).serialize()
                self.assertEqual(restored, encoded)
                self.assertTrue(key.verify(digest, restored))
