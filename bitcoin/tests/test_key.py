# Copyright (C) The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.


import subprocess
import sys
import unittest

from bitcoin.core.key import *
from bitcoin.core import x

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


class Test_OpenSSLLoading(unittest.TestCase):
    def test_missing_library_raises_clear_error(self):
        code = """
import ctypes.util
ctypes.util.find_library = lambda name: None

try:
    import bitcoin.core.key
except EnvironmentError as exc:
    assert str(exc) == (
        "OpenSSL library not found. Install OpenSSL and ensure it is on your "
        "PATH or system library path."
    )
else:
    raise AssertionError("bitcoin.core.key imported without OpenSSL")
"""

        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
