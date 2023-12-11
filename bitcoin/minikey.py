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

"""
Minikey Handling

Minikeys are an old key format, for details see
https://en.bitcoin.it/wiki/Mini_private_key_format.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import sys
_bord = (lambda x: x) if sys.version > '3' else ord

from hashlib import sha256

from bitcoin.wallet import CBitcoinSecret

class InvalidMinikeyError(Exception):
    """Raised for invalid minikeys"""
    pass

def decode_minikey(minikey):
    """Decode minikey from str or bytes to a CBitcoinSecret"""
    if isinstance(minikey, str):
        minikey = minikey.encode('ascii')
    length = len(minikey)
    if length not in [22, 30]:
        raise InvalidMinikeyError('Minikey length %d is not 22 or 30' % length)
    h0 = sha256(minikey)
    h1 = h0.copy()
    h1.update(b'?')
    checksum = _bord(h1.digest()[0])
    if checksum != 0:
        raise InvalidMinikeyError('Minikey checksum %s is not 0' % checksum)
    return CBitcoinSecret.from_secret_bytes(h0.digest(), False)

__all__ = (
        'InvalidMinikeyError',
        'decode_minikey'
)
