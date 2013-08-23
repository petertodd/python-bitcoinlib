
#
# hash.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from __future__ import absolute_import, division, print_function, unicode_literals

import struct
from bitcoin.serialize import *
from bitcoin.coredefs import *
from bitcoin.script import CScript

def ROTL32(x, r):
    assert x <= 0xFFFFFFFF
    return ((x << r) & 0xFFFFFFFF) | (x >> (32 - r))

def MurmurHash3(nHashSeed, vDataToHash):
    """MurmurHash3 (x86_32)

    Used for bloom filters. See http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp
    """

    assert nHashSeed <= 0xFFFFFFFF

    h1 = nHashSeed
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    # body
    i = 0
    while i < len(vDataToHash) - len(vDataToHash) % 4 \
          and len(vDataToHash) - i >= 4:

        k1 = struct.unpack(b"<L", vDataToHash[i:i+4])[0]

        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ROTL32(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ROTL32(h1, 13)
        h1 = (((h1*5) & 0xFFFFFFFF) + 0xe6546b64) & 0xFFFFFFFF

        i += 4

    # tail
    k1 = 0
    j = (len(vDataToHash) // 4) * 4
    import sys
    bord = ord
    if sys.version > '3':
        # In Py3 indexing bytes returns numbers, not characters
        bord = lambda x: x
    if len(vDataToHash) & 3 >= 3:
        k1 ^= bord(vDataToHash[j+2]) << 16
    if len(vDataToHash) & 3 >= 2:
        k1 ^= bord(vDataToHash[j+1]) << 8
    if len(vDataToHash) & 3 >= 1:
        k1 ^= bord(vDataToHash[j])

    k1 &= 0xFFFFFFFF
    k1 = (k1 * c1) & 0xFFFFFFFF
    k1 = ROTL32(k1, 15)
    k1 = (k1 * c2) & 0xFFFFFFFF
    h1 ^= k1

    # finalization
    h1 ^= len(vDataToHash) & 0xFFFFFFFF
    h1 ^= (h1 & 0xFFFFFFFF) >> 16
    h1 *= 0x85ebca6b
    h1 ^= (h1 & 0xFFFFFFFF) >> 13
    h1 *= 0xc2b2ae35
    h1 ^= (h1 & 0xFFFFFFFF) >> 16

    return h1 & 0xFFFFFFFF
