
#
# bloom.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from __future__ import absolute_import, division, print_function, unicode_literals

import struct
import math
from bitcoin.serialize import *
from bitcoin.coredefs import *
from bitcoin.core import *
from bitcoin.hash import MurmurHash3

class CBloomFilter(object):
    # 20,000 items with fp rate < 0.1% or 10,000 items and <0.0001%
    MAX_BLOOM_FILTER_SIZE = 36000
    MAX_HASH_FUNCS = 50

    UPDATE_NONE = 0
    UPDATE_ALL = 1
    UPDATE_P2PUBKEY_ONLY = 2
    UPDATE_MASK = 3

    def __init__(self, nElements, nFPRate, nTweak, nFlags):
        """Create a new bloom filter

        The filter will have a given false-positive rate when filled with the
        given number of elements.

        Note that if the given parameters will result in a filter outside the
        bounds of the protocol limits, the filter created will be as close to
        the given parameters as possible within the protocol limits. This will
        apply if nFPRate is very low or nElements is unreasonably high.

        nTweak is a constant which is added to the seed value passed to the
        hash function It should generally always be a random value (and is
        largely only exposed for unit testing)

        nFlags should be one of the UPDATE_* enums (but not _MASK)
        """
        LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455
        LN2 = 0.6931471805599453094172321214581765680755001343602552
        self.vData = bytearray(int(min(-1  / LN2SQUARED * nElements * math.log(nFPRate), self.MAX_BLOOM_FILTER_SIZE * 8) / 8))
        self.nHashFuncs = int(min(len(self.vData) * 8 / nElements * LN2, self.MAX_HASH_FUNCS))
        self.nTweak = nTweak
        self.nFlags = nFlags

    def bloom_hash(self, nHashNum, vDataToHash):
        return MurmurHash3(((nHashNum * 0xFBA4C795) + self.nTweak) & 0xFFFFFFFF, vDataToHash) % (len(self.vData) * 8)

    __bit_mask = bytearray([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80])
    def insert(self, elem):
        """Insert an element in the filter.

        elem may be a COutPoint or bytes
        """
        if isinstance(elem, COutPoint):
            elem = elem.serialize()

        if len(self.vData) == 1 and self.vData[0] == 0xff:
            return

        for i in range(0, self.nHashFuncs):
            nIndex = self.bloom_hash(i, elem)
            # Sets bit nIndex of vData
            self.vData[nIndex >> 3] |= self.__bit_mask[7 & nIndex]

    def contains(self, elem):
        """Test if the filter contains an element

        elem may be a COutPoint or bytes
        """
        if isinstance(elem, COutPoint):
            elem = elem.serialize()

        if len(self.vData) == 1 and self.vData[0] == 0xff:
            return True

        for i in range(0, self.nHashFuncs):
            nIndex = self.bloom_hash(i, elem)
            if not (self.vData[nIndex >> 3] & self.__bit_mask[7 & nIndex]):
                return False
        return True

    def IsWithinSizeConstraints(self):
        return len(self.vData) <= self.MAX_BLOOM_FILTER_SIZE and self.nHashFuncs <= self.MAX_HASH_FUNCS

    def IsRelevantAndUpdate(tx, tx_hash):
        # Not useful for a client, so not implemented yet.
        raise NotImplementedError

    __struct = struct.Struct(b'<IIB')
    def deserialize(self, f):
        self.vData = deser_string(f)
        (self.nHashFuncs,
         self.nTweak,
         self.nFlags) = self.__struct.unpack(f.read(self.__struct.size))

    def serialize(self):
        r = ser_string(self.vData)
        return r + self.__struct.pack(self.nHashFuncs, self.nTweak, self.nFlags)
