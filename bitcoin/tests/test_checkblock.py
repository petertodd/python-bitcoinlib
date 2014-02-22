# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from __future__ import absolute_import, division, print_function, unicode_literals

import json
import unittest
import os

from bitcoin.core import *

def load_test_vectors(name):
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        for test_case in json.load(fd):
            # Comments designated by single length strings
            if len(test_case) == 1:
                continue
            assert len(test_case) == 5

            (comment, fHeader, fCheckPoW, cur_time, serialized_blk) = test_case

            blk = None
            if fHeader:
                blk = CBlockHeader.deserialize(x(serialized_blk))
            else:
                blk = CBlock.deserialize(x(serialized_blk))

            yield (comment, fHeader, fCheckPoW, cur_time, blk)


class Test_CheckBlock(unittest.TestCase):
    def test_checkblock_valid(self):
        for comment, fHeader, fCheckPoW, cur_time, blk in load_test_vectors('checkblock_valid.json'):
            try:
                if fHeader:
                    CheckBlockHeader(blk, fCheckPoW=fCheckPoW, cur_time=cur_time)
                else:
                    CheckBlock(blk, fCheckPoW=fCheckPoW, cur_time=cur_time)
            except ValidationError as err:
                self.fail('Failed "%s" with error %r' % (comment, err))

    def test_checkblock_invalid(self):
        for comment, fHeader, fCheckPoW, cur_time, blk in load_test_vectors('checkblock_invalid.json'):
            try:
                if fHeader:
                    CheckBlockHeader(blk, fCheckPoW=fCheckPoW, cur_time=cur_time)
                else:
                    CheckBlock(blk, fCheckPoW=fCheckPoW, cur_time=cur_time)
            except ValidationError as err:
                continue

            self.fail('Invalid block "%s" passed checks' % comment)
