
#
# coredefs.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from __future__ import absolute_import, division, print_function, unicode_literals

PROTO_VERSION = 60002

CADDR_TIME_VERSION = 31402

MIN_PROTO_VERSION = 209

BIP0031_VERSION = 60000

NOBLKS_VERSION_START = 32000
NOBLKS_VERSION_END = 32400

MEMPOOL_GD_VERSION = 60002

COIN = 100000000
MAX_MONEY = 21000000 * COIN

def MoneyRange(nValue):
    return 0<= nValue <= MAX_MONEY

class NetMagic(object):
    def __init__(self, msg_start, block0, checkpoints):
        self.msg_start = msg_start
        self.block0 = block0
        self.checkpoints = checkpoints

        self.checkpoint_max = 0
        for height in self.checkpoints.keys():
            if height > self.checkpoint_max:
                self.checkpoint_max = height

NETWORKS = {
 'mainnet' : NetMagic(b"\xf9\xbe\xb4\xd9",
    0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f,
    {
     0: 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f,
         11111: 0x0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d,
         33333: 0x000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6,
         74000: 0x0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20,
        105000: 0x00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97,
        134444: 0x00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe,
        168000: 0x000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763,
        193000: 0x000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317,
    210000: 0x000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e,
    216116: 0x00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e,
    }),
 'testnet3' : NetMagic(b"\x0b\x11\x09\x07",
        0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943,
    {
     0: 0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943,
    })
}

