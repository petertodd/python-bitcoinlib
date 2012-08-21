
#
# coredefs.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

PROTO_VERSION = 60002

CADDR_TIME_VERSION = 31402

MIN_PROTO_VERSION = 209

BIP0031_VERSION = 60000

NOBLKS_VERSION_START = 32000
NOBLKS_VERSION_END = 32400

MEMPOOL_GD_VERSION = 60002

COIN = 100000000

class NetMagic(object):
	def __init__(self, msg_start, block0):
		self.msg_start = msg_start
		self.block0 = block0

NETWORKS = {
 'mainnet' : NetMagic("\xf9\xbe\xb4\xd9",
	0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26fL),
 'testnet3' : NetMagic("\x0b\x11\x09\x07",
        0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943L)
}

