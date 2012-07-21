
#
# ChainDb.py - Bitcoin blockchain database
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import anydbm
from serialize import *

class ChainDb(object):
	def __init__(self, datadir, mempool):
		self.mempool = mempool
		self.misc = anydbm.open(datadir + '/misc.dat', 'c')
		self.blocks = anydbm.open(datadir + '/blocks.dat', 'c')
		self.height = anydbm.open(datadir + '/height.dat', 'c')

		if 'height' not in self.misc:
			self.misc['height'] = str(-1)

	def putblock(self, block):
		block.calc_sha256()
		ser_hash = ser_uint256(block.sha256)

		if not block.is_valid():
			print "Invalid block %064x" % (block.sha256, )
			return False
		if ser_hash in self.blocks:
			print "Duplicate block %064x" % (block.sha256, )
			return False

		print "ChainDb: NEW block %064x" % (block.sha256, )

		neverseen = 0
		for tx in block.vtx:
			if not self.mempool.remove(tx.sha256):
				neverseen += 1

		print "MemPool: blk.vtx.sz %d, neverseen %d, poolsz %d" % (len(block.vtx), neverseen, self.mempool.size())

		self.blocks[ser_hash] = block.serialize()
		return True

	def getheight(self):
		return int(self.misc['height'])

