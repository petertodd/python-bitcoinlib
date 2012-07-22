
#
# ChainDb.py - Bitcoin blockchain database
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import string
import cStringIO
import gdbm
from serialize import *
from datatypes import *
from defs import *

class ChainDb(object):
	def __init__(self, datadir, mempool):
		self.mempool = mempool
		self.orphans = {}
		self.orphan_deps = {}
		self.misc = gdbm.open(datadir + '/misc.dat', 'c')
		self.blocks = gdbm.open(datadir + '/blocks.dat', 'c')
		self.height = gdbm.open(datadir + '/height.dat', 'c')
		self.tx = gdbm.open(datadir + '/tx.dat', 'c')

		if 'height' not in self.misc:
			print "INITIALIZING EMPTY BLOCKCHAIN DATABASE"
			self.misc['height'] = str(-1)
			self.misc['tophash'] = str(0L)

	def is_nextblock(self, block):
		if self.getheight() < 0 and block.sha256 == BLOCK0:
			return True
		if self.gettophash() == block.hashPrevBlock:
			return True
		return False

	def puttxidx(self, block, tx):
		txhash = tx.sha256
		ser_txhash = ser_uint256(txhash)

		if ser_txhash in self.tx:
			l = self.gettxidx(txhash)
			print "WARNING: puttxidx conflict (blk %064x, spent %x)" % (l[0], l[1])

		self.tx[ser_txhash] = hex(block.sha256) + ' 0'

		return True
	
	def gettxidx(self, txhash):
		ser_txhash = ser_uint256(txhash)
		if ser_txhash not in self.tx:
			return None

		ser_value = self.tx[ser_txhash]
		pos = string.find(ser_value, ' ')
		blkhash = long(ser_value[:pos], 16)
		spentmask = long(ser_value[pos+1:], 16)

		return (blkhash, spentmask)

	def gettx(self, txhash):
		l = self.gettxidx(txhash)
		if l is None:
			return None

		block = self.getblock(l[0])
		for tx in block.vtx:
			tx.calc_sha256()
			if tx.sha256 == txhash:
				return tx

		print "ERROR: Missing TX %064x in block %064x" % (txhash, l[0])
		return None

	def getblock(self, blkhash):
		ser_hash = ser_uint256(blkhash)
		if ser_hash not in self.blocks:
			return None

		f = cStringIO.StringIO(self.blocks[ser_hash])
		block = CBlock()
		block.deserialize(f)

		return block

	def putblock(self, block):
		block.calc_sha256()
		ser_hash = ser_uint256(block.sha256)

		if not block.is_valid():
			print "Invalid block %064x" % (block.sha256, )
			return False
		if ser_hash in self.blocks:
			print "Duplicate block %064x" % (block.sha256, )
			return False

		if not self.is_nextblock(block):
			self.orphans[block.sha256] = block
			self.orphan_deps[block.hashPrevBlock] = block
			print "Orphan block %064x (%d orphans)" % (block.sha256, len(self.orphans))
			return False

		neverseen = 0
		for tx in block.vtx:
			if not self.mempool.remove(tx.sha256):
				neverseen += 1

			if not self.puttxidx(block, tx):
				print "TxIndex failed %064x" % (tx.sha256,)
				return False

		print "MemPool: blk.vtx.sz %d, neverseen %d, poolsz %d" % (len(block.vtx), neverseen, self.mempool.size())

		self.blocks[ser_hash] = block.serialize()
		self.misc['height'] = str(self.getheight() + 1)
		self.misc['tophash'] = str(block.sha256)
		self.height[str(self.getheight())] = str(block.sha256)

		print "ChainDb: block %064x, height %d" % (block.sha256, self.getheight())

		return True

	def getheight(self):
		return int(self.misc['height'])
	def gettophash(self):
		return long(self.misc['tophash'])

	def loadfile(self, filename):
		f = open(filename, 'rb', 0)
		print "IMPORTING DATA FROM ", filename
		buf = ''
		wanted = 4096
		while True:
			if wanted > 0:
				if wanted < 4096:
					wanted = 4096
				s = f.read(wanted)
				if len(s) == 0:
					break

				buf += s
				wanted = 0

			buflen = len(buf)
			startpos = string.find(buf, MSG_START)
			if startpos < 0:
				wanted = 8
				continue

			sizepos = startpos + 4
			blkpos = startpos + 8
			if blkpos > buflen:
				wanted = 8
				continue

			blksize = struct.unpack("<i", buf[sizepos:blkpos])[0]
			if (blkpos + blksize) > buflen:
				wanted = 8 + blksize
				continue

			ser_blk = buf[blkpos:blkpos+blksize]
			buf = buf[blkpos+blksize:]

			f = cStringIO.StringIO(ser_blk)
			block = CBlock()
			block.deserialize(f)

			self.putblock(block)

