
#
# ChainDb.py - Bitcoin blockchain database
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import string
import cStringIO
import gdbm
import os
from bitcoin.serialize import *
from bitcoin.core import *

class TxIdx(object):
	def __init__(self, blkhash=0L, spentmask=0L):
		self.blkhash = blkhash
		self.spentmask = spentmask

class ChainDb(object):
	def __init__(self, datadir, log, mempool, netmagic):
		self.log = log
		self.mempool = mempool
		self.netmagic = netmagic
		self.orphan_deps = {}
		self.misc = gdbm.open(datadir + '/misc.dat', 'c')
		self.blocks = gdbm.open(datadir + '/blocks.dat', 'c')
		self.height = gdbm.open(datadir + '/height.dat', 'c')
		self.to_height = gdbm.open(datadir + '/to-height.dat', 'c')
		self.tx = gdbm.open(datadir + '/tx.dat', 'c')

		if 'height' not in self.misc:
			self.log.write("INITIALIZING EMPTY BLOCKCHAIN DATABASE")
			self.misc['height'] = str(-1)
			self.misc['msg_start'] = self.netmagic.msg_start
			self.misc['tophash'] = str(0L)

		if 'msg_start' not in self.misc or (self.misc['msg_start'] != self.netmagic.msg_start):
			self.log.write("Database magic number mismatch. Data corruption or incorrect network?")
			raise RuntimeError

	def is_nextblock(self, block):
		if self.getheight() < 0 and block.sha256 == self.netmagic.block0:
			return True
		if self.gettophash() == block.hashPrevBlock:
			return True
		return False

	def puttxidx(self, blkhash, txhash, spentmask=0L):
		ser_txhash = ser_uint256(txhash)

		if ser_txhash in self.tx:
			txidx = self.gettxidx(txhash)
			self.log.write("WARNING: overwriting duplicate TX %064x, height %d, oldblk %064x, oldspent %x, newblk %064x" % (txhash, self.getheight(), txidx.blkhash, txidx.spentmask, blkhash))

		self.tx[ser_txhash] = hex(blkhash) + ' ' + hex(spentmask)

		return True

	def gettxidx(self, txhash):
		ser_txhash = ser_uint256(txhash)
		if ser_txhash not in self.tx:
			return None

		ser_value = self.tx[ser_txhash]
		pos = string.find(ser_value, ' ')

		txidx = TxIdx()
		txidx.blkhash = long(ser_value[:pos], 16)
		txidx.spentmask = long(ser_value[pos+1:], 16)

		return txidx

	def gettx(self, txhash):
		txidx = self.gettxidx(txhash)
		if txidx is None:
			return None

		block = self.getblock(txidx.blkhash)
		for tx in block.vtx:
			tx.calc_sha256()
			if tx.sha256 == txhash:
				return tx

		self.log.write("ERROR: Missing TX %064x in block %064x" % (txhash, txidx.blkhash))
		return None

	def getblock(self, blkhash):
		ser_hash = ser_uint256(blkhash)
		if ser_hash not in self.blocks:
			return None

		f = cStringIO.StringIO(self.blocks[ser_hash])
		block = CBlock()
		block.deserialize(f)

		return block

	def spend_txout(self, txhash, n_idx):
		txidx = self.gettxidx(txhash)
		if txidx is None:
			return False

		txidx.spentmask |= (1L << n_idx)
		self.puttxidx(txidx.blkhash, txhash, txidx.spentmask)

		return True

	def unique_outpts(self, block):
		outpts = {}
		txmap = {}
		for tx in block.vtx:
			if tx.is_coinbase:
				continue
			txmap[tx.sha256] = tx
			for txin in tx.vin:
				v = (txin.prevout.hash, txin.prevout.n)
				if v in outs:
					return None

				outpts[v] = False

		return (outpts, txmap)

	def spent_outpts(self, block):
		# list of outpoints this block wants to spend
		l = self.unique_outpts(block)
		if l is None:
			return None
		outpts = l[0]
		txmap = l[1]
		spendlist = {}

		# pass 1: if outpoint in db, make sure it is unspent
		for k in outpts.iterkeys():
			txidx = self.gettxidx(k[0])
			if txidx is None:
				continue

			if k[1] > 100000:	# outpoint index sanity check
				return None

			if txidx.spentmask & (1L << k[1]):
				return None

			outpts[k] = True	# skip in pass 2

		# pass 2: remaining outpoints must exist in this block
		for k, v in outpts.iteritems():
			if v:
				continue

			if k[0] not in txmap:	# validate txout hash
				return None

			tx = txmap[k[0]]	# validate txout index (n)
			if k[1] >= len(tx.vout):
				return None

			# outpts[k] = True	# not strictly necessary

		return outpts.keys()

	def tx_connected(self, tx):
		if not tx.is_valid():
			return False

		block = CBlock()
		block.vtx.append(tx)

		outpts = self.spent_outpts(block)
		if outpts is None:
			return False

		return True

	def putoneblock(self, block):
		block.calc_sha256()
		ser_hash = ser_uint256(block.sha256)

		if not block.is_valid():
			self.log.write("Invalid block %064x" % (block.sha256, ))
			return False
		if ser_hash in self.blocks:
			self.log.write("Duplicate block %064x" % (block.sha256, ))
			return False

		if not self.is_nextblock(block):
			self.orphan_deps[block.hashPrevBlock] = block
			self.log.write("Orphan block %064x (%d orphans)" % (block.sha256, len(self.orphan_deps)))
			return False

		# check TX connectivity
		outpts = self.spent_outpts(block)
		if outpts is None:
			self.log.write("Unconnectable block %064x" % (block.sha256, ))
			return False

		self.blocks[ser_hash] = block.serialize()
		self.misc['height'] = str(self.getheight() + 1)
		self.misc['tophash'] = str(block.sha256)
		self.height[str(self.getheight())] = str(block.sha256)
		self.to_height[str(block.sha256)] = str(self.getheight())

		self.log.write("ChainDb: block %064x, height %d" % (block.sha256, self.getheight()))

		# all TX's in block are connectable; index
		neverseen = 0
		for tx in block.vtx:
			if not self.mempool.remove(tx.sha256):
				neverseen += 1

			if not self.puttxidx(block.sha256, tx.sha256):
				self.log.write("TxIndex failed %064x" % (tx.sha256,))
				return False

		self.log.write("MemPool: blk.vtx.sz %d, neverseen %d, poolsz %d" % (len(block.vtx), neverseen, self.mempool.size()))

		# mark deps as spent
		for outpt in outpts:
			self.spend_txout(outpt[0], outpt[1])

		return True

	def putblock(self, block):
		if not self.putoneblock(block):
			return False

		blkhash = block.sha256
		while blkhash in self.orphan_deps:
			block = self.orphan_deps[blkhash]
			if not self.putoneblock(block):
				return True

			del self.orphan_deps[blkhash]

			blkhash = block.sha256

		return True

	def locate(self, locator):
		for hash in locator.vHave:
			str_hash = str(hash)
			if str_hash in self.to_height:
				return int(self.to_height[str_hash])
		return 0

	def getheight(self):
		return int(self.misc['height'])
	def gettophash(self):
		return long(self.misc['tophash'])

	def loadfile(self, filename):
		fd = os.open(filename, os.O_RDONLY)
		self.log.write("IMPORTING DATA FROM " + filename)
		buf = ''
		wanted = 4096
		while True:
			if wanted > 0:
				if wanted < 4096:
					wanted = 4096
				s = os.read(fd, wanted)
				if len(s) == 0:
					break

				buf += s
				wanted = 0

			buflen = len(buf)
			startpos = string.find(buf, self.netmagic.msg_start)
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

