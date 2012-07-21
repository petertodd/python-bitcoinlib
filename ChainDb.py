
#
# ChainDb.py - Bitcoin blockchain database
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import anydbm

class ChainDb(object):
	def __init__(self, datadir):
		self.misc = anydbm.open(datadir + '/misc.dat', 'c')
		self.blocks = anydbm.open(datadir + '/blocks.dat', 'c')
		self.height = anydbm.open(datadir + '/height.dat', 'c')

		if 'height' not in self.misc:
			self.misc['height'] = str(-1)

	def putblock(self, ser_hash, block):
		if ser_hash in self.blocks:
			return False

		self.blocks[ser_hash] = block.serialize()
		return True

	def getheight(self):
		return int(self.misc['height'])

