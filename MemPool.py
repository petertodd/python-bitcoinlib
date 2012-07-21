
#
# MemPool.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from serialize import uint256_to_shortstr

class MemPool(object):
	def __init__(self):
		self.pool = {}
	
	def add(self, tx):
		tx.calc_sha256()
		hash = tx.sha256
		hashstr = uint256_to_shortstr(hash)

		if hash in self.pool:
			print "MemPool.add(%s): already known" % (hashstr, )
			return False
		if not tx.is_valid():
			print "MemPool.add(%s): invalid TX" % (hashstr, )
			return False

		self.pool[hash] = tx

		print "MemPool.add(%s), poolsz %d" % (hashstr, len(self.pool))

		return True

	def remove(self, hash):
		if hash not in self.pool:
			return False

		del self.pool[hash]
		return True

	def size(self):
		return len(self.pool)


