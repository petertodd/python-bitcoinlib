#!/usr/bin/python
#
# testscript.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#


import Log
import MemPool
import ChainDb
import cStringIO
from datatypes import *
from script import *
from serialize import *

log = Log.Log('/tmp/testscript.log')
mempool = MemPool.MemPool(log)
chaindb = ChainDb.ChainDb('/tmp/chaindb', log, mempool)

scanned = 0
failures = 0
cb_failures = 0

for height in xrange(chaindb.getheight()):
	blkhash = long(chaindb.height[str(height)])
	ser_hash = ser_uint256(blkhash)

	f = cStringIO.StringIO(chaindb.blocks[ser_hash])
	block = CBlock()
	block.deserialize(f)
	block.calc_sha256()

	log.write("Scanning block #%d %064x (%d tx)" % (height, block.sha256, len(block.vtx)))

	for tx in block.vtx:
		tx.calc_sha256()
		log.write("   TX %064x" % (tx.sha256,))

		i = 0
		for txin in tx.vin:
			script = CScript()
			if not script.tokenize(txin.scriptSig):
				log.write("      txin %d parse failed" % (i,))
				failures += 1
				if tx.is_coinbase():
					cb_failures += 1
			i += 1

		i = 0
		for txout in tx.vout:
			script = CScript()
			if not script.tokenize(txout.scriptPubKey):
				log.write("      txout %d parse failed" % (i,))
				failures += 1
				if tx.is_coinbase():
					cb_failures += 1
			i += 1

	scanned += 1
	if (scanned % 1000) == 0:
		print "Scanned %d blocks (%d/%d failures)" % (scanned, cb_failures, failures)



