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
from defs import *
from datatypes import *
from script import *
from serialize import *

log = Log.Log('/tmp/testscript.log')
mempool = MemPool.MemPool(log)
chaindb = ChainDb.ChainDb('/tmp/chaindb', log, mempool, NETWORKS['mainnet'])

scanned = 0
failures = 0
warnings = 0

for height in xrange(chaindb.getheight()):
	blkhash = long(chaindb.height[str(height)])
	ser_hash = ser_uint256(blkhash)

	f = cStringIO.StringIO(chaindb.blocks[ser_hash])
	block = CBlock()
	block.deserialize(f)

	if not block.is_valid():
		log.write("Failed block #%d %064x (%d tx)" % (height, block.sha256, len(block.vtx)))
		failures += 1

	scanned += 1
	if (scanned % 1000) == 0:
		print "Scanned %d blocks (%d warnings, %d failures)" % (scanned, warnings, failures)


print "Scanned %d blocks (%d warnings, %d failures)" % (scanned, warnings, failures)

