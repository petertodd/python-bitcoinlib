#!/usr/bin/python
#
# dbck.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#


import sys
import Log
import MemPool
import ChainDb
import cStringIO

from bitcoin.coredefs import NETWORKS
from bitcoin.core import CBlock
from bitcoin.scripteval import *

NET_SETTINGS = {
	'mainnet' : {
		'log' : '/tmp/dbck.log',
		'db' : '/tmp/chaindb'
	},
	'testnet3' : {
		'log' : '/tmp/dbcktest.log',
		'db' : '/tmp/chaintest'
	}
}

MY_NETWORK = 'mainnet'

SETTINGS = NET_SETTINGS[MY_NETWORK]

log = Log.Log(SETTINGS['log'])
mempool = MemPool.MemPool(log)
chaindb = ChainDb.ChainDb(SETTINGS['db'], log, mempool, NETWORKS[MY_NETWORK])

scanned = 0
failures = 0

for height in xrange(chaindb.getheight()):
	heightidx = ChainDb.HeightIdx()
	heightidx.deserialize(chaindb.height[str(height)])

	blkhash = heightidx.blocks[0]
	ser_hash = ser_uint256(blkhash)

	f = cStringIO.StringIO(chaindb.blocks[ser_hash])
	block = CBlock()
	block.deserialize(f)

	if not block.is_valid():
		log.write("block %064x failed" % (blkhash,))
		failures += 1

	scanned += 1
	if (scanned % 1000) == 0:
		log.write("Scanned height %d (%d failures)" % (
			height, failures))


log.write("Scanned %d blocks (%d failures)" % (scanned, failures))

