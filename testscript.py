#!/usr/bin/python
#
# testscript.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#


import sys
import time
import Log
import MemPool
import ChainDb
import cStringIO

from bitcoin.coredefs import NETWORKS
from bitcoin.core import CBlock
from bitcoin.serialize import ser_uint256
from bitcoin.scripteval import VerifySignature

NET_SETTINGS = {
	'mainnet' : {
		'log' : '/spare/tmp/testscript.log',
		'db' : '/spare/tmp/chaindb'
	},
	'testnet3' : {
		'log' : '/spare/tmp/testtestscript.log',
		'db' : '/spare/tmp/chaintest'
	}
}

MY_NETWORK = 'mainnet'

SETTINGS = NET_SETTINGS[MY_NETWORK]

start_height = 0
end_height = -1
if len(sys.argv) > 1:
	start_height = int(sys.argv[1])
if len(sys.argv) > 2:
	end_height = int(sys.argv[2])
if len(sys.argv) > 3:
	SETTINGS['log'] = sys.argv[3]

log = Log.Log(SETTINGS['log'])
mempool = MemPool.MemPool(log)
chaindb = ChainDb.ChainDb(SETTINGS['db'], log, mempool,
			  NETWORKS[MY_NETWORK], True)
chaindb.blk_cache.max = 500

if end_height < 0 or end_height > chaindb.getheight():
	end_height = chaindb.getheight()

scanned = 0
scanned_tx = 0
failures = 0
opcount = {}

SKIP_TX = {
}


def scan_tx(tx):
	tx.calc_sha256()

	if tx.sha256 in SKIP_TX:
		return True

#	log.write("...Scanning TX %064x" % (tx.sha256,))
	for i in xrange(len(tx.vin)):
		txin = tx.vin[i]
		txfrom = chaindb.gettx(txin.prevout.hash)
		if not VerifySignature(txfrom, tx, i, 0):
			log.write("TX %064x/%d failed" % (tx.sha256, i))
			log.write("FROMTX %064x" % (txfrom.sha256,))
			log.write(txfrom.__repr__())
			log.write("TOTX %064x" % (tx.sha256,))
			log.write(tx.__repr__())
			return False
	return True

for height in xrange(end_height):
	if height < start_height:
		continue
	heightidx = ChainDb.HeightIdx()
	heightidx.deserialize(chaindb.height[str(height)])

	blkhash = heightidx.blocks[0]
	ser_hash = ser_uint256(blkhash)

	f = cStringIO.StringIO(chaindb.blocks[ser_hash])
	block = CBlock()
	block.deserialize(f)

	start_time = time.time()

	for tx_tmp in block.vtx:
		if tx_tmp.is_coinbase():
			continue

		scanned_tx += 1

		if not scan_tx(tx_tmp):
			failures += 1
			sys.exit(1)

	end_time = time.time()

	scanned += 1
#	if (scanned % 1000) == 0:
	log.write("Scanned %d tx, height %d (%d failures), %.2f sec" % (
		scanned_tx, height, failures, end_time - start_time))


log.write("Scanned %d tx, %d blocks (%d failures)" % (
	scanned_tx, scanned, failures))

#for k,v in opcount.iteritems():
#	print k, v

