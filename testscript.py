#!/usr/bin/python
#
# testscript.py
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
		'log' : '/tmp/testscript.log',
		'db' : '/tmp/chaindb'
	},
	'testnet3' : {
		'log' : '/tmp/testtestscript.log',
		'db' : '/tmp/chaintest'
	}
}

MY_NETWORK='mainnet'

SETTINGS = NET_SETTINGS[MY_NETWORK]

log = Log.Log(SETTINGS['log'])
mempool = MemPool.MemPool(log)
chaindb = ChainDb.ChainDb(SETTINGS['db'], log, mempool, NETWORKS[MY_NETWORK])

scanned = 0
scanned_tx = 0
failures = 0
opcount = {}

def scan_tx(tx):
	tx.calc_sha256()
#	print "...Scanning TX %064x" % (tx.sha256,)
	for i in xrange(len(tx.vin)):
		txin = tx.vin[i]
		txfrom = chaindb.gettx(txin.prevout.hash)
		if not VerifySignature(txfrom, tx, i, 0):
			print "TX %064x/%d failed" % (tx.sha256, i)
			print "FROMTX %064x" % (txfrom.sha256,)
			print txfrom
			print "TOTX %064x" % (tx.sha256,)
			print tx
			return False
	return True
	
for height in xrange(chaindb.getheight()):
	blkhash = long(chaindb.height[str(height)])
	ser_hash = ser_uint256(blkhash)

	f = cStringIO.StringIO(chaindb.blocks[ser_hash])
	block = CBlock()
	block.deserialize(f)

	for tx in block.vtx:
		if tx.is_coinbase():
			continue

		scanned_tx += 1

		if not scan_tx(tx):
			failures += 1
			sys.exit(1)

	scanned += 1
#	if (scanned % 1000) == 0:
	print "Scanned %d tx, %d blocks (%d failures)" % (scanned_tx, scanned, failures)


print "Scanned %d tx, %d blocks (%d failures)" % (scanned_tx, scanned, failures)

for k,v in opcount.iteritems():
	print k, v

