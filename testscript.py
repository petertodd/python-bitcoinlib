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
from bitcoin.scripteval import *

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

MY_NETWORK='mainnet'

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
  # testnet3 transactions
  0x9aa3a5a6d9b7d1ac9555be8e42596d06686cc5f76d259b06c560a207d310d5f5L : True,
  0xc5d4b73af6eed28798473b05d2b227edd4f285069629843e899b52c2d1c165b7L : True,
  0xe335562f7e297aadeed88e5954bc4eeb8dc00b31d829eedb232e39d672b0c009L : True,
  0x74ea059a63c7ebddaee6805e1560b15c937d99a9ee9745412cbc6d2a0a5f5305L : True,
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

	for tx in block.vtx:
		if tx.is_coinbase():
			continue

		scanned_tx += 1

		if not scan_tx(tx):
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

