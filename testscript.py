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
from bitcoin.core import *
from bitcoin.script import *
from bitcoin.serialize import *

log = Log.Log('/tmp/testscript.log')
mempool = MemPool.MemPool(log)
chaindb = ChainDb.ChainDb('/tmp/chaindb', log, mempool, NETWORKS['mainnet'])

scanned = 0
failures = 0
warnings = 0
opcount = {}

def scan_script(scriptIn):
	global opcount
	script = CScript(scriptIn)
	while script.pc < script.pend:
		if not script.getop():
			return False

		sop = script.sop
		if sop.op in OPCODE_NAMES:
			name = OPCODE_NAMES[sop.op]
		elif sop.op <= OP_PUSHDATA4:
			name = 'OP_PUSHDATA'
		else:
			name = "0x%02x" % (sop.op,)

		if name in opcount:
			opcount[name] += 1
		else:
			opcount[name] = 1

	return True

for height in xrange(chaindb.getheight()):
	blkhash = long(chaindb.height[str(height)])
	ser_hash = ser_uint256(blkhash)

	f = cStringIO.StringIO(chaindb.blocks[ser_hash])
	block = CBlock()
	block.deserialize(f)

	for tx in block.vtx:
		if not tx.is_coinbase():
			for txin in tx.vin:
				if not scan_script(txin.scriptSig):
					failures += 1
		for txout in tx.vout:
			if not scan_script(txout.scriptPubKey):
				failures += 1

	scanned += 1
	if (scanned % 1000) == 0:
		print "Scanned %d blocks (%d warnings, %d failures)" % (scanned, warnings, failures)


print "Scanned %d blocks (%d warnings, %d failures)" % (scanned, warnings, failures)

for k,v in opcount.iteritems():
	print k, v

