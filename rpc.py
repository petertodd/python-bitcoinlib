
#
# rpc.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import re
import base64
import json
import cStringIO
import struct
import sys
import itertools

import ChainDb
import bitcoin.coredefs
from bitcoin.serialize import uint256_from_compact

VALID_RPCS = {
	"getblockcount",
	"getblock",
	"getblockhash",
	"getconnectioncount",
	"getinfo",
	"getrawmempool",
	"getrawtransaction",
	"getwork",
	"submitblock",
	"help",
	"stop",
}

class RPCException(Exception):
	def __init__(self, status, message):
		self.status = status
		self.message = message

def uint32(x):
	return x & 0xffffffffL

def bytereverse(x):
	return uint32(( ((x) << 24) | (((x) << 8) & 0x00ff0000) |
			(((x) >> 8) & 0x0000ff00) | ((x) >> 24) ))

def bufreverse(in_buf):
	out_words = []
	for i in range(0, len(in_buf), 4):
		word = struct.unpack('@I', in_buf[i:i+4])[0]
		out_words.append(struct.pack('@I', bytereverse(word)))
	return ''.join(out_words)

def blockToJSON(block, blkmeta, cur_height):
	block.calc_sha256()
	res = {}

	res['hash'] = "%064x" % (block.sha256,)
	res['confirmations'] = cur_height - blkmeta.height + 1
	res['size'] = len(block.serialize())
	res['height'] = blkmeta.height
	res['version'] = block.nVersion
	res['merkleroot'] = "%064x" % (block.hashMerkleRoot,)
	res['time'] = block.nTime
	res['nonce'] = block.nNonce
	res['bits'] = "%x" % (block.nBits,)
	res['previousblockhash'] = "%064x" % (block.hashPrevBlock,)

	txs = []
	for tx in block.vtx:
		tx.calc_sha256()
		txs.append("%064x" % (tx.sha256,))
	
	res['tx'] = txs

	return res

class RPCExec(object):
	def __init__(self, peermgr, mempool, chaindb, log, rpcuser, rpcpass):
		self.peermgr = peermgr
		self.mempool = mempool
		self.chaindb = chaindb
		self.rpcuser = rpcuser
		self.rpcpass = rpcpass
		self.log = log

		self.work_tophash = None
		self.work_blocks = {}

	def help(self, params):
		s = "Available RPC calls:\n"
		s += "getblock <hash> - Return block header and list of transactions\n"
		s += "getblockcount - number of blocks in the longest block chain\n"
		s += "getblockhash <index> - Returns hash of block in best-block-chain at <index>\n"
		s += "getconnectioncount - get P2P peer count\n"
		s += "getinfo - misc. node info\n"
		s += "getrawmempool - list mempool contents\n"
		s += "getrawtransaction <txid> - Get serialized bytes for transaction <txid>\n"
		s += "getwork [data] - get mining work\n"
		s += "submitblock <data>\n"
		s += "help - this message\n"
		s += "stop - stop node\n"
		return (s, None)

	def getblock(self, params):
		err = { "code" : -1, "message" : "invalid params" }
		if (len(params) != 1 or
		    (not isinstance(params[0], str) and
		     not isinstance(params[0], unicode))):
			return (None, err)

		blkhash = long(params[0], 16)
		block = self.chaindb.getblock(blkhash)
		blkmeta = self.chaindb.getblockmeta(blkhash)
		cur_height = self.chaindb.getheight()
		if block is None or blkmeta is None or cur_height < 0:
			err = { "code" : -4, "message" : "block hash not found"}
			return (None, err)

		res = blockToJSON(block, blkmeta, cur_height)

		return (res, None)

	def getblockcount(self, params):
		return (self.chaindb.getheight(), None)

	def getblockhash(self, params):
		err = { "code" : -1, "message" : "invalid params" }
		if (len(params) != 1 or
			not isinstance(params[0], int)):
			return (None, err)

		index = params[0]
		heightstr = str(index)
		if heightstr not in self.chaindb.height:
			err = { "code" : -2, "message" : "invalid height" }
			return (None, err)

		heightidx = ChainDb.HeightIdx()
		heightidx.deserialize(self.chaindb.height[str(index)])

		return ("%064x" % (heightidx.blocks[0],), None)

	def getconnectioncount(self, params):
		return (len(self.peermgr.peers), None)

	def getinfo(self, params):
		d = {}
		d['protocolversion'] = bitcoin.coredefs.PROTO_VERSION
		d['blocks'] = self.chaindb.getheight()
		if self.chaindb.netmagic.block0 == 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26fL:
			d['testnet'] = False
		else:
			d['testnet'] = True
		return (d, None)

	def getrawmempool(self, params):
		l = []
		for k in self.mempool.pool.iterkeys():
			l.append("%064x" % (k,))
		return (l, None)

	def getrawtransaction(self, params):
		err = { "code" : -1, "message" : "invalid params" }
		if (len(params) != 1 or
			(not isinstance(params[0], str) and
			 not isinstance(params[0], unicode))):
			return (None, err)
		m = re.search('\s*([\dA-Fa-f]+)\s*', params[0])
		if m is None:
			err = { "code" : -1, "message" : "invalid txid param" }
			return (None, err)

		txhash = long(m.group(1), 16)
		tx = self.chaindb.gettx(txhash)
		if tx is None:
			err = { "code" : -3, "message" : "txid not found" }
			return (None, err)

		ser_tx = tx.serialize()
		return (ser_tx.encode('hex'), None)

	def getwork_new(self):
		err = { "code" : -6, "message" : "internal error" }
		tmp_top = self.chaindb.gettophash()
		if self.work_tophash != tmp_top:
			self.work_tophash = tmp_top
			self.work_blocks = {}

		block = self.chaindb.newblock()
		if block is None:
			return (None, err)
		self.work_blocks[block.hashMerkleRoot] = block

		res = {}

		target = uint256_from_compact(block.nBits)
		res['target'] = "%064x" % (target,)

		data = block.serialize()
		data = data[:80]
		data += "\x00" * 48

		data = bufreverse(data)
		res['data'] = data.encode('hex')

		return (res, None)

	def getwork_submit(self, hexstr):
		data = hexstr.decode('hex')
		if len(data) != 128:
			err = { "code" : -5, "message" : "invalid data" }
			return (None, err)

		data = bufreverse(data)
		blkhdr = data[:80]
		f = cStringIO.StringIO(blkhdr)
		block_tmp = CBlock()
		block_tmp.deserialize(f)

		if block_tmp.hashMerkleRoot not in self.work_blocks:
			return (False, None)

		block = self.work_blocks[block_tmp.hashMerkleRoot]
		block.nTime = block_tmp.nTime
		block.nNonce = block_tmp.nNonce

		res = self.chaindb.putblock(block)

		return (res, None)

	def getwork(self, params):
		err = { "code" : -1, "message" : "invalid params" }
		if len(params) == 1:
			if (not isinstance(params[0], str) and
			    not isinstance(params[0], unicode)):
				return (None, err)
			return self.getwork_submit(params[0])
		elif len(params) == 0:
			return self.getwork_new()
		else:
			return (None, err)

	def submitblock(self, params):
		err = { "code" : -1, "message" : "invalid params" }
		if (len(params) != 1 or
		    (not isinstance(params[0], str) and
		     not isinstance(params[0], unicode))):
			return (None, err)

		data = params[0].decode('hex')
		f = cStringIO.StringIO(data)
		block = CBlock()
		block.deserialize(f)

		res = self.chaindb.putblock(block)
		if not res:
			return ("rejected", None)

		return (None, None)

	def stop(self, params):
		self.peermgr.closeall()
		return (True, None)

	def handle_request(self, environ, start_response):
		try:
			# Posts only
			if environ['REQUEST_METHOD'] != 'POST':
				raise RPCException('501', "Unsupported method (%s)" % environ['REQUEST_METHOD'])

			# Only accept default path
			if environ['PATH_INFO'] + environ['SCRIPT_NAME'] != '/':
				raise RPCException('404', "Path not found")

			# RPC authentication
			username = self.check_auth(environ['HTTP_AUTHORIZATION'])
			if username is None:
				raise RPCException('401', 'Forbidden')

			# Dispatch the RPC call
			length = environ['CONTENT_LENGTH']
			body = environ['wsgi.input'].read(length)
			try:
				rpcreq = json.loads(body)
			except ValueError:
				raise RPCException('400', "Unable to decode JSON data")

			if isinstance(rpcreq, dict):
				start_response('200 OK', [('Content-Type', 'application/json')])
				resp = self.handle_rpc(rpcreq)
				respstr = json.dumps(resp) + "\n"
				yield respstr

			elif isinstance(rpcreq, list):
				start_response('200 OK', [('Content-Type', 'application/json')])
				for resp in itertools.imap(self.handle_rpc, repcreq_list):
					respstr = json.dumps(resp) + "\n"
					yield respstr
			else:
				raise RPCException('400', "Not a valid JSON-RPC request")

		except RPCException, e:
			start_response(e.status, [('Content-Type', 'text/plain')], sys.exc_info())
			yield e.message


	def check_auth(self, hdr):
		if hdr is None:
			return None

		m = re.search('\s*(\w+)\s+(\S+)', hdr)
		if m is None or m.group(0) is None:
			return None
		if m.group(1) != 'Basic':
			return None

		unpw = base64.b64decode(m.group(2))
		if unpw is None:
			return None

		m = re.search('^([^:]+):(.*)$', unpw)
		if m is None:
			return None

		un = m.group(1)
		pw = m.group(2)
		if (un != self.rpcuser or
			pw != self.rpcpass):
			return None

		return un


	def handle_rpc(self, rpcreq):
		id = None
		if 'id' in rpcreq:
			id = rpcreq['id']
		if ('method' not in rpcreq or
			(not isinstance(rpcreq['method'], str) and
			 not isinstance(rpcreq['method'], unicode))):
			resp = { "id" : id, "error" :
				  { "code" : -1,
					"message" : "method not specified" } }
			return resp
		if ('params' not in rpcreq or
			not isinstance(rpcreq['params'], list)):
			resp = { "id" : id, "error" :
				  { "code" : -2,
					"message" : "invalid/missing params" } }
			return resp

		(res, err) = self.jsonrpc(rpcreq['method'], rpcreq['params'])

		if err is None:
			resp = { "result" : res, "error" : None, "id" : id }
		else:
			resp = { "error" : err, "id" : id }

		return resp

	def json_response(self, resp):
		pass

	def jsonrpc(self, method, params):
		if method not in VALID_RPCS:
			return (None, { "code" : -32601,
					"message" : "method not found" })
		rpcfunc = getattr(self, method)
		return rpcfunc(params)

	def log_message(self, format, *args):
		self.log.write("HTTP %s - - [%s] %s \"%s\" \"%s\"" %
			(self.address_string(),
			 self.log_date_time_string(),
			 format%args,
			 self.headers.get('referer', ''),
			 self.headers.get('user-agent', '')
			 ))
