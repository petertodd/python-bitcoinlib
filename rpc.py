
#
# rpc.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import re
import base64
import json
import sys
import ChainDb
import bitcoin.coredefs

VALID_RPCS = {
	"getblockcount",
	"getblockhash",
	"getconnectioncount",
	"getinfo",
	"getrawmempool",
	"getrawtransaction",
	"help",
	"stop",
}

class RPCException(Exception):
	def __init__(self, status, message):
		self.status = status
		self.message = message

class RPCExec(object):
	def __init__(self, peermgr, mempool, chaindb, log, rpcuser, rpcpass):
		self.peermgr = peermgr
		self.mempool = mempool
		self.chaindb = chaindb
		self.rpcuser = rpcuser
		self.rpcpass = rpcpass
		self.log = log

	def help(self, params):
		s = "Available RPC calls:\n"
		s += "getblockcount - number of blocks in the longest block chain\n"
		s += "getblockhash <index> - Returns hash of block in best-block-chain at <index>\n"
		s += "getconnectioncount - get P2P peer count\n"
		s += "getinfo - misc. node info\n"
		s += "getrawmempool - list mempool contents\n"
		s += "getrawtransaction <txid> - Get serialized bytes for transaction <txid>\n"
		s += "help - this message\n"
		s += "stop - stop node\n"
		return (s, None)

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
				resp = self.handle_rpc(rpcreq)
			elif isinstance(rpcreq, list):
				resp = self.handle_rpc_batch(rpcreq)
			else:
				raise RPCException('400', "Not a valid JSON-RPC request")
			respstr = json.dumps(resp) + "\n"

			# Return a json response
			start_response('200 OK', [('Content-Type', 'application/json')])
			return respstr

		except RPCException, e:
			start_response(e.status, [('Content-Type', 'text/plain')], sys.exc_info())
			return e.message


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

	def handle_rpc_batch(self, rpcreq_list):
		res = []
		return ''.join(map(self.handle_rpc, repcreq_list))

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
