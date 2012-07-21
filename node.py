#!/usr/bin/python

import struct
import socket
import asyncore
import binascii
import time
import sys
import random
import cStringIO
from Crypto.Hash import SHA256

MY_VERSION = 312
MY_SUBVERSION = ".4"

def deser_string(f):
	nit = struct.unpack("<B", f.read(1))[0]
	if nit == 253:
		nit = struct.unpack("<H", f.read(2))[0]
	elif nit == 254:
		nit = struct.unpack("<I", f.read(4))[0]
	elif nit == 255:
		nit = struct.unpack("<Q", f.read(8))[0]
	return f.read(nit)

def ser_string(s):
	if len(s) < 253:
		return chr(len(s)) + s
	elif len(s) < 0x10000:
		return chr(253) + struct.pack("<H", len(s)) + s
	elif len(s) < 0x100000000L:
		return chr(254) + struct.pack("<I", len(s)) + s
	return chr(255) + struct.pack("<Q", len(s)) + s

def deser_uint256(f):
	r = 0L
	for i in xrange(8):
		t = struct.unpack("<I", f.read(4))[0]
		r += t << (i * 32)
	return r

def ser_uint256(u):
	rs = ""
	for i in xrange(8):
		rs += struct.pack("<I", u & 0xFFFFFFFFL)
		u >>= 32
	return rs

def uint256_from_str(s):
	r = 0L
	t = struct.unpack("<IIIIIIII", s[:32])
	for i in xrange(8):
		r += t[i] << (i * 32)
	return r

def uint256_from_compact(c):
	nbytes = (c >> 24) & 0xFF
	v = (c & 0xFFFFFFL) << (8 * (nbytes - 3))
	return v

def deser_vector(f, c):
	nit = struct.unpack("<B", f.read(1))[0]
	if nit == 253:
		nit = struct.unpack("<H", f.read(2))[0]
	elif nit == 254:
		nit = struct.unpack("<I", f.read(4))[0]
	elif nit == 255:
		nit = struct.unpack("<Q", f.read(8))[0]
	r = []
	for i in xrange(nit):
		t = c()
		t.deserialize(f)
		r.append(t)
	return r

def ser_vector(l):
	r = ""
	if len(l) < 253:
		r = chr(len(l))
	elif len(l) < 0x10000:
		r = chr(253) + struct.pack("<H", len(l))
	elif len(l) < 0x100000000L:
		r = chr(254) + struct.pack("<I", len(l))
	else:
		r = chr(255) + struct.pack("<Q", len(l))
	for i in l:
		r += i.serialize()
	return r

def deser_uint256_vector(f):
	nit = struct.unpack("<B", f.read(1))[0]
	if nit == 253:
		nit = struct.unpack("<H", f.read(2))[0]
	elif nit == 254:
		nit = struct.unpack("<I", f.read(4))[0]
	elif nit == 255:
		nit = struct.unpack("<Q", f.read(8))[0]
	r = []
	for i in xrange(nit):
		t = deser_uint256(f)
		r.append(t)
	return r

def ser_uint256_vector(l):
	r = ""
	if len(l) < 253:
		r = chr(len(l))
	elif len(s) < 0x10000:
		r = chr(253) + struct.pack("<H", len(l))
	elif len(s) < 0x100000000L:
		r = chr(254) + struct.pack("<I", len(l))
	else:
		r = chr(255) + struct.pack("<Q", len(l))
	for i in l:
		r += ser_uint256(i)
	return r

class CAddress(object):
	def __init__(self):
		self.nServices = 1
		self.pchReserved = "\x00" * 10 + "\xff" * 2
		self.ip = "0.0.0.0"
		self.port = 0
	def deserialize(self, f):
		self.nServices = struct.unpack("<Q", f.read(8))[0]
		self.pchReserved = f.read(12)
		self.ip = socket.inet_ntoa(f.read(4))
		self.port = struct.unpack(">H", f.read(2))[0]
	def serialize(self):
		r = ""
		r += struct.pack("<Q", self.nServices)
		r += self.pchReserved
		r += socket.inet_aton(self.ip)
		r += struct.pack(">H", self.port)
		return r
	def __repr__(self):
		return "CAddress(nServices=%i ip=%s port=%i)" % (self.nServices, self.ip, self.port)

class CInv(object):
	typemap = {
		0: "Error",
		1: "TX",
		2: "Block"}
	def __init__(self):
		self.type = 0
		self.hash = 0L
	def deserialize(self, f):
		self.type = struct.unpack("<i", f.read(4))[0]
		self.hash = deser_uint256(f)
	def serialize(self):
		r = ""
		r += struct.pack("<i", self.type)
		r += ser_uint256(self.hash)
		return r
	def __repr__(self):
		return "CInv(type=%s hash=%064x)" % (self.typemap[self.type], self.hash)

class CBlockLocator(object):
	def __init__(self):
		self.nVersion = MY_VERSION
		self.vHave = []
	def deserialize(self, f):
		self.nVersion = struct.unpack("<i", f.read(4))[0]
		self.vHave = deser_uint256_vector(f)
	def serialize(self):
		r = ""
		r += struct.pack("<i", self.nVersion)
		r += ser_uint256_vector(self.vHave)
		return r
	def __repr__(self):
		return "CBlockLocator(nVersion=%i vHave=%s)" % (self.nVersion, repr(self.vHave))

class COutPoint(object):
	def __init__(self):
		self.hash = 0
		self.n = 0
	def deserialize(self, f):
		self.hash = deser_uint256(f)
		self.n = struct.unpack("<I", f.read(4))[0]
	def serialize(self):
		r = ""
		r += ser_uint256(self.hash)
		r += struct.pack("<I", self.n)
		return r
	def __repr__(self):
		return "COutPoint(hash=%064x n=%i)" % (self.hash, self.n)

class CTxIn(object):
	def __init__(self):
		self.prevout = COutPoint()
		self.scriptSig = ""
		self.nSequence = 0
	def deserialize(self, f):
		self.prevout = COutPoint()
		self.prevout.deserialize(f)
		self.scriptSig = deser_string(f)
		self.nSequence = struct.unpack("<I", f.read(4))[0]
	def serialize(self):
		r = ""
		r += self.prevout.serialize()
		r += ser_string(self.scriptSig)
		r += struct.pack("<I", self.nSequence)
		return r
	def __repr__(self):
		return "CTxIn(prevout=%s scriptSig=%s nSequence=%i)" % (repr(self.prevout), binascii.hexlify(self.scriptSig), self.nSequence)

class CTxOut(object):
	def __init__(self):
		self.nValue = 0
		self.scriptPubKey = ""
	def deserialize(self, f):
		self.nValue = struct.unpack("<q", f.read(8))[0]
		self.scriptPubKey = deser_string(f)
	def serialize(self):
		r = ""
		r += struct.pack("<q", self.nValue)
		r += ser_string(self.scriptPubKey)
		return r
	def __repr__(self):
		return "CTxOut(nValue=%i.%08i scriptPubKey=%s)" % (self.nValue // 100000000, self.nValue % 100000000, binascii.hexlify(self.scriptPubKey))

class CTransaction(object):
	def __init__(self):
		self.nVersion = 1
		self.vin = []
		self.vout = []
		self.nLockTime = 0
		self.sha256 = None
	def deserialize(self, f):
		self.nVersion = struct.unpack("<i", f.read(4))[0]
		self.vin = deser_vector(f, CTxIn)
		self.vout = deser_vector(f, CTxOut)
		self.nLockTime = struct.unpack("<I", f.read(4))[0]
	def serialize(self):
		r = ""
		r += struct.pack("<i", self.nVersion)
		r += ser_vector(self.vin)
		r += ser_vector(self.vout)
		r += struct.pack("<I", self.nLockTime)
		return r
	def calc_sha256(self):
		if self.sha256 is None:
			self.sha256 = uint256_from_str(SHA256.new(SHA256.new(self.serialize()).digest()).digest())
	def is_valid(self):
		self.calc_sha256()
		for tout in self.vout:
			if tout.nValue < 0 or tout.nValue > 21000000L * 100000000L:
				return False
		return True
	def __repr__(self):
		return "CTransaction(nVersion=%i vin=%s vout=%s nLockTime=%i)" % (self.nVersion, repr(self.vin), repr(self.vout), self.nLockTime)

class CBlock(object):
	def __init__(self):
		self.nVersion = 1
		self.hashPrevBlock = 0
		self.hashMerkleRoot = 0
		self.nTime = 0
		self.nBits = 0
		self.nNonce = 0
		self.vtx = []
		self.sha256 = None
	def deserialize(self, f):
		self.nVersion = struct.unpack("<i", f.read(4))[0]
		self.hashPrevBlock = deser_uint256(f)
		self.hashMerkleRoot = deser_uint256(f)
		self.nTime = struct.unpack("<I", f.read(4))[0]
		self.nBits = struct.unpack("<I", f.read(4))[0]
		self.nNonce = struct.unpack("<I", f.read(4))[0]
		self.vtx = deser_vector(f, CTransaction)
	def serialize(self):
		r = ""
		r += struct.pack("<i", self.nVersion)
		r += ser_uint256(self.hashPrevBlock)
		r += ser_uint256(self.hashMerkleRoot)
		r += struct.pack("<I", self.nTime)
		r += struct.pack("<I", self.nBits)
		r += struct.pack("<I", self.nNonce)
		r += ser_vector(self.vtx)
		return r
	def calc_sha256(self):
		if self.sha256 is None:
			r = ""
			r += struct.pack("<i", self.nVersion)
			r += ser_uint256(self.hashPrevBlock)
			r += ser_uint256(self.hashMerkleRoot)
			r += struct.pack("<I", self.nTime)
			r += struct.pack("<I", self.nBits)
			r += struct.pack("<I", self.nNonce)
			self.sha256 = uint256_from_str(SHA256.new(SHA256.new(r).digest()).digest())
	def is_valid(self):
		self.calc_sha256()
		target = uint256_from_compact(self.nBits)
		if self.sha256 > target:
			return False
		hashes = []
		for tx in self.vtx:
			if not tx.is_valid():
				return False
			tx.calc_sha256()
			hashes.append(ser_uint256(tx.sha256))
		while len(hashes) > 1:
			newhashes = []
			for i in xrange(0, len(hashes), 2):
				i2 = min(i+1, len(hashes)-1)
				newhashes.append(SHA256.new(SHA256.new(hashes[i] + hashes[i2]).digest()).digest())
			hashes = newhashes
		if uint256_from_str(hashes[0]) != self.hashMerkleRoot:
			return False
		return True
	def __repr__(self):
		return "CBlock(nVersion=%i hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nNonce=%08x vtx=%s)" % (self.nVersion, self.hashPrevBlock, self.hashMerkleRoot, time.ctime(self.nTime), self.nBits, self.nNonce, repr(self.vtx))

class msg_version(object):
	command = "version"
	def __init__(self):
		self.nVersion = MY_VERSION
		self.nServices = 1
		self.nTime = time.time()
		self.addrTo = CAddress()
		self.addrFrom = CAddress()
		self.nNonce = random.getrandbits(64)
		self.strSubVer = MY_SUBVERSION
		self.nStartingHeight = -1
	def deserialize(self, f):
		self.nVersion = struct.unpack("<i", f.read(4))[0]
		if self.nVersion == 10300:
			self.nVersion = 300
		self.nServices = struct.unpack("<Q", f.read(8))[0]
		self.nTime = struct.unpack("<q", f.read(8))[0]
		self.addrTo = CAddress()
		self.addrTo.deserialize(f)
		if self.nVersion >= 106:
			self.addrFrom = CAddress()
			self.addrFrom.deserialize(f)
			self.nNonce = struct.unpack("<Q", f.read(8))[0]
			self.strSubVer = deser_string(f)
			if self.nVersion >= 209:
				self.nStartingHeight = struct.unpack("<i", f.read(4))[0]
			else:
				self.nStartingHeight = None
		else:
			self.addrFrom = None
			self.nNonce = None
			self.strSubVer = None
			self.nStartingHeight = None
	def serialize(self):
		r = ""
		r += struct.pack("<i", self.nVersion)
		r += struct.pack("<Q", self.nServices)
		r += struct.pack("<q", self.nTime)
		r += self.addrTo.serialize()
		r += self.addrFrom.serialize()
		r += struct.pack("<Q", self.nNonce)
		r += ser_string(self.strSubVer)
		r += struct.pack("<i", self.nStartingHeight)
		return r
	def __repr__(self):
		return "msg_version(nVersion=%i nServices=%i nTime=%s addrTo=%s addrFrom=%s nNonce=0x%016X strSubVer=%s nStartingHeight=%i)" % (self.nVersion, self.nServices, time.ctime(self.nTime), repr(self.addrTo), repr(self.addrFrom), self.nNonce, self.strSubVer, self.nStartingHeight)

class msg_verack(object):
	command = "verack"
	def __init__(self):
		pass
	def deserialize(self, f):
		pass
	def serialize(self):
		return ""
	def __repr__(self):
		return "msg_verack()"

class msg_addr(object):
	command = "addr"
	def __init__(self):
		self.addrs = []
	def deserialize(self, f):
		self.addrs = deser_vector(f, CAddress)
	def serialize(self):
		return ser_vector(self.addrs)
	def __repr__(self):
		return "msg_addr(addrs=%s)" % (repr(self.addrs))

class msg_inv(object):
	command = "inv"
	def __init__(self):
		self.inv = []
	def deserialize(self, f):
		self.inv = deser_vector(f, CInv)
	def serialize(self):
		return ser_vector(self.inv)
	def __repr__(self):
		return "msg_inv(inv=%s)" % (repr(self.inv))

class msg_getdata(object):
	command = "getdata"
	def __init__(self):
		self.inv = []
	def deserialize(self, f):
		self.inv = deser_vector(f, CInv)
	def serialize(self):
		return ser_vector(self.inv)
	def __repr__(self):
		return "msg_getdata(inv=%s)" % (repr(self.inv))

class msg_getblocks(object):
	command = "getblocks"
	def __init__(self):
		self.locator = CBlockLocator()
		self.hashstop = 0L
	def deserialize(self, f):
		self.locator = CBlockLocator()
		self.locator.deserialize(f)
		self.hashstop = deser_uint256(f)
	def serialize(self):
		r = ""
		r += self.locator.serialize()
		r += ser_uint256(self.hashstop)
		return r
	def __repr__(self):
		return "msg_getblocks(locator=%s hashstop=%064x)" % (repr(self.locator), self.hashstop)

class msg_tx(object):
	command = "tx"
	def __init__(self):
		self.tx = CTransaction()
	def deserialize(self, f):
		self.tx.deserialize(f)
	def serialize(self):
		return self.tx.serialize()
	def __repr__(self):
		return "msg_tx(tx=%s)" % (repr(self.tx))

class msg_block(object):
	command = "block"
	def __init__(self):
		self.block = CBlock()
	def deserialize(self, f):
		self.block.deserialize(f)
	def serialize(self):
		return self.block.serialize()
	def __repr__(self):
		return "msg_block(block=%s)" % (repr(self.block))

class msg_getaddr(object):
	command = "getaddr"
	def __init__(self):
		pass
	def deserialize(self, f):
		pass
	def serialize(self):
		return ""
	def __repr__(self):
		return "msg_getaddr()"

#msg_checkorder
#msg_submitorder
#msg_reply

class msg_ping(object):
	command = "ping"
	def __init__(self):
		pass
	def deserialize(self, f):
		pass
	def serialize(self):
		return ""
	def __repr__(self):
		return "msg_ping()"





class NodeConn(asyncore.dispatcher):
	messagemap = {
		"version": msg_version,
		"verack": msg_verack,
		"addr": msg_addr,
		"inv": msg_inv,
		"getdata": msg_getdata,
		"getblocks": msg_getblocks,
		"tx": msg_tx,
		"block": msg_block,
		"getaddr": msg_getaddr,
		"ping": msg_ping
	}
	def __init__(self, dstaddr, dstport):
		asyncore.dispatcher.__init__(self)
		self.dstaddr = dstaddr
		self.dstport = dstport
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sendbuf = ""
		self.recvbuf = ""
		self.ver_send = 209
		self.ver_recv = 209
		self.last_sent = 0
		self.state = "connecting"

		#stuff version msg into sendbuf
		vt = msg_version()
		vt.addrTo.ip = self.dstaddr
		vt.addrTo.port = self.dstport
		vt.addrFrom.ip = "0.0.0.0"
		vt.addrFrom.port = 0
		self.send_message(vt, True)

		print "connecting"
		try:
			self.connect((dstaddr, dstport))
		except:
			self.handle_close()
	def handle_connect(self):
		print "connected"
		self.state = "connected"
		#send version msg
#		t = msg_version()
#		t.addrTo.ip = self.dstaddr
#		t.addrTo.port = self.dstport
#		t.addrFrom.ip = "0.0.0.0"
#		t.addrFrom.port = 0
#		self.send_message(t)
	def handle_close(self):
		print "close"
		self.state = "closed"
		self.recvbuf = ""
		self.sendbuf = ""
		try:
			self.close()
		except:
			pass
	def handle_read(self):
		try:
			t = self.recv(8192)
		except:
			self.handle_close()
			return
		if len(t) == 0:
			self.handle_close()
			return
		self.recvbuf += t
		self.got_data()
	def readable(self):
		return True
	def writable(self):
		return (len(self.sendbuf) > 0)
	def handle_write(self):
		try:
			sent = self.send(self.sendbuf)
		except:
			self.handle_close()
			return
		self.sendbuf = self.sendbuf[sent:]
	def got_data(self):
		while True:
			if len(self.recvbuf) < 4:
				return
			if self.recvbuf[:4] != "\xf9\xbe\xb4\xd9":
				raise ValueError("got garbage %s" % repr(self.recvbuf))
			if self.ver_recv < 209:
				if len(self.recvbuf) < 4 + 12 + 4:
					return
				command = self.recvbuf[4:4+12].split("\x00", 1)[0]
				msglen = struct.unpack("<i", self.recvbuf[4+12:4+12+4])[0]
				checksum = None
				if len(self.recvbuf) < 4 + 12 + 4 + msglen:
					return
				msg = self.recvbuf[4+12+4:4+12+4+msglen]
				self.recvbuf = self.recvbuf[4+12+4+msglen:]
			else:
				if len(self.recvbuf) < 4 + 12 + 4 + 4:
					return
				command = self.recvbuf[4:4+12].split("\x00", 1)[0]
				msglen = struct.unpack("<i", self.recvbuf[4+12:4+12+4])[0]
				checksum = self.recvbuf[4+12+4:4+12+4+4]
				if len(self.recvbuf) < 4 + 12 + 4 + 4 + msglen:
					return
				msg = self.recvbuf[4+12+4+4:4+12+4+4+msglen]
				th = SHA256.new(msg).digest()
				h = SHA256.new(th).digest()
				if checksum != h[:4]:
					raise ValueError("got bad checksum %s" % repr(self.recvbuf))
				self.recvbuf = self.recvbuf[4+12+4+4+msglen:]
			if command in self.messagemap:
				f = cStringIO.StringIO(msg)
				t = self.messagemap[command]()
				t.deserialize(f)
				self.got_message(t)
			else:
				print "UNKNOWN COMMAND", command, repr(msg)
	def send_message(self, message, pushbuf=False):
		if self.state != "connected" and not pushbuf:
			return
		print "send %s" % repr(message)
		command = message.command
		data = message.serialize()
		tmsg = "\xf9\xbe\xb4\xd9"
		tmsg += command
		tmsg += "\x00" * (12 - len(command))
		tmsg += struct.pack("<I", len(data))
		if self.ver_send >= 209:
			th = SHA256.new(data).digest()
			h = SHA256.new(th).digest()
			tmsg += h[:4]
		tmsg += data
		self.sendbuf += tmsg
		self.last_sent = time.time()
	def got_message(self, message):
		if self.last_sent + 30 * 60 < time.time():
			self.send_message(msg_ping())
		print "recv %s" % repr(message)
		if message.command  == "version":
			if message.nVersion >= 209:
				self.send_message(msg_verack())
			self.ver_send = min(MY_VERSION, message.nVersion)
			if message.nVersion < 209:
				self.ver_recv = self.ver_send
		elif message.command == "verack":
			self.ver_recv = self.ver_send
		elif message.command == "inv":
			want = msg_getdata()
			for i in message.inv:
				if i.type == 1:
					want.inv.append(i)
				elif i.type == 2:
					want.inv.append(i)
			if len(want.inv):
				self.send_message(want)
		elif message.command == "tx":
			if not message.tx.is_valid():
				print "invalid TX"
		elif message.command == "block":
			if not message.block.is_valid():
				print "invalid block"
			else:
				print "WOOOOOO!!!!!  We have a block!"

c = NodeConn("127.0.0.1", 8333)
asyncore.loop()
