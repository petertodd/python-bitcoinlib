
#
# messages.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import struct
import time
import random
from defs import *
from datatypes import *

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

class msg_alert(object):
	command = "alert"
	def __init__(self):
		self.alert = CAlert()
	def deserialize(self, f):
		self.alert = CAlert()
		self.alert.deserialize(f)
	def serialize(self):
		r = ""
		r += self.alert.serialize()
		return r
	def __repr__(self):
		return "msg_alert(alert=%s)" % (repr(self.alert), )

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


