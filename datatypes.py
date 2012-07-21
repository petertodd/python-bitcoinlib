
import struct
import socket
import binascii
from Crypto.Hash import SHA256
from serialize import *

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

class CUnsignedAlert(object):
	def __init__(self):
		self.nVersion = 1
		self.nRelayUntil = 0
		self.nExpiration = 0
		self.nID = 0
		self.nCancel = 0
		self.setCancel = []
		self.nMinVer = 0
		self.nMaxVer = 0
		self.setSubVer = []
		self.nPriority = 0
		self.strComment = ""
		self.strStatusBar = ""
		self.strReserved = ""
	def deserialize(self, f):
		self.nVersion = struct.unpack("<i", f.read(4))[0]
		self.nRelayUntil = struct.unpack("<q", f.read(8))[0]
		self.nExpiration = struct.unpack("<q", f.read(8))[0]
		self.nID = struct.unpack("<i", f.read(4))[0]
		self.nCancel = struct.unpack("<i", f.read(4))[0]
		self.setCancel = deser_int_vector(f)
		self.nMinVer = struct.unpack("<i", f.read(4))[0]
		self.nMaxVer = struct.unpack("<i", f.read(4))[0]
		self.setSubVer = deser_string_vector(f)
		self.nPriority = struct.unpack("<i", f.read(4))[0]
		self.strComment = deser_string(f)
		self.strStatusBar = deser_string(f)
		self.strReserved = deser_string(f)
	def serialize(self):
		r = ""
		r += struct.pack("<i", self.nVersion)
		r += struct.pack("<q", self.nRelayUntil)
		r += struct.pack("<q", self.nExpiration)
		r += struct.pack("<i", self.nID)
		r += struct.pack("<i", self.nCancel)
		r += ser_int_vector(self.setCancel)
		r += struct.pack("<i", self.nMinVer)
		r += struct.pack("<i", self.nMaxVer)
		r += ser_string_vector(self.setSubVer)
		r += struct.pack("<i", self.nPriority)
		r += ser_string(self.strComment)
		r += ser_string(self.strStatusBar)
		r += ser_string(self.strReserved)
		return r
	def __repr__(self):
		return "CUnsignedAlert(nVersion %d, nRelayUntil %d, nExpiration %d, nID %d, nCancel %d, nMinVer %d, nMaxVer %d, nPriority %d, strComment %s, strStatusBar %s, strReserved %s)" % (self.nVersion, self.nRelayUntil, self.nExpiration, self.nID, self.nCancel, self.nMinVer, self.nMaxVer, self.nPriority, self.strComment, self.strStatusBar, self.strReserved)

class CAlert(object):
	def __init__(self):
		self.vchMsg = ""
		self.vchSig = ""
	def deserialize(self, f):
		self.vchMsg = deser_string(f)
		self.vchSig = deser_string(f)
	def serialize(self):
		r = ""
		r += ser_string(self.vchMsg)
		r += ser_string(self.vchSig)
		return r
	def __repr__(self):
		return "CAlert(vchMsg.sz %d, vchSig.sz %d)" % (len(self.vchMsg), len(self.vchSig))

