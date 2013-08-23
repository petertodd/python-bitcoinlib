
#
# core.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from __future__ import absolute_import, division, print_function, unicode_literals

import struct
import socket
import binascii
import time
import hashlib
from bitcoin.serialize import *
from bitcoin.coredefs import *
from bitcoin.script import CScript

class CAddress(object):
    def __init__(self, protover=PROTO_VERSION):
        self.protover = protover
        self.nTime = 0
        self.nServices = 1
        self.pchReserved = b"\x00" * 10 + b"\xff" * 2
        self.ip = "0.0.0.0"
        self.port = 0
    def deserialize(self, f):
        if self.protover >= CADDR_TIME_VERSION:
            self.nTime = struct.unpack(b"<I", f.read(4))[0]
        self.nServices = struct.unpack(b"<Q", f.read(8))[0]
        self.pchReserved = f.read(12)
        self.ip = socket.inet_ntoa(f.read(4))
        self.port = struct.unpack(b">H", f.read(2))[0]
    def serialize(self):
        r = b""
        if self.protover >= CADDR_TIME_VERSION:
            r += struct.pack(b"<I", self.nTime)
        r += struct.pack(b"<Q", self.nServices)
        r += self.pchReserved
        r += socket.inet_aton(self.ip)
        r += struct.pack(b">H", self.port)
        return r
    def __repr__(self):
        return "CAddress(nTime=%d nServices=%i ip=%s port=%i)" % (self.nTime, self.nServices, self.ip, self.port)

class CInv(object):
    typemap = {
        0: "Error",
        1: "TX",
        2: "Block"}
    def __init__(self):
        self.type = 0
        self.hash = 0
    def deserialize(self, f):
        self.type = struct.unpack(b"<i", f.read(4))[0]
        self.hash = deser_uint256(f)
    def serialize(self):
        r = b""
        r += struct.pack(b"<i", self.type)
        r += ser_uint256(self.hash)
        return r
    def __repr__(self):
        return "CInv(type=%s hash=%064x)" % (self.typemap[self.type], self.hash)

class CBlockLocator(object):
    def __init__(self):
        self.nVersion = PROTO_VERSION
        self.vHave = []
    def deserialize(self, f):
        self.nVersion = struct.unpack(b"<i", f.read(4))[0]
        self.vHave = deser_uint256_vector(f)
    def serialize(self):
        r = b""
        r += struct.pack(b"<i", self.nVersion)
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
        self.n = struct.unpack(b"<I", f.read(4))[0]
    def serialize(self):
        r = b""
        r += ser_uint256(self.hash)
        r += struct.pack(b"<I", self.n)
        return r
    def set_null(self):
        self.hash = 0
        self.n = 0xffffffff
    def is_null(self):
        return ((self.hash == 0) and (self.n == 0xffffffff))
    def copy(self, old_outpt):
        self.hash = old_outpt.hash
        self.n = old_outpt.n
    def __repr__(self):
        return "COutPoint(hash=%064x n=%i)" % (self.hash, self.n)

class CTxIn(object):
    def __init__(self):
        self.prevout = COutPoint()
        self.scriptSig = b""
        self.nSequence = 0xffffffff
    def deserialize(self, f):
        self.prevout = COutPoint()
        self.prevout.deserialize(f)
        self.scriptSig = deser_string(f)
        self.nSequence = struct.unpack(b"<I", f.read(4))[0]
    def serialize(self):
        r = b""
        r += self.prevout.serialize()
        r += ser_string(self.scriptSig)
        r += struct.pack(b"<I", self.nSequence)
        return r
    def is_final(self):
        return (self.nSequence == 0xffffffff)
    def is_valid(self):
        script = CScript()
        if not script.tokenize(self.scriptSig):
            return False
        return True
    def copy(self, old_txin):
        self.prevout = COutPoint()
        self.prevout.copy(old_txin.prevout)
        self.scriptSig = old_txin.scriptSig
        self.nSequence = old_txin.nSequence
    def __repr__(self):
        return "CTxIn(prevout=%s scriptSig=%s nSequence=%i)" % (repr(self.prevout), binascii.hexlify(self.scriptSig), self.nSequence)

class CTxOut(object):
    def __init__(self):
        self.nValue = -1
        self.scriptPubKey = b""
    def deserialize(self, f):
        self.nValue = struct.unpack(b"<q", f.read(8))[0]
        self.scriptPubKey = deser_string(f)
    def serialize(self):
        r = b""
        r += struct.pack(b"<q", self.nValue)
        r += ser_string(self.scriptPubKey)
        return r
    def is_valid(self):
        if not MoneyRange(self.nValue):
            return False
        script = CScript()
        if not script.tokenize(self.scriptPubKey):
            return False
        return True
    def copy(self, old_txout):
        self.nValue = old_txout.nValue
        self.scriptPubKey = old_txout.scriptPubKey
    def __repr__(self):
        return "CTxOut(nValue=%i.%08i scriptPubKey=%s)" % (self.nValue // 100000000, self.nValue % 100000000, binascii.hexlify(self.scriptPubKey))

class CTransaction(object):
    def __init__(self):
        # serialized
        self.nVersion = 1
        self.vin = []
        self.vout = []
        self.nLockTime = 0

        # used at runtime
        self.sha256 = None
        self.nFeesPaid = 0
        self.dFeePerKB = None
        self.dPriority = None
        self.ser_size = 0
    def deserialize(self, f):
        self.nVersion = struct.unpack(b"<i", f.read(4))[0]
        self.vin = deser_vector(f, CTxIn)
        self.vout = deser_vector(f, CTxOut)
        self.nLockTime = struct.unpack(b"<I", f.read(4))[0]
    def serialize(self):
        r = b""
        r += struct.pack(b"<i", self.nVersion)
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        r += struct.pack(b"<I", self.nLockTime)
        return r
    def calc_sha256(self):
        if self.sha256 is None:
            self.sha256 = Hash(self.serialize())
    def is_valid(self):
        self.calc_sha256()
        if not self.is_coinbase():
            for tin in self.vin:
                if not tin.is_valid():
                    return False
        for tout in self.vout:
            if not tout.is_valid():
                return False
        return True
    def is_final(self):
        for tin in self.vin:
            if not tin.is_final():
                return False
        return True
    def is_coinbase(self):
        return len(self.vin) == 1 and self.vin[0].prevout.is_null()

    def copy(self, old_tx):
        self.nVersion = old_tx.nVersion
        self.vin = []
        self.vout = []
        self.nLockTime = old_tx.nLockTime
        self.sha256 = None

        for old_txin in old_tx.vin:
            txin = CTxIn()
            txin.copy(old_txin)
            self.vin.append(txin)

        for old_txout in old_tx.vout:
            txout = CTxOut()
            txout.copy(old_txout)
            self.vout.append(txout)

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
        self.nVersion = struct.unpack(b"<i", f.read(4))[0]
        self.hashPrevBlock = deser_uint256(f)
        self.hashMerkleRoot = deser_uint256(f)
        self.nTime = struct.unpack(b"<I", f.read(4))[0]
        self.nBits = struct.unpack(b"<I", f.read(4))[0]
        self.nNonce = struct.unpack(b"<I", f.read(4))[0]
        self.vtx = deser_vector(f, CTransaction)
    def serialize_hdr(self):
        r = b""
        r += struct.pack(b"<i", self.nVersion)
        r += ser_uint256(self.hashPrevBlock)
        r += ser_uint256(self.hashMerkleRoot)
        r += struct.pack(b"<I", self.nTime)
        r += struct.pack(b"<I", self.nBits)
        r += struct.pack(b"<I", self.nNonce)
        return r
    def serialize(self):
        r = self.serialize_hdr()
        r += ser_vector(self.vtx)
        return r
    def calc_sha256(self):
        if self.sha256 is None:
            self.sha256 = Hash(self.serialize_hdr())
    def calc_merkle(self):
        hashes = []
        for tx in self.vtx:
            if not tx.is_valid():
                return None
            tx.calc_sha256()
            hashes.append(ser_uint256(tx.sha256))
        while len(hashes) > 1:
            newhashes = []
            for i in range(0, len(hashes), 2):
                i2 = min(i+1, len(hashes)-1)
                newhashes.append(hashlib.sha256(hashlib.sha256(hashes[i] + hashes[i2]).digest()).digest())
            hashes = newhashes
        return uint256_from_str(hashes[0])
    def is_valid(self):
        self.calc_sha256()
        target = uint256_from_compact(self.nBits)
        if self.sha256 > target:
            return False
        if self.calc_merkle() != self.hashMerkleRoot:
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
        self.strComment = b""
        self.strStatusBar = b""
        self.strReserved = b""
    def deserialize(self, f):
        self.nVersion = struct.unpack(b"<i", f.read(4))[0]
        self.nRelayUntil = struct.unpack(b"<q", f.read(8))[0]
        self.nExpiration = struct.unpack(b"<q", f.read(8))[0]
        self.nID = struct.unpack(b"<i", f.read(4))[0]
        self.nCancel = struct.unpack(b"<i", f.read(4))[0]
        self.setCancel = deser_int_vector(f)
        self.nMinVer = struct.unpack(b"<i", f.read(4))[0]
        self.nMaxVer = struct.unpack(b"<i", f.read(4))[0]
        self.setSubVer = deser_string_vector(f)
        self.nPriority = struct.unpack(b"<i", f.read(4))[0]
        self.strComment = deser_string(f)
        self.strStatusBar = deser_string(f)
        self.strReserved = deser_string(f)
    def serialize(self):
        r = b""
        r += struct.pack(b"<i", self.nVersion)
        r += struct.pack(b"<q", self.nRelayUntil)
        r += struct.pack(b"<q", self.nExpiration)
        r += struct.pack(b"<i", self.nID)
        r += struct.pack(b"<i", self.nCancel)
        r += ser_int_vector(self.setCancel)
        r += struct.pack(b"<i", self.nMinVer)
        r += struct.pack(b"<i", self.nMaxVer)
        r += ser_string_vector(self.setSubVer)
        r += struct.pack(b"<i", self.nPriority)
        r += ser_string(self.strComment)
        r += ser_string(self.strStatusBar)
        r += ser_string(self.strReserved)
        return r
    def __repr__(self):
        return "CUnsignedAlert(nVersion %d, nRelayUntil %d, nExpiration %d, nID %d, nCancel %d, nMinVer %d, nMaxVer %d, nPriority %d, strComment %s, strStatusBar %s, strReserved %s)" % (self.nVersion, self.nRelayUntil, self.nExpiration, self.nID, self.nCancel, self.nMinVer, self.nMaxVer, self.nPriority, self.strComment, self.strStatusBar, self.strReserved)

class CAlert(object):
    def __init__(self):
        self.vchMsg = b""
        self.vchSig = b""
    def deserialize(self, f):
        self.vchMsg = deser_string(f)
        self.vchSig = deser_string(f)
    def serialize(self):
        r = b""
        r += ser_string(self.vchMsg)
        r += ser_string(self.vchSig)
        return r
    def __repr__(self):
        return "CAlert(vchMsg.sz %d, vchSig.sz %d)" % (len(self.vchMsg), len(self.vchSig))

