
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
import hashlib
import bitcoin.base58 as base58
import bitcoin.script as script

from bitcoin.serialize import *
from bitcoin.coredefs import *

def x(h):
    """Convert a hex string to bytes"""
    import sys
    if sys.version > '3':
        return binascii.unhexlify(h.encode('utf8'))
    else:
        return binascii.unhexlify(h)

def b2x(b):
    """Convert bytes to a hex string"""
    if sys.version > '3':
        return binascii.hexlify(b).decode('utf8')
    else:
        return binascii.hexlify(b)

def lx(h):
    """Convert a little-endian hex string to bytes

    Lets you write uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    import sys
    if sys.version > '3':
        return binascii.unhexlify(h.encode('utf8'))[::-1]
    else:
        return binascii.unhexlify(h)[::-1]

def b2lx(b):
    """Convert bytes to a little-endian hex string

    Lets you show uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    if sys.version > '3':
        return binascii.hexlify(b[::-1]).decode('utf8')
    else:
        return binascii.hexlify(b[::-1])

def str_money_value(value):
    """Convert an integer money value to a fixed point string"""
    r = '%i.%08i' % (value // 100000000, value % 100000000)
    r = r.rstrip('0')
    if r[-1] == '.':
        r += '0'
    return r

class CBitcoinAddress(base58.CBase58Data):
    """A Bitcoin address"""
    PUBKEY_ADDRESS = 0
    SCRIPT_ADDRESS = 5
    PUBKEY_ADDRESS_TEST = 111
    SCRIPT_ADDRESS_TEST = 196

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        if self.nVersion in (self.PUBKEY_ADDRESS, self.PUBKEY_ADDRESS_TEST):
            return script.CScript([script.OP_DUP, script.OP_HASH160, self, script.OP_EQUALVERIFY, script.OP_CHECKSIG])

        elif self.nVersion in (self.SCRIPT_ADDRESS, self.SCRIPT_ADDRESS_TEST):
            return script.CScript([script.OP_HASH160, self, script.OP_EQUAL])

        else:
            raise ValueError("CBitcoinAddress: Don't know how to convert version %d to a scriptPubKey" % self.nVersion)


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
            self.nTime = struct.unpack(b"<I", ser_read(f,4))[0]
        self.nServices = struct.unpack(b"<Q", ser_read(f,8))[0]
        self.pchReserved = ser_read(f,12)
        self.ip = socket.inet_ntoa(ser_read(f,4))
        self.port = struct.unpack(b">H", ser_read(f,2))[0]
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
        self.type = struct.unpack(b"<i", ser_read(f,4))[0]
        self.hash = ser_read(f,32)
    def serialize(self):
        r = b""
        r += struct.pack(b"<i", self.type)
        r += self.hash
        return r
    def __repr__(self):
        return "CInv(type=%s hash=%064x)" % (self.typemap[self.type], self.hash)

class CBlockLocator(object):
    def __init__(self):
        self.nVersion = PROTO_VERSION
        self.vHave = []
    def deserialize(self, f):
        self.nVersion = struct.unpack(b"<i", ser_read(f,4))[0]
        self.vHave = deser_uint256_vector(f)
    def serialize(self):
        r = b""
        r += struct.pack(b"<i", self.nVersion)
        r += ser_uint256_vector(self.vHave)
        return r
    def __repr__(self):
        return "CBlockLocator(nVersion=%i vHave=%s)" % (self.nVersion, repr(self.vHave))

class COutPoint(Serializable):
    """The combination of a transaction hash and an index n into its vout"""
    __slots__ = ['hash', 'n']

    def __init__(self, hash=b'\x00'*32, n=0xffffffff):
        if not len(hash) == 32:
            raise ValueError('COutPoint: hash must be exactly 32 bytes; got %d bytes' % len(hash))
        self.hash = hash
        if not (0 <= n <= 0xffffffff):
            raise ValueError('COutPoint: n must be in range 0x0 to 0xffffffff; got %x' % n)
        self.n = n

    @classmethod
    def stream_deserialize(cls, f):
        hash = ser_read(f,32)
        n = struct.unpack(b"<I", ser_read(f,4))[0]
        return cls(hash, n)

    def stream_serialize(self, f):
        assert len(self.hash) == 32
        f.write(self.hash)
        f.write(struct.pack(b"<I", self.n))

    def is_null(self):
        return ((self.hash == b'\x00'*32) and (self.n == 0xffffffff))

    def __repr__(self):
        if self.is_null():
            return 'COutPoint()'
        else:
            return 'COutPoint(lx(%r), %i)' % (b2lx(self.hash), self.n)

class CTxIn(Serializable):
    """An input of a transaction

    Contains the location of the previous transaction's output that it claims,
    and a signature that matches the output's public key.
    """
    __slots__ = ['prevout', 'scriptSig', 'nSequence']

    def __init__(self, prevout=None, scriptSig=script.CScript(), nSequence = 0xffffffff):
        if prevout is None:
            prevout = COutPoint()
        self.prevout = prevout
        self.scriptSig = scriptSig
        if not (0 <= nSequence <= 0xffffffff):
            raise ValueError('CTxIn: nSequence must be an integer between 0x0 and 0xffffffff; got %x' % nSequence)
        self.nSequence = nSequence

    @classmethod
    def stream_deserialize(cls, f):
        prevout = COutPoint.stream_deserialize(f)
        scriptSig = script.CScript(BytesSerializer.stream_deserialize(f))
        nSequence = struct.unpack(b"<I", ser_read(f,4))[0]
        return cls(prevout, scriptSig, nSequence)

    def stream_serialize(self, f):
        self.prevout.stream_serialize(f)
        BytesSerializer.stream_serialize(self.scriptSig, f)
        f.write(struct.pack(b"<I", self.nSequence))

    def is_final(self):
        return (self.nSequence == 0xffffffff)

    def __repr__(self):
        return "CTxIn(%s, %s, 0x%x)" % (repr(self.prevout), repr(self.scriptSig), self.nSequence)

class CTxOut(Serializable):
    """An output of a transaction

    Contains the public key that the next input must be able to sign with to
    claim it.
    """
    __slots__ = ['nValue', 'scriptPubKey']

    def __init__(self, nValue=-1, scriptPubKey=script.CScript()):
        self.nValue = int(nValue)
        self.scriptPubKey = scriptPubKey

    @classmethod
    def stream_deserialize(cls, f):
        nValue = struct.unpack(b"<q", ser_read(f,8))[0]
        scriptPubKey = script.CScript(BytesSerializer.stream_deserialize(f))
        return cls(nValue, scriptPubKey)

    def stream_serialize(self, f):
        f.write(struct.pack(b"<q", self.nValue))
        BytesSerializer.stream_serialize(self.scriptPubKey, f)

    def is_valid(self):
        if not MoneyRange(self.nValue):
            return False
        if not self.scriptPubKey.is_valid():
            return False
        return True

    def __repr__(self):
        if self.nValue >= 0:
            return "CTxOut(%s*COIN, %r)" % (str_money_value(self.nValue), self.scriptPubKey)
        else:
            return "CTxOut(%d, %r)" % (self.nValue, self.scriptPubKey)

class CTransaction(Serializable):
    """A transaction"""
    __slots__ = ['nVersion', 'vin', 'vout', 'nLockTime']

    def __init__(self, vin=None, vout=None, nLockTime=0, nVersion=1):
        if vin is None:
            vin = []
        if vout is None:
            vout = []
        self.nVersion = nVersion
        self.vin = vin
        self.vout = vout
        if not (0 <= nLockTime <= 0xffffffff):
            raise ValueError('CTransaction: nLockTime must be in range 0x0 to 0xffffffff; got %x' % nLockTime)
        self.nLockTime = nLockTime

    @classmethod
    def stream_deserialize(cls, f):
        nVersion = struct.unpack(b"<i", ser_read(f,4))[0]
        vin = VectorSerializer.stream_deserialize(CTxIn, f)
        vout = VectorSerializer.stream_deserialize(CTxOut, f)
        nLockTime = struct.unpack(b"<I", ser_read(f,4))[0]
        return cls(vin, vout, nLockTime, nVersion)

    def stream_serialize(self, f):
        f.write(struct.pack(b"<i", self.nVersion))
        VectorSerializer.stream_serialize(CTxIn, self.vin, f)
        VectorSerializer.stream_serialize(CTxOut, self.vout, f)
        f.write(struct.pack(b"<I", self.nLockTime))

    def is_coinbase(self):
        return len(self.vin) == 1 and self.vin[0].prevout.is_null()

    def __repr__(self):
        return "CTransaction(%r, %r, %i, %i)" % (self.vin, self.vout, self.nLockTime, self.nVersion)

class CBlockHeader(Serializable):
    """A block header"""
    __slots__ = ['nVersion', 'hashPrevBlock', 'hashMerkleRoot', 'nTime', 'nBits', 'nBits']

    def __init__(self, nVersion=2, hashPrevBlock=None, hashMerkleRoot=None, nTime=None, nBits=None, nNonce=None):
        self.nVersion = nVersion
        assert len(hashPrevBlock) == 32
        self.hashPrevBlock = hashPrevBlock
        assert len(hashMerkleRoot) == 32
        self.hashMerkleRoot = hashMerkleRoot
        self.nTime = nTime
        self.nBits = nBits
        self.nNonce = nNonce

    @classmethod
    def stream_deserialize(cls, f):
        nVersion = struct.unpack(b"<i", ser_read(f,4))[0]
        hashPrevBlock = ser_read(f,32)
        hashMerkleRoot = ser_read(f,32)
        nTime = struct.unpack(b"<I", ser_read(f,4))[0]
        nBits = struct.unpack(b"<I", ser_read(f,4))[0]
        nNonce = struct.unpack(b"<I", ser_read(f,4))[0]
        return cls(nVersion, hashPrevBlock, hashMerkleRoot, nTime, nBits, nNonce)

    def stream_serialize(self, f):
        f.write(struct.pack(b"<i", self.nVersion))
        assert len(self.hashPrevBlock) == 32
        f.write(self.hashPrevBlock)
        assert len(self.hashMerkleRoot) == 32
        f.write(self.hashMerkleRoot)
        f.write(struct.pack(b"<I", self.nTime))
        f.write(struct.pack(b"<I", self.nBits))
        f.write(struct.pack(b"<I", self.nNonce))

    def is_pow_valid(self):
        """Return True if the proof-of-work is valid"""
        hash = Hash(self.serialize())
        target = uint256_from_compact(self.nBits)
        return hash < target

    @staticmethod
    def calc_difficulty(nBits):
        """Calculate difficulty from nBits target"""
        nShift = (nBits >> 24) & 0xff
        dDiff = float(0x0000ffff) / float(nBits & 0x00ffffff)
        while nShift < 29:
            dDiff *= 256.0
            nShift += 1
        while nShift > 29:
            dDiff /= 256.0
            nShift -= 1
        return dDiff
    difficulty = property(lambda self: CBlockHeader.calc_difficulty(self.nBits))

    def __repr__(self):
        return "%s(%i, lx(%s), lx(%s), %s, 0x%08x, 0x%08x)" % \
                (self.__class__.__name__, self.nVersion, b2lx(self.hashPrevBlock), b2lx(self.hashMerkleRoot),
                 self.nTime, self.nBits, self.nNonce)

class CBlock(CBlockHeader):
    """A block including all transactions in it"""
    __slots__ = ['vtx']

    def __init__(self, nVersion=2, hashPrevBlock=None, hashMerkleRoot=None, nTime=None, nBits=None, nNonce=None, vtx=None):
        super(CBlock, self).__init__(nVersion, hashPrevBlock, hashMerkleRoot, nTime, nBits, nNonce)
        if not vtx:
            vtx = []
        self.vtx = vtx

    @classmethod
    def stream_deserialize(cls, f):
        self = super(CBlock, cls).stream_deserialize(f)
        self.vtx = VectorSerializer.stream_deserialize(CTransaction, f)
        return self

    def stream_serialize(self, f):
        super(CBlock, self).stream_serialize(f)
        VectorSerializer.stream_serialize(CTransaction, self.vtx, f)

    @staticmethod
    def calc_merkle_root_from_hashes(hashes):
        while len(hashes) > 1:
            newhashes = []
            for i in range(0, len(hashes), 2):
                i2 = min(i+1, len(hashes)-1)
                newhashes.append(hashlib.sha256(hashlib.sha256(hashes[i] + hashes[i2]).digest()).digest())
            hashes = newhashes
        return hashes[0]

    def calc_merkle_root(self):
        hashes = []
        for tx in self.vtx:
            hashes.append(Hash(tx.serialize()))
        return CBlock.calc_merkle_root_from_hashes(hashes)

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
        self.nVersion = struct.unpack(b"<i", ser_read(f,4))[0]
        self.nRelayUntil = struct.unpack(b"<q", ser_read(f,8))[0]
        self.nExpiration = struct.unpack(b"<q", ser_read(f,8))[0]
        self.nID = struct.unpack(b"<i", ser_read(f,4))[0]
        self.nCancel = struct.unpack(b"<i", ser_read(f,4))[0]
        self.setCancel = deser_int_vector(f)
        self.nMinVer = struct.unpack(b"<i", ser_read(f,4))[0]
        self.nMaxVer = struct.unpack(b"<i", ser_read(f,4))[0]
        self.setSubVer = deser_string_vector(f)
        self.nPriority = struct.unpack(b"<i", ser_read(f,4))[0]
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

