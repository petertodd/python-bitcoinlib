
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

from .script import CScript

from .serialize import *

# Core definitions
COIN = 100000000
MAX_MONEY = 21000000 * COIN
MAX_BLOCK_SIZE = 1000000
MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50

PROTO_VERSION = 60002
MIN_PROTO_VERSION = 209

def MoneyRange(nValue):
        return 0<= nValue <= MAX_MONEY

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


class ValidationError(Exception):
    """Base class for all blockchain validation errors

    Everything that is related to validating the blockchain, blocks,
    transactions, scripts, etc. is derived from this class.
    """


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

    def __init__(self, prevout=None, scriptSig=CScript(), nSequence = 0xffffffff):
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

    def get_header(self):
        """Return the block header

        Returned header is a new object.
        """
        return CBlockHeader(nVersion=self.nVersion,
                            hashPrevBlock=self.hashPrevBlock,
                            hashMerkleRoot=self.hashMerkleRoot,
                            nTime=self.nTime,
                            nBits=self.nBits,
                            nNonce=self.nNonce)

    def calc_merkle_root(self):
        hashes = []
        for tx in self.vtx:
            hashes.append(Hash(tx.serialize()))
        return CBlock.calc_merkle_root_from_hashes(hashes)


class CoreChainParams(object):
    """Define consensus-critical parameters of a given instance of the Bitcoin system"""
    GENESIS_BLOCK = None
    PROOF_OF_WORK_LIMIT = None
    SUBSIDY_HALVING_INTERVAL = None
    NAME = None

class CoreMainParams(CoreChainParams):
    NAME = 'mainnet'
    GENESIS_BLOCK = CBlock.deserialize(x('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000'))
    SUBSIDY_HALVING_INTERVAL = 210000
    PROOF_OF_WORK_LIMIT = 2**256-1 >> 32

class CoreTestNetParams(CoreMainParams):
    NAME = 'testnet'
    GENESIS_BLOCK = CBlock.deserialize(x('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000'))

class CoreRegTestParams(CoreTestNetParams):
    NAME = 'regtest'
    GENESIS_BLOCK = CBlock.deserialize(x('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000'))
    SUBSIDY_HALVING_INTERVAL = 150
    PROOF_OF_WORK_LIMIT = 2**256-1 >> 1

"""Master global setting for what core chain params we're using"""
coreparams = CoreMainParams()

def _SelectCoreParams(name):
    """Select the core chain parameters to use

    Don't use this directly, use bitcoin.SelectParams() instead so both
    consensus-critical and general parameters are set properly.
    """
    global coreparams
    if name == 'mainnet':
        coreparams = CoreMainParams()
    elif name == 'testnet':
        coreparams = CoreTestNetParams()
    elif name == 'regtest':
        coreparams = CoreRegTestParams()
    else:
        raise ValueError('Unknown chain %r' % name)


class CheckTransactionError(ValidationError):
    pass

def CheckTransaction(tx):
    """Basic transaction checks that don't depend on any context.

    Raises CheckTransactionError
    """

    if not tx.vin:
        raise CheckTransactionError("CheckTransaction() : vin empty")
    if not tx.vout:
        raise CheckTransactionError("CheckTransaction() : vout empty")

    # Size limits
    if len(tx.serialize()) > MAX_BLOCK_SIZE:
        raise CheckTransactionError("CheckTransaction() : size limits failed")

    # Check for negative or overflow output values
    nValueOut = 0
    for txout in tx.vout:
        if txout.nValue < 0:
            raise CheckTransactionError("CheckTransaction() : txout.nValue negative")
        if txout.nValue > MAX_MONEY:
            raise CheckTransactionError("CheckTransaction() : txout.nValue too high")
        nValueOut += txout.nValue
        if not MoneyRange(nValueOut):
            raise CheckTransactionError("CheckTransaction() : txout total out of range")

    # Check for duplicate inputs
    vin_outpoints = set()
    for txin in tx.vin:
        if txin.prevout in vin_outpoints:
            raise CheckTransactionError("CheckTransaction() : duplicate inputs")
        vin_outpoints.add(txin.prevout)

    if tx.is_coinbase():
        if not (2 <= len(tx.vin[0].scriptSig) <= 100):
            raise CheckTransactionError("CheckTransaction() : coinbase script size")

    else:
        for txin in tx.vin:
            if txin.prevout.is_null():
                raise CheckTransactionError("CheckTransaction() : prevout is null")





class CheckBlockHeaderError(ValidationError):
    pass

class CheckProofOfWorkError(CheckBlockHeaderError):
    pass

def CheckProofOfWork(hash, nBits):
    """Check a proof-of-work

    Raises CheckProofOfWorkError
    """
    target = uint256_from_compact(nBits)

    # Check range
    if not (0 < target <= coreparams.PROOF_OF_WORK_LIMIT):
        raise CheckProofOfWorkError("CheckProofOfWork() : nBits below minimum work")

    # Check proof of work matches claimed amount
    hash = uint256_from_str(hash)
    if hash > target:
        raise CheckProofOfWorkError("CheckProofOfWork() : hash doesn't match nBits")


def CheckBlockHeader(block_header, fCheckPoW = True, cur_time=None):
    """Context independent CBlockHeader checks.

    fCheckPoW - Check proof-of-work.
    cur_time  - Current time. Defaults to time.time()

    Raises CBlockHeaderError if block header is invalid.
    """
    if cur_time is None:
        cur_time = time.time()

    # Check proof-of-work matches claimed amount
    if fCheckPoW:
        CheckProofOfWork(Hash(block_header.serialize()), block_header.nBits)

    # Check timestamp
    if block_header.nTime > cur_time + 2 * 60 * 60:
        raise CheckBlockHeaderError("CheckBlockHeader() : block timestamp too far in the future")


class CheckBlockError(CheckBlockHeaderError):
    pass

def GetLegacySigOpCount(tx):
    nSigOps = 0
    for txin in tx.vin:
        nSigOps += txin.scriptSig.GetSigOpCount(False)
    for txout in tx.vout:
        nSigOps += txout.scriptPubKey.GetSigOpCount(False)
    return nSigOps


def CheckBlock(block, fCheckPoW = True, fCheckMerkleRoot = True, cur_time=None):
    """Context independent CBlock checks.

    CheckBlockHeader() is called first, which may raise a CheckBlockHeader
    exception, followed the block tests. CheckTransaction() is called for every
    transaction.

    fCheckPoW        - Check proof-of-work.
    fCheckMerkleRoot - Check merkle root matches transactions.
    cur_time         - Current time. Defaults to time.time()
    """

    # Block header checks
    CheckBlockHeader(block.get_header(), fCheckPoW=fCheckPoW, cur_time=cur_time)

    # Size limits
    if not block.vtx:
        raise CheckBlockError("CheckBlock() : vtx empty")
    if len(block.serialize()) > MAX_BLOCK_SIZE:
        raise CheckBlockError("CheckBlock() : block larger than MAX_BLOCK_SIZE")

    # First transaction must be coinbase
    if not block.vtx[0].is_coinbase():
        raise CheckBlockError("CheckBlock() : first tx is not coinbase")

    # Check rest of transactions. Note how we do things "all at once", which
    # could potentially be a consensus failure if there was some obscure bug.

    # For unique txid uniqueness testing. If coinbase tx is included twice
    # it'll be caught by the "more than one coinbase" test.
    unique_txids = set()
    nSigOps = 0
    for tx in block.vtx[1:]:
        if tx.is_coinbase():
            raise CheckBlockError("CheckBlock() : more than one coinbase")

        CheckTransaction(tx)

        txid = Hash(tx.serialize())
        if txid in unique_txids:
            raise CheckBlockError("CheckBlock() : duplicate transaction")
        unique_txids.add(txid)

        nSigOps += GetLegacySigOpCount(tx)
        if nSigOps > MAX_BLOCK_SIGOPS:
            raise CheckBlockError("CheckBlock() : out-of-bounds SigOpCount")

    # Check merkle root
    if fCheckMerkleRoot and block.hashMerkleRoot != block.calc_merkle_root():
        raise CheckBlockError("CheckBlock() : hashMerkleRoot mismatch")
