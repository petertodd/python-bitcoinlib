
#
# net.py
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
        2: "Block",
        3: "FilteredBlock"}
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
