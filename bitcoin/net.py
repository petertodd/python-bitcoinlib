# Copyright (C) 2012-2014 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from __future__ import absolute_import, division, print_function, unicode_literals

import struct
import socket
from binascii import hexlify

from .core import PROTO_VERSION, CADDR_TIME_VERSION
from .core.serialize import *


class CAddress(Serializable):
    def __init__(self, protover=PROTO_VERSION):
        self.protover = protover
        self.nTime = 0
        self.nServices = 1
        self.pchReserved = b"\x00" * 10 + b"\xff" * 2
        self.ip = "0.0.0.0"
        self.port = 0

    @classmethod
    def stream_deserialize(cls, f, without_time=False):
        c = cls()
        if c.protover >= CADDR_TIME_VERSION and not without_time:
            c.nTime = struct.unpack(b"<I", ser_read(f, 4))[0]
        c.nServices = struct.unpack(b"<Q", ser_read(f, 8))[0]
        c.pchReserved = ser_read(f, 12)
        c.ip = socket.inet_ntoa(ser_read(f, 4))
        c.port = struct.unpack(b">H", ser_read(f, 2))[0]
        return c

    def stream_serialize(self, f, without_time=False):
        if self.protover >= CADDR_TIME_VERSION and not without_time:
            f.write(struct.pack(b"<I", self.nTime))
        f.write(struct.pack(b"<Q", self.nServices))
        f.write(self.pchReserved)
        f.write(socket.inet_aton(self.ip))
        f.write(struct.pack(b">H", self.port))

    def __repr__(self):
        return "CAddress(nTime=%d nServices=%i ip=%s port=%i)" % (self.nTime, self.nServices, self.ip, self.port)


class CInv(Serializable):
    typemap = {
        0: "Error",
        1: "TX",
        2: "Block",
        3: "FilteredBlock"}

    def __init__(self):
        self.type = 0
        self.hash = 0

    @classmethod
    def stream_deserialize(cls, f):
        c = cls()
        c.type = struct.unpack(b"<i", ser_read(f, 4))[0]
        c.hash = ser_read(f, 32)
        return c

    def stream_serialize(self, f):
        f.write(struct.pack(b"<i", self.type))
        f.write(self.hash)

    def __repr__(self):
        return "CInv(type=%s hash=%s)" % (self.typemap[self.type], hexlify(self.hash))


class CBlockLocator(Serializable):
    def __init__(self, protover=PROTO_VERSION):
        self.nVersion = protover
        self.vHave = []

    @classmethod
    def stream_deserialize(cls, f):
        c = cls()
        c.nVersion = struct.unpack(b"<i", ser_read(f, 4))[0]
        c.vHave = uint256VectorSerializer.stream_deserialize(f)
        return c

    def stream_serialize(self, f):
        f.write(struct.pack(b"<i", self.nVersion))
        uint256VectorSerializer.stream_serialize(self.vHave, f)

    def __repr__(self):
        return "CBlockLocator(nVersion=%i vHave=%s)" % (self.nVersion, repr(self.vHave))


class CUnsignedAlert(Serializable):
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

    @classmethod
    def stream_deserialize(cls, f):
        c = cls()
        c.nVersion = struct.unpack(b"<i", ser_read(f,4))[0]
        c.nRelayUntil = struct.unpack(b"<q", ser_read(f,8))[0]
        c.nExpiration = struct.unpack(b"<q", ser_read(f,8))[0]
        c.nID = struct.unpack(b"<i", ser_read(f,4))[0]
        c.nCancel = struct.unpack(b"<i", ser_read(f,4))[0]
        c.setCancel = intVectorSerialzer.deserialize(f)
        c.nMinVer = struct.unpack(b"<i", ser_read(f,4))[0]
        c.nMaxVer = struct.unpack(b"<i", ser_read(f,4))[0]
        c.setSubVer = VarStringSerializer.deserialize(f)
        c.nPriority = struct.unpack(b"<i", ser_read(f,4))[0]
        c.strComment = VarStringSerializer.deserialize(f)
        c.strStatusBar = VarStringSerializer.deserialize(f)
        c.strReserved = VarStringSerializer.deserialize(f)
        return c

    def stream_serialize(self, f):
        f.write(struct.pack(b"<i", self.nVersion))
        f.write(struct.pack(b"<q", self.nRelayUntil))
        f.write(struct.pack(b"<q", self.nExpiration))
        f.write(struct.pack(b"<i", self.nID))
        f.write(struct.pack(b"<i", self.nCancel))
        f.write(ser_int_vector(self.setCancel))
        f.write(struct.pack(b"<i", self.nMinVer))
        f.write(struct.pack(b"<i", self.nMaxVer))
        f.write(ser_string_vector(self.setSubVer))
        f.write(struct.pack(b"<i", self.nPriority))
        f.write(ser_string(self.strComment))
        f.write(ser_string(self.strStatusBar))
        f.write(ser_string(self.strReserved))

    def __repr__(self):
        return "CUnsignedAlert(nVersion %d, nRelayUntil %d, nExpiration %d, nID %d, nCancel %d, nMinVer %d, nMaxVer %d, nPriority %d, strComment %s, strStatusBar %s, strReserved %s)" % (self.nVersion, self.nRelayUntil, self.nExpiration, self.nID, self.nCancel, self.nMinVer, self.nMaxVer, self.nPriority, self.strComment, self.strStatusBar, self.strReserved)


class CAlert(Serializable):
    def __init__(self):
        self.vchMsg = b""
        self.vchSig = b""

    @classmethod
    def stream_deserialize(cls, f):
        c = cls()
        c.vchMsg = VarStringSerializer.stream_deserialize(f)
        c.vchSig = VarStringSerializer.stream_deserialize(f)
        return c

    def stream_serialize(self, f):
        VarStringSerializer.stream_serialize(self.vchMsg, f)
        VarStringSerializer.stream_serialize(self.vchSig, f)

    def __repr__(self):
        return "CAlert(vchMsg.sz %d, vchSig.sz %d)" % (len(self.vchMsg), len(self.vchSig))
