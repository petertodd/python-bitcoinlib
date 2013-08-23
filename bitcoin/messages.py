
#
# messages.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from __future__ import absolute_import, division, print_function, unicode_literals

import struct
import time
import random
import cStringIO
from bitcoin.coredefs import *
from bitcoin.core import *

MSG_TX = 1
MSG_BLOCK = 2

class msg_version(object):
    command = b"version"
    def __init__(self, protover=PROTO_VERSION):
        self.protover = MIN_PROTO_VERSION
        self.nVersion = protover
        self.nServices = 1
        self.nTime = time.time()
        self.addrTo = CAddress(MIN_PROTO_VERSION)
        self.addrFrom = CAddress(MIN_PROTO_VERSION)
        self.nNonce = random.getrandbits(64)
        self.strSubVer = b'/python-bitcoin-0.0.1/'
        self.nStartingHeight = -1
    def deserialize(self, f):
        self.nVersion = struct.unpack(b"<i", f.read(4))[0]
        if self.nVersion == 10300:
            self.nVersion = 300
        self.nServices = struct.unpack(b"<Q", f.read(8))[0]
        self.nTime = struct.unpack(b"<q", f.read(8))[0]
        self.addrTo = CAddress(MIN_PROTO_VERSION)
        self.addrTo.deserialize(f)
        if self.nVersion >= 106:
            self.addrFrom = CAddress(MIN_PROTO_VERSION)
            self.addrFrom.deserialize(f)
            self.nNonce = struct.unpack(b"<Q", f.read(8))[0]
            self.strSubVer = deser_string(f)
            if self.nVersion >= 209:
                self.nStartingHeight = struct.unpack(b"<i", f.read(4))[0]
            else:
                self.nStartingHeight = None
        else:
            self.addrFrom = None
            self.nNonce = None
            self.strSubVer = None
            self.nStartingHeight = None
    def serialize(self):
        r = b""
        r += struct.pack(b"<i", self.nVersion)
        r += struct.pack(b"<Q", self.nServices)
        r += struct.pack(b"<q", self.nTime)
        r += self.addrTo.serialize()
        r += self.addrFrom.serialize()
        r += struct.pack(b"<Q", self.nNonce)
        r += ser_string(self.strSubVer)
        r += struct.pack(b"<i", self.nStartingHeight)
        return r
    def __repr__(self):
        return "msg_version(nVersion=%i nServices=%i nTime=%s addrTo=%s addrFrom=%s nNonce=0x%016X strSubVer=%s nStartingHeight=%i)" % (self.nVersion, self.nServices, time.ctime(self.nTime), repr(self.addrTo), repr(self.addrFrom), self.nNonce, self.strSubVer, self.nStartingHeight)

class msg_verack(object):
    command = b"verack"
    def __init__(self, protover=PROTO_VERSION):
        self.protover = protover
    def deserialize(self, f):
        pass
    def serialize(self):
        return b""
    def __repr__(self):
        return "msg_verack()"

class msg_addr(object):
    command = b"addr"
    def __init__(self, protover=PROTO_VERSION):
        self.protover = protover
        self.addrs = []
    def deserialize(self, f):
        self.addrs = deser_vector(f, CAddress, self.protover)
    def serialize(self):
        return ser_vector(self.addrs)
    def __repr__(self):
        return "msg_addr(addrs=%s)" % (repr(self.addrs))

class msg_alert(object):
    command = b"alert"
    def __init__(self, protover=PROTO_VERSION):
        self.protover = protover
        self.alert = CAlert()
    def deserialize(self, f):
        self.alert = CAlert()
        self.alert.deserialize(f)
    def serialize(self):
        r = b""
        r += self.alert.serialize()
        return r
    def __repr__(self):
        return "msg_alert(alert=%s)" % (repr(self.alert), )

class msg_inv(object):
    command = b"inv"
    def __init__(self, protover=PROTO_VERSION):
        self.protover = protover
        self.inv = []
    def deserialize(self, f):
        self.inv = deser_vector(f, CInv)
    def serialize(self):
        return ser_vector(self.inv)
    def __repr__(self):
        return "msg_inv(inv=%s)" % (repr(self.inv))

class msg_getdata(object):
    command = b"getdata"
    def __init__(self, protover=PROTO_VERSION):
        self.protover = protover
        self.inv = []
    def deserialize(self, f):
        self.inv = deser_vector(f, CInv)
    def serialize(self):
        return ser_vector(self.inv)
    def __repr__(self):
        return "msg_getdata(inv=%s)" % (repr(self.inv))

class msg_getblocks(object):
    command = b"getblocks"
    def __init__(self, protover=PROTO_VERSION):
        self.protover = protover
        self.locator = CBlockLocator()
        self.hashstop = 0
    def deserialize(self, f):
        self.locator = CBlockLocator()
        self.locator.deserialize(f)
        self.hashstop = deser_uint256(f)
    def serialize(self):
        r = b""
        r += self.locator.serialize()
        r += ser_uint256(self.hashstop)
        return r
    def __repr__(self):
        return "msg_getblocks(locator=%s hashstop=%064x)" % (repr(self.locator), self.hashstop)

class msg_getheaders(object):
    command = b"getheaders"
    def __init__(self, protover=PROTO_VERSION):
        self.protover = protover
        self.locator = CBlockLocator()
        self.hashstop = 0
    def deserialize(self, f):
        self.locator = CBlockLocator()
        self.locator.deserialize(f)
        self.hashstop = deser_uint256(f)
    def serialize(self):
        r = b""
        r += self.locator.serialize()
        r += ser_uint256(self.hashstop)
        return r
    def __repr__(self):
        return "msg_getheaders(locator=%s hashstop=%064x)" % (repr(self.locator), self.hashstop)

class msg_headers(object):
    command = b"headers"
    def __init__(self, protover=PROTO_VERSION):
        self.protover = protover
        self.headers = []
    def deserialize(self, f):
        self.headers = deser_vector(f, CBlock)
    def serialize(self):
        return ser_vector(self.headers)
    def __repr__(self):
        return "msg_headers(headers=%s)" % (repr(self.headers))

class msg_tx(object):
    command = b"tx"
    def __init__(self, protover=PROTO_VERSION):
        self.protover = protover
        self.tx = CTransaction()
    def deserialize(self, f):
        self.tx.deserialize(f)
    def serialize(self):
        return self.tx.serialize()
    def __repr__(self):
        return "msg_tx(tx=%s)" % (repr(self.tx))

class msg_block(object):
    command = b"block"
    def __init__(self, protover=PROTO_VERSION):
        self.protover = protover
        self.block = CBlock()
    def deserialize(self, f):
        self.block.deserialize(f)
    def serialize(self):
        return self.block.serialize()
    def __repr__(self):
        return "msg_block(block=%s)" % (repr(self.block))

class msg_getaddr(object):
    command = b"getaddr"
    def __init__(self, protover=PROTO_VERSION):
        self.protover = protover
    def deserialize(self, f):
        pass
    def serialize(self):
        return b""
    def __repr__(self):
        return "msg_getaddr()"

#msg_checkorder
#msg_submitorder
#msg_reply

class msg_ping(object):
    command = b"ping"
    def __init__(self, protover=PROTO_VERSION, nonce=0):
        self.protover = protover
        self.nonce = nonce
    def deserialize(self, f):
        if self.protover > BIP0031_VERSION:
            self.nonce = struct.unpack(b"<Q", f.read(8))[0]
    def serialize(self):
        r = b""
        if self.protover > BIP0031_VERSION:
            r += struct.pack(b"<Q", self.nonce)
        return r
    def __repr__(self):
        return "msg_ping(0x%x)" % (self.nonce,)

class msg_pong(object):
    command = b"pong"
    def __init__(self, protover=PROTO_VERSION, nonce=0):
        self.protover = protover
        self.nonce = nonce
    def deserialize(self, f):
        self.nonce = struct.unpack(b"<Q", f.read(8))[0]
    def serialize(self):
        r = b""
        r += struct.pack(b"<Q", self.nonce)
        return r
    def __repr__(self):
        return "msg_pong(0x%x)" % (self.nonce,)

class msg_mempool(object):
    command = b"mempool"
    def __init__(self, protover=PROTO_VERSION):
        self.protover = protover
    def deserialize(self, f):
        pass
    def serialize(self):
        return b""
    def __repr__(self):
        return "msg_mempool()"

messagemap = {
    "version": msg_version,
    "verack": msg_verack,
    "addr": msg_addr,
    "alert": msg_alert,
    "inv": msg_inv,
    "getdata": msg_getdata,
    "getblocks": msg_getblocks,
    "tx": msg_tx,
    "block": msg_block,
    "getaddr": msg_getaddr,
    "ping": msg_ping,
    "pong": msg_pong,
    "mempool": msg_mempool
}

def message_read(netmagic, f):
    try:
        recvbuf = f.read(4 + 12 + 4 + 4)
    except IOError:
        return None
    
    # check magic
    if len(recvbuf) < 4:
        return
    if recvbuf[:4] != netmagic.msg_start:
        raise ValueError("got garbage %s" % repr(recvbuf))

    # check checksum
    if len(recvbuf) < 4 + 12 + 4 + 4:
        return

    # remaining header fields: command, msg length, checksum
    command = recvbuf[4:4+12].split(b"\x00", 1)[0]
    msglen = struct.unpack(b"<i", recvbuf[4+12:4+12+4])[0]
    checksum = recvbuf[4+12+4:4+12+4+4]

    # read message body
    try:
        recvbuf += f.read(msglen)
    except IOError:
        return None

    msg = recvbuf[4+12+4+4:4+12+4+4+msglen]
    th = hashlib.sha256(msg).digest()
    h = hashlib.sha256(th).digest()
    if checksum != h[:4]:
        raise ValueError("got bad checksum %s" % repr(recvbuf))
    recvbuf = recvbuf[4+12+4+4+msglen:]

    if command in messagemap:
        f = cStringIO.StringIO(msg)
        t = messagemap[command]()
        t.deserialize(f)
        return t
    else:
        return None

def message_to_str(netmagic, message):
    command = message.command
    data = message.serialize()
    tmsg = netmagic.msg_start
    tmsg += command
    tmsg += b"\x00" * (12 - len(command))
    tmsg += struct.pack(b"<I", len(data))

    # add checksum
    th = hashlib.sha256(data).digest()
    h = hashlib.sha256(th).digest()
    tmsg += h[:4]

    tmsg += data

    return tmsg

