
#
# serialize.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from __future__ import absolute_import, division, print_function, unicode_literals

import struct
import hashlib

# Py3 compatibility
import sys
bchr = chr
if sys.version > '3':
    bchr = lambda x: bytes([x])

def deser_string(f):
    nit = struct.unpack(b"<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack(b"<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack(b"<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack(b"<Q", f.read(8))[0]
    return f.read(nit)

def ser_string(s):
    if len(s) < 253:
        return bchr(len(s)) + s
    elif len(s) < 0x10000:
        return bchr(253) + struct.pack(b"<H", len(s)) + s
    elif len(s) < 0x100000000:
        return bchr(254) + struct.pack(b"<I", len(s)) + s
    return bchr(255) + struct.pack(b"<Q", len(s)) + s

def deser_uint256(f):
    r = 0
    for i in range(8):
        t = struct.unpack(b"<I", f.read(4))[0]
        r += t << (i * 32)
    return r

def ser_uint256(u):
    rs = b""
    for i in range(8):
        rs += struct.pack(b"<I", u & 0xFFFFFFFF)
        u >>= 32
    return rs

def ser_uint160(u):
    rs = b""
    for i in range(5):
        rs += struct.pack(b"<I", u & 0xFFFFFFFF)
        u >>= 32
    return rs

def uint160_from_str(s):
    r = 0
    t = struct.unpack(b"<IIIII", s[:20])
    for i in range(5):
        r += t[i] << (i * 32)
    return r

def uint256_from_str(s):
    r = 0
    t = struct.unpack(b"<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r

def uint256_from_compact(c):
    nbytes = (c >> 24) & 0xFF
    v = (c & 0xFFFFFF) << (8 * (nbytes - 3))
    return v

def uint256_to_shortstr(u):
    s = "%064x" % (u,)
    return s[:16]

def deser_vector(f, c, arg1=None):
    nit = struct.unpack(b"<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack(b"<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack(b"<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack(b"<Q", f.read(8))[0]
    r = []
    for i in range(nit):
        if arg1 is not None:
            t = c(arg1)
        else:
            t = c()
        t.deserialize(f)
        r.append(t)
    return r

def ser_vector(l):
    r = b""
    if len(l) < 253:
        r = bchr(len(l))
    elif len(l) < 0x10000:
        r = bchr(253) + struct.pack(b"<H", len(l))
    elif len(l) < 0x100000000:
        r = bchr(254) + struct.pack(b"<I", len(l))
    else:
        r = bchr(255) + struct.pack(b"<Q", len(l))
    for i in l:
        r += i.serialize()
    return r

def deser_uint256_vector(f):
    nit = struct.unpack(b"<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack(b"<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack(b"<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack(b"<Q", f.read(8))[0]
    r = []
    for i in range(nit):
        t = deser_uint256(f)
        r.append(t)
    return r

def ser_uint256_vector(l):
    r = b""
    if len(l) < 253:
        r = bchr(len(l))
    elif len(s) < 0x10000:
        r = bchr(253) + struct.pack(b"<H", len(l))
    elif len(s) < 0x100000000:
        r = bchr(254) + struct.pack(b"<I", len(l))
    else:
        r = bchr(255) + struct.pack(b"<Q", len(l))
    for i in l:
        r += ser_uint256(i)
    return r

def deser_string_vector(f):
    nit = struct.unpack(b"<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack(b"<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack(b"<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack(b"<Q", f.read(8))[0]
    r = []
    for i in range(nit):
        t = deser_string(f)
        r.append(t)
    return r

def ser_string_vector(l):
    r = b""
    if len(l) < 253:
        r = bchr(len(l))
    elif len(s) < 0x10000:
        r = bchr(253) + struct.pack(b"<H", len(l))
    elif len(s) < 0x100000000:
        r = bchr(254) + struct.pack(b"<I", len(l))
    else:
        r = bchr(255) + struct.pack(b"<Q", len(l))
    for sv in l:
        r += ser_string(sv)
    return r

def deser_int_vector(f):
    nit = struct.unpack(b"<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack(b"<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack(b"<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack(b"<Q", f.read(8))[0]
    r = []
    for i in range(nit):
        t = struct.unpack(b"<i", f.read(4))[0]
        r.append(t)
    return r

def ser_int_vector(l):
    r = b""
    if len(l) < 253:
        r = bchr(len(l))
    elif len(s) < 0x10000:
        r = bchr(253) + struct.pack(b"<H", len(l))
    elif len(s) < 0x100000000:
        r = bchr(254) + struct.pack(b"<I", len(l))
    else:
        r = bchr(255) + struct.pack(b"<Q", len(l))
    for i in l:
        r += struct.pack(b"<i", i)
    return r

def Hash(s):
    return uint256_from_str(hashlib.sha256(hashlib.sha256(s).digest()).digest())

def Hash160(s):
    h = hashlib.new('ripemd160')
    h.update(hashlib.sha256(s).digest())
    return uint160_from_str(h.digest())

