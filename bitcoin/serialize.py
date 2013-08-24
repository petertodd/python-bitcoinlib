
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
bord = ord
if sys.version > '3':
    bchr = lambda x: bytes([x])
    bord = lambda x: x[0]
    from io import BytesIO
else:
    from cStringIO import StringIO as BytesIO

class Serializable(object):
    def stream_serialize(self, f):
        raise NotImplementedError

    @classmethod
    def stream_deserialize(cls, f):
        raise NotImplementedError

    def serialize(self):
        f = BytesIO()
        self.stream_serialize(f)
        return f.getvalue()

    @classmethod
    def deserialize(cls, buf):
        return cls.stream_deserialize(BytesIO(buf))

    def __eq__(self, other):
        if (not isinstance(other, self.__class__) and
            not isinstance(self, other.__class__)):
            raise TypeError("Can't compare equality between %r instance and %r instance" %
                    (self.__class__, other.__class__))
        return self.serialize() == other.serialize()

def stream_ser_varint(i, f):
    if i < 0xfd:
        f.write(bchr(i))
    elif i <= 0xffff:
        f.write(bchr(0xfd))
        f.write(struct.pack(b'<H', i))
    elif i <= 0xffffffff:
        f.write(bchr(0xfe))
        f.write(struct.pack(b'<I', i))
    else:
        f.write(bchr(0xff))
        f.write(struct.pack(b'<Q', i))

def stream_deser_varint(f):
    r = bord(f.read(1))
    if r < 0xfd:
        return r
    elif i == 0xfd:
        return struct.unpack(b'<H', f.read(2))
    elif i == 0xfe:
        return struct.unpack(b'<I', f.read(4))
    else:
        return struct.unpack(b'<Q', f.read(8))

def stream_deser_bytes(f):
    l = stream_deser_varint(f)
    return f.read(l)

def stream_ser_bytes(b, f):
    l = len(b)
    stream_ser_varint(l, f)
    f.write(b)

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

def stream_deser_vector(f, cls):
    n = stream_deser_varint(f)
    r = []
    for i in range(n):
        r.append(cls.stream_deserialize(f))
    return r

def stream_ser_vector(l, f):
    stream_ser_varint(len(l), f)
    for i in l:
        i.stream_serialize(f)

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
        t = f.read(32)
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
        r += i
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
        t = f.read(32)
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
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def Hash160(s):
    h = hashlib.new('ripemd160')
    h.update(hashlib.sha256(s).digest())
    return h.digest()

