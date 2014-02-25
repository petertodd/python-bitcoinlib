
#
# serialize.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

"""Serialization routines

You probabably don't need to use these directly.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import hashlib
import struct

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

MAX_SIZE = 0x02000000

class SerializationError(Exception):
    """Base class for serialization errors"""

class SerializationTruncationError(Exception):
    """Serialized data was truncated

    Thrown by deserialize() and stream_deserialize()
    """

def ser_read(f, n):
    """Read from a stream safely

    Raises SerializationError and SerializationTruncationError appropriately.
    Use this instead of f.read() in your classes stream_(de)serialization()
    functions.
    """
    if n > MAX_SIZE:
        raise SerializationError('Asked to read 0x%x bytes; MAX_SIZE exceeded')
    r = f.read(n)
    if len(r) < n:
        raise SerializationTruncationError()
    return r

class Serializable(object):
    """Base class for serializable objects"""
    def stream_serialize(self, f):
        """Serialize to a stream"""
        raise NotImplementedError

    @classmethod
    def stream_deserialize(cls, f):
        """Deserialize from a stream"""
        raise NotImplementedError

    def serialize(self):
        """Serialize, returning bytes"""
        f = BytesIO()
        self.stream_serialize(f)
        return f.getvalue()

    @classmethod
    def deserialize(cls, buf):
        """Deserialize bytes, returning an instance"""
        return cls.stream_deserialize(BytesIO(buf))

    def __eq__(self, other):
        if (not isinstance(other, self.__class__) and
            not isinstance(self, other.__class__)):
            return NotImplemented
        return self.serialize() == other.serialize()

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(self.serialize())

class Serializer(object):
    """Base class for object serializers"""
    def __new__(cls):
        raise NotImplementedError

    @classmethod
    def stream_serialize(cls, obj, f):
        raise NotImplementedError
    @classmethod
    def stream_deserialize(cls, f):
        raise NotImplementedError

    @classmethod
    def serialize(cls, obj):
        f = BytesIO()
        cls.stream_serialize(obj, f)
        return f.getvalue()

    @classmethod
    def deserialize(cls, buf):
        return cls.stream_deserialize(BytesIO(buf))

class VarIntSerializer(Serializer):
    """Serialization of variable length ints"""
    @classmethod
    def stream_serialize(cls, i, f):
        if i < 0:
            raise ValueError('varint must be non-negative integer')
        elif i < 0xfd:
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

    @classmethod
    def stream_deserialize(cls, f):
        r = bord(ser_read(f, 1))
        if r < 0xfd:
            return r
        elif r == 0xfd:
            return struct.unpack(b'<H', ser_read(f, 2))[0]
        elif r == 0xfe:
            return struct.unpack(b'<I', ser_read(f, 4))[0]
        else:
            return struct.unpack(b'<Q', ser_read(f, 8))[0]

class BytesSerializer(Serializer):
    """Serialization of bytes instances"""
    @classmethod
    def stream_serialize(cls, b, f):
        VarIntSerializer.stream_serialize(len(b), f)
        f.write(b)

    @classmethod
    def stream_deserialize(cls, f):
        l = VarIntSerializer.stream_deserialize(f)
        return ser_read(f, l)

class VectorSerializer(Serializer):
    """Base class for serializers of object vectors"""
    @classmethod
    def stream_serialize(cls, inner_cls, objs, f):
        VarIntSerializer.stream_serialize(len(objs), f)
        for obj in objs:
            inner_cls.stream_serialize(obj, f)

    @classmethod
    def stream_deserialize(cls, inner_cls, f):
        n = VarIntSerializer.stream_deserialize(f)
        r = []
        for i in range(n):
            r.append(inner_cls.stream_deserialize(f))
        return r

class uint256VectorSerializer(Serializer):
    """Serialize vectors of uint256"""
    @classmethod
    def stream_serialize(cls, inner_cls, objs, f):
        VarIntSerializer.stream_serialize(len(objs), f)
        for obj in objs:
            assert len(obj) == 32
            f.write(obj)

    @classmethod
    def stream_deserialize(cls, inner_cls, f):
        n = VarIntSerializer.stream_deserialize(f)
        r = []
        for i in range(n):
            r.append(ser_read(f, 32))
        return r

def uint256_from_str(s):
    """Convert bytes to uint256"""
    r = 0
    t = struct.unpack(b"<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r

def uint256_from_compact(c):
    """Convert compact encoding to uint256

    Used for the nBits compact encoding of the target in the block header.
    """
    nbytes = (c >> 24) & 0xFF
    v = (c & 0xFFFFFF) << (8 * (nbytes - 3))
    return v

def uint256_to_shortstr(u):
    s = "%064x" % (u,)
    return s[:16]

def deser_int_vector(f):
    """Deserialize a vector of ints"""
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
    """Serialize a vector of ints"""
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

def Hash(msg):
    """SHA256^2)(msg) -> bytes"""
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()

def Hash160(msg):
    """RIPEME160(SHA256(msg)) -> bytes"""
    h = hashlib.new('ripemd160')
    h.update(hashlib.sha256(msg).digest())
    return h.digest()
