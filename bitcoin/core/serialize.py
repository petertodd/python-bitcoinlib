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

"""Serialization routines

You probabably don't need to use these directly.
"""

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import hashlib
import struct

# Py3 compatibility
import sys

if sys.version > '3':
    bchr = lambda x: bytes([x])
    bord = lambda x: x[0]
    from io import BytesIO
else:
    bchr = chr
    bord = ord
    from cStringIO import StringIO as BytesIO

MAX_SIZE = 0x02000000


def Hash(msg):
    """SHA256^2)(msg) -> bytes"""
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()

def Hash160(msg):
    """RIPEME160(SHA256(msg)) -> bytes"""
    h = hashlib.new('ripemd160')
    h.update(hashlib.sha256(msg).digest())
    return h.digest()


class SerializationError(Exception):
    """Base class for serialization errors"""


class SerializationTruncationError(SerializationError):
    """Serialized data was truncated

    Thrown by deserialize() and stream_deserialize()
    """

class DeserializationExtraDataError(SerializationError):
    """Deserialized data had extra data at the end

    Thrown by deserialize() when not all data is consumed during
    deserialization. The deserialized object and extra padding not consumed are
    saved.
    """
    def __init__(self, msg, obj, padding):
        super(DeserializationExtraDataError, self).__init__(msg)
        self.obj = obj
        self.padding = padding

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
        raise SerializationTruncationError('Asked to read %i bytes, but only got %i' % (n, len(r)))
    return r


class Serializable(object):
    """Base class for serializable objects"""

    __slots__ = []

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
    def deserialize(cls, buf, allow_padding=False):
        """Deserialize bytes, returning an instance

        allow_padding - Allow buf to include extra padding. (default False)

        If allow_padding is False and not all bytes are consumed during
        deserialization DeserializationExtraDataError will be raised.
        """
        fd = BytesIO(buf)
        r = cls.stream_deserialize(fd)
        if not allow_padding:
            padding = fd.read()
            if len(padding) != 0:
                raise DeserializationExtraDataError('Not all bytes consumed during deserialization',
                                                    r, padding)
        return r

    def GetHash(self):
        """Return the hash of the serialized object"""
        return Hash(self.serialize())

    def __eq__(self, other):
        if (not isinstance(other, self.__class__) and
            not isinstance(self, other.__class__)):
            return NotImplemented
        return self.serialize() == other.serialize()

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(self.serialize())

class ImmutableSerializable(Serializable):
    """Immutable serializable object"""

    __slots__ = ['_cached_GetHash', '_cached__hash__']

    def __setattr__(self, name, value):
        raise AttributeError('Object is immutable')

    def __delattr__(self, name):
        raise AttributeError('Object is immutable')

    def GetHash(self):
        """Return the hash of the serialized object"""
        try:
            return self._cached_GetHash
        except AttributeError:
            _cached_GetHash = super(ImmutableSerializable, self).GetHash()
            object.__setattr__(self, '_cached_GetHash', _cached_GetHash)
            return _cached_GetHash

    def __hash__(self):
        try:
            return self._cached__hash__
        except AttributeError:
            _cached__hash__ = hash(self.serialize())
            object.__setattr__(self, '_cached__hash__', _cached__hash__)
            return _cached__hash__

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
    def stream_serialize(cls, uints, f):
        VarIntSerializer.stream_serialize(len(uints), f)
        for uint in uints:
            assert len(uint) == 32
            f.write(uint)

    @classmethod
    def stream_deserialize(cls, f):
        n = VarIntSerializer.stream_deserialize(f)
        r = []
        for i in range(n):
            r.append(ser_read(f, 32))
        return r


class intVectorSerialzer(Serializer):
    @classmethod
    def stream_serialize(cls, ints, f):
        l = len(ints)
        VarIntSerializer.stream_serialize(l, f)
        for i in ints:
            f.write(struct.pack(b"<i", i))

    @classmethod
    def stream_deserialize(cls, f):
        l = VarIntSerializer.stream_deserialize(f)
        ints = []
        for i in range(l):
            ints.append(struct.unpack(b"<i", ser_read(f, 4)))


class VarStringSerializer(Serializer):
    """Serialize variable length strings"""
    @classmethod
    def stream_serialize(cls, s, f):
        l = len(s)
        VarIntSerializer.stream_serialize(l, f)
        f.write(s)

    @classmethod
    def stream_deserialize(cls, f):
        l = VarIntSerializer.stream_deserialize(f)
        return ser_read(f, l)


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


