
#
# base58.py
# Original source: git://github.com/joric/brutus.git
# which was forked from git://github.com/samrushing/caesure.git
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from __future__ import absolute_import, division, print_function, unicode_literals

from bitcoin.serialize import Hash, ser_uint256

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

from binascii import hexlify, unhexlify

class Base58Error(Exception):
    pass

class InvalidBase58Error(Base58Error):
    pass

def encode(b):
    """Encode bytes to a base58-encoded string"""

    # Convert big-endian bytes to integer
    n = int('0x0' + hexlify(b).decode('utf8'), 16)

    # Divide that integer into bas58
    res = []
    while n > 0:
        n, r = divmod (n, 58)
        res.append(b58_digits[r])
    res = ''.join(res[::-1])

    # Encode leading zeros as base58 zeros
    import sys
    czero = b'\x00'
    if sys.version > '3':
        # In Python3 indexing a bytes returns numbers, not characters.
        czero = 0
    pad = 0
    for c in b:
        if c == czero: pad += 1
        else: break
    return b58_digits[0] * pad + res

def decode(s):
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''

    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise InvalidBase58Error('Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n += digit

    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]: pad += 1
        else: break
    return b'\x00' * pad + res


class Base58ChecksumError(Base58Error):
    pass

class CBase58Data(bytes):
    def __new__(cls, data, nVersion):
        self = super(CBase58Data, cls).__new__(cls, data)
        self.nVersion = nVersion
        return self

    def __repr__(self):
        return '%s(%s, %d)' % (self.__class__.__name__, bytes.__repr__(self), self.nVersion)

    def __str__(self):
        vs = chr(self.nVersion) + self
        check = ser_uint256(Hash(vs))[0:4]
        return encode(vs + check)

    @classmethod
    def from_str(cls, s):
        k = decode(s)
        addrbyte, data, check0 = k[0], k[1:-4], k[-4:]
        check1 = ser_uint256(Hash(addrbyte + data))[:4]
        if check0 != check1:
            raise Base58ChecksumError('Checksum mismatch: expected %r, calculated %r' % (check0, check1))
        return cls(data, ord(addrbyte))


class CBitcoinAddress(CBase58Data):
    PUBKEY_ADDRESS = 0
    SCRIPT_ADDRESS = 5
    PUBKEY_ADDRESS_TEST = 111
    SCRIPT_ADDRESS_TEST = 196
