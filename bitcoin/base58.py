
#
# base58.py
# Original source: git://github.com/joric/brutus.git
# which was forked from git://github.com/samrushing/caesure.git
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from bitcoin.serialize import Hash

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def encode (n):
    l = []
    while n > 0:
        n, r = divmod (n, 58)
        l.insert (0, (b58_digits[r]))
    return ''.join (l)

def decode (s):
    n = 0
    for ch in s:
        n *= 58
        digit = b58_digits.index (ch)
        n += digit
    return n

def encode_padded (s):
    res = base58_encode (int ('0x' + s.encode ('hex'), 16))
    pad = 0
    for c in s:
        if c == chr(0): pad += 1
        else: break
    return b58_digits[0] * pad + res

def decode_padded (s):
    pad = 0
    for c in s:
        if c == b58_digits[0]: pad += 1
        else: break
    h = '%x' % base58_decode (s)
    if len(h) % 2:
        h = '0' + h
    res = h.decode ('hex')
    return chr(0) * pad + res

def key_to_address (s):
    vs = chr (addrtype) + s
    check = Hash(vs)[:4]
    return base58_encode_padded (vs + check)

def address_to_key (s):
    k = base58_decode_padded (s)
    hash160, check0 = k[1:-4], k[-4:]
    check1 = Hash (chr (addrtype) + hash160)[:4]
    if check0 != check1:
        return None
    return hash160

