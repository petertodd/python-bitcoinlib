# Copyright (C) 2011 Sam Rushing
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

"""ECC secp256k1 crypto routines

WARNING: This module does not mlock() secrets; your private keys may end up on
disk in swap! Use with caution!
"""

import ctypes
import ctypes.util
import hashlib
import sys

_ssl = ctypes.cdll.LoadLibrary(ctypes.util.find_library('ssl') or 'libeay32')

# this specifies the curve used with ECDSA.
_NID_secp256k1 = 714 # from openssl/obj_mac.h

# Thx to Sam Devlin for the ctypes magic 64-bit fix.
def _check_result (val, func, args):
    if val == 0:
        raise ValueError
    else:
        return ctypes.c_void_p(val)

_ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
_ssl.EC_KEY_new_by_curve_name.errcheck = _check_result

class CECKey:
    """Wrapper around OpenSSL's EC_KEY"""

    POINT_CONVERSION_COMPRESSED = 2
    POINT_CONVERSION_UNCOMPRESSED = 4

    def __init__(self):
        self.k = _ssl.EC_KEY_new_by_curve_name(_NID_secp256k1)

    def __del__(self):
        if _ssl:
            _ssl.EC_KEY_free(self.k)
        self.k = None

    def set_secretbytes(self, secret):
        priv_key = _ssl.BN_bin2bn(secret, 32, _ssl.BN_new())
        group = _ssl.EC_KEY_get0_group(self.k)
        pub_key = _ssl.EC_POINT_new(group)
        ctx = _ssl.BN_CTX_new()
        if not _ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx):
            raise ValueError("Could not derive public key from the supplied secret.")
        _ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx)
        _ssl.EC_KEY_set_private_key(self.k, priv_key)
        _ssl.EC_KEY_set_public_key(self.k, pub_key)
        _ssl.EC_POINT_free(pub_key)
        _ssl.BN_CTX_free(ctx)
        return self.k

    def get_secretbytes(self):
        secret = _ssl.EC_KEY_get0_private_key(self.k)
        mb = ctypes.create_string_buffer(32)
        size = _ssl.BN_bn2bin(secret, mb)
        if size == 32:
          return mb.raw
        else:
          # Move the data into a zero-padded buffer of 32 bytes
          padding = 32 - size
          new_buffer = ctypes.create_string_buffer(32)
          for idx in range(0, padding):
              new_buffer[idx] = "\x00"
          for idx in range(padding, 32):
              new_buffer[idx] = mb[idx - padding]
          return new_buffer.raw

    def generate(self):
        _ssl.EC_KEY_generate_key(self.k)
        return self.k

    def set_privkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        return _ssl.d2i_ECPrivateKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def set_pubkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        return _ssl.o2i_ECPublicKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def get_privkey(self):
        size = _ssl.i2d_ECPrivateKey(self.k, 0)
        mb_pri = ctypes.create_string_buffer(size)
        _ssl.i2d_ECPrivateKey(self.k, ctypes.byref(ctypes.pointer(mb_pri)))
        return mb_pri.raw

    def get_pubkey(self):
        size = _ssl.i2o_ECPublicKey(self.k, 0)
        mb = ctypes.create_string_buffer(size)
        _ssl.i2o_ECPublicKey(self.k, ctypes.byref(ctypes.pointer(mb)))
        return mb.raw

    def get_raw_ecdh_key(self, other_pubkey):
        ecdh_keybuffer = ctypes.create_string_buffer(32)
        r = _ssl.ECDH_compute_key(ctypes.pointer(ecdh_keybuffer), 32,
                                 _ssl.EC_KEY_get0_public_key(other_pubkey.k),
                                 self.k, 0)
        if r != 32:
            raise Exception('CKey.get_ecdh_key(): ECDH_compute_key() failed')
        return ecdh_keybuffer.raw

    def get_ecdh_key(self, other_pubkey, kdf=lambda k: hashlib.sha256(k).digest()):
        # FIXME: be warned it's not clear what the kdf should be as a default
        r = self.get_raw_ecdh_key(other_pubkey)
        return kdf(r)

    def sign(self, hash):
        # FIXME: need unit tests for below cases
        if not isinstance(hash, bytes):
            raise TypeError('Hash must be bytes instance; got %r' % hash.__class__)
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        sig_size0 = ctypes.c_uint32()
        sig_size0.value = _ssl.ECDSA_size(self.k)
        mb_sig = ctypes.create_string_buffer(sig_size0.value)
        result = _ssl.ECDSA_sign(0, hash, len(hash), mb_sig, ctypes.byref(sig_size0), self.k)
        assert 1 == result
        return mb_sig.raw[:sig_size0.value]

    def verify(self, hash, sig):
        """Verify a DER signature"""
        return _ssl.ECDSA_verify(0, hash, len(hash), sig, len(sig), self.k) == 1

    def set_compressed(self, compressed):
        if compressed:
            form = self.POINT_CONVERSION_COMPRESSED
        else:
            form = self.POINT_CONVERSION_UNCOMPRESSED
        _ssl.EC_KEY_set_conv_form(self.k, form)


class CPubKey(bytes):
    """An encapsulated public key

    Attributes:

    is_valid      - Corresponds to CPubKey.IsValid()
    is_fullyvalid - Corresponds to CPubKey.IsFullyValid()
    is_compressed - Corresponds to CPubKey.IsCompressed()
    """

    def __new__(cls, buf, _cec_key=None):
        self = super(CPubKey, cls).__new__(cls, buf)
        if _cec_key is None:
            _cec_key = CECKey()
        self._cec_key = _cec_key
        self.is_fullyvalid = _cec_key.set_pubkey(self) != 0
        return self

    @property
    def is_valid(self):
        return len(self) > 0

    @property
    def is_compressed(self):
        return len(self) == 33

    def verify(self, hash, sig):
        return self._cec_key.verify(hash, sig)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        # Always have represent as b'<secret>' so test cases don't have to
        # change for py2/3
        if sys.version > '3':
            return '%s(%s)' % (self.__class__.__name__, super(CPubKey, self).__repr__())
        else:
            return '%s(b%s)' % (self.__class__.__name__, super(CPubKey, self).__repr__())

__all__ = (
        'CECKey',
        'CPubKey',
)
