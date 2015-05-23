# Copyright (C) 2011 Sam Rushing
# Copyright (C) 2012-2015 The python-bitcoinlib developers
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

import hashlib
import sys
from cryptography.hazmat.bindings.openssl.binding import Binding

import bitcoin.core.script

_binding = Binding()
_ssl = _binding.lib
_ffi = _binding.ffi

class OpenSSLError(Exception):
    pass

def _checksslerr(exc_type=OpenSSLError):
    errno = _ssl.ERR_get_error()
    if errno == 0:
        return
    _ssl.SSL_load_error_strings()
    msgs = []
    while errno != 0:
        errmsg = _ffi.new('char[120]')
        _ssl.ERR_error_string_n(errno, errmsg, 120)
        msg = [
            errno,
            errmsg,
            _ssl.ERR_lib_error_string(errno),
            _ssl.ERR_func_error_string(errno),
            _ssl.ERR_reason_error_string(errno),
        ]
        msg[1:] = [ _ffi.string(c) if c else None for c in msg[1:] ]
        msgs.append(msg)
        errno = _ssl.ERR_get_error()
    if exc_type is not None:
        raise exc_type(msgs)

# test that openssl support secp256k1
_EC_GROUP_secp256k1 = _ssl.EC_GROUP_new_by_curve_name(_ssl.NID_secp256k1)
if _EC_GROUP_secp256k1 == 0:
    _checksslerr()
else:
    _ssl.EC_GROUP_free(_EC_GROUP_secp256k1)

class CECKey:
    """Wrapper around OpenSSL's EC_KEY"""

    POINT_CONVERSION_COMPRESSED = 2
    POINT_CONVERSION_UNCOMPRESSED = 4

    def __init__(self):
        self.k = _ffi.gc(_ssl.EC_KEY_new_by_curve_name(_ssl.NID_secp256k1), _ssl.EC_KEY_free)

    def set_secretbytes(self, secret):
        priv_key = _ffi.gc(_ssl.BN_bin2bn(secret, min(len(secret), 32), _ffi.NULL), _ssl.BN_free)
        group = _ssl.EC_KEY_get0_group(self.k)
        pub_key = _ffi.gc(_ssl.EC_POINT_new(group), _ssl.EC_POINT_free)
        bn_ctx = _ffi.gc(_ssl.BN_CTX_new(), _ssl.BN_CTX_free)
        _ssl.EC_POINT_mul(group, pub_key, priv_key, _ffi.NULL, _ffi.NULL, bn_ctx)
        _checksslerr()
        _ssl.EC_POINT_mul(group, pub_key, priv_key, _ffi.NULL, _ffi.NULL, bn_ctx)
        _checksslerr()
        _ssl.EC_KEY_set_private_key(self.k, priv_key)
        _checksslerr()
        _ssl.EC_KEY_set_public_key(self.k, pub_key)
        _checksslerr()
        return self.k

    def set_privkey(self, key):
        if hasattr(_ssl, 'd2i_ECPrivateKey'):
            k = _ssl.d2i_ECPrivateKey(_ffi.NULL, [key], len(key))
        else:
            # TODO: alternate implementation?
            raise RuntimeError('d2i_ECPrivateKey unsupported by this version of cryptography')
        _checksslerr()
        self.k = _ffi.gc(k, _ssl.EC_KEY_free)
        return self.k

    def set_pubkey(self, key):
        if hasattr(_ssl, 'o2i_ECPublicKey'):
            _ssl.o2i_ECPublicKey([self.k], [key], len(key))
        else:
            group = _ssl.EC_KEY_get0_group(self.k)
            point = _ffi.gc(_ssl.EC_POINT_new(group), _ssl.EC_POINT_free)
            _ssl.EC_POINT_oct2point(group, point, key, len(key), _ffi.NULL)
            _checksslerr()
            _ssl.EC_KEY_set_public_key(self.k, point)
        return self.k

    def get_privkey(self):
        if hasattr(_ssl, 'i2d_ECPrivateKey'):
            size = _ssl.i2d_ECPrivateKey(self.k, _ffi.NULL)
        else:
            # TODO: alternate implementation?
            raise RuntimeError('i2d_ECPrivateKey unsupported by this version of cryptography')
        _checksslerr()
        uc_buf = _ffi.new('unsigned char[]', size)
        if hasattr(_ssl, 'i2d_ECPrivateKey'):
            _ssl.i2d_ECPrivateKey(self.k, [uc_buf])
        else:
            # TODO: alternate implementation?
            raise RuntimeError('i2d_ECPrivateKey unsupported by this version of cryptography')
        _checksslerr()
        return _ffi.buffer(uc_buf, size)[:]

    def get_pubkey(self):
        if hasattr(_ssl, 'i2o_ECPublicKey'):
            size = _ssl.i2o_ECPublicKey(self.k, _ffi.NULL)
        else:
            conv_form = _ssl.EC_KEY_get_conv_form(self.k)
            group = _ssl.EC_KEY_get0_group(self.k)
            pub_key = _ssl.EC_KEY_get0_public_key(self.k)
            size = _ssl.EC_POINT_point2oct(group, pub_key, conv_form, _ffi.NULL, 0, _ffi.NULL)
        _checksslerr()
        uc_buf = _ffi.new('unsigned char[]', size)
        if hasattr(_ssl, 'i2o_ECPublicKey'):
            _ssl.i2o_ECPublicKey(self.k, [uc_buf])
        else:
            _ssl.EC_POINT_point2oct(group, pub_key, conv_form, uc_buf, size, _ffi.NULL)
        _checksslerr()
        return _ffi.buffer(uc_buf, size)[:]

    def get_raw_ecdh_key(self, other_pubkey):
        ecdh_key_buf = _ffi.new('unsigned char[]', 32)
        r = _ssl.ECDH_compute_key(ecdh_key_buf, 32,
                                 _ssl.EC_KEY_get0_public_key(other_pubkey.k),
                                 self.k, _ffi.NULL)
        if r != 32:
            raise RuntimeError('CKey.get_ecdh_key(): ECDH_compute_key() failed')
        return _ffi.buffer(ecdh_key_buf, 32)[:]

    def get_ecdh_key(self, other_pubkey, kdf=lambda k: hashlib.sha256(k).digest()):
        # FIXME: be warned it's not clear what the kdf should be as a default
        r = self.get_raw_ecdh_key(other_pubkey)
        return kdf(r)

    def sign(self, hash):
        if not isinstance(hash, bytes):
            raise TypeError('Hash must be bytes instance; got %r' % hash.__class__)
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        sig_size0_p = _ffi.new('unsigned int*')
        sig_size0_p[0] = _ssl.ECDSA_size(self.k)
        _checksslerr()
        uc_buf = _ffi.new('unsigned char[]', sig_size0_p[0])
        result = _ssl.ECDSA_sign(0, hash, len(hash), uc_buf, sig_size0_p, self.k)
        _checksslerr()
        mb_sig = _ffi.buffer(uc_buf, sig_size0_p[0])[:]
        assert 1 == result
        if bitcoin.core.script.IsLowDERSignature(mb_sig):
            return mb_sig
        else:
            return self.signature_to_low_s(uc_buf, sig_size0_p[0])

    def signature_to_low_s(self, sig_buf, sig_buf_len):
        der_sig = _ssl.d2i_ECDSA_SIG(_ffi.NULL, [sig_buf], sig_buf_len)
        _checksslerr()
        der_sig = _ffi.gc(der_sig, _ssl.ECDSA_SIG_free)
        group = _ssl.EC_KEY_get0_group(self.k)
        order = _ffi.gc(_ssl.BN_new(), _ssl.BN_free)
        halforder = _ffi.gc(_ssl.BN_new(), _ssl.BN_free)
        bn_ctx = _ffi.gc(_ssl.BN_CTX_new(), _ssl.BN_CTX_free)
        _ssl.EC_GROUP_get_order(group, order, bn_ctx)
        _ssl.BN_rshift1(halforder, order)

        # Verify that s is over half the order of the curve before we actually subtract anything from it
        if _ssl.BN_cmp(der_sig.s, halforder) > 0:
          _ssl.BN_sub(der_sig.s, order, der_sig.s)

        derlen = _ssl.i2d_ECDSA_SIG(der_sig, _ffi.NULL)
        _checksslerr()
        if derlen == 0:
            return None
        new_sig_buf = _ffi.new('unsigned char[]', derlen)
        _ssl.i2d_ECDSA_SIG(der_sig, [new_sig_buf])
        _checksslerr()

        return _ffi.buffer(new_sig_buf, derlen)[:]

    def verify(self, hash, sig):
        """Verify a DER signature"""
        if not sig:
          return False

        # New versions of OpenSSL will reject non-canonical DER signatures. de/re-serialize first.
        norm_sig_p = _ffi.new('ECDSA_SIG**')
        c_sig = _ffi.new('char[]', len(sig))
        c_sig[0:len(sig)] = sig
        uc_sig = _ffi.cast('unsigned char*', c_sig)
        _ssl.d2i_ECDSA_SIG(norm_sig_p, [uc_sig], len(sig))
        _checksslerr()

        derlen = _ssl.i2d_ECDSA_SIG(norm_sig_p[0], _ffi.NULL)
        _checksslerr()
        if derlen == 0:
            _ssl.ECDSA_SIG_free(norm_sig_p[0])
            return False

        uc_der = _ffi.new('unsigned char[]', derlen)
        _ssl.i2d_ECDSA_SIG(norm_sig_p[0], [uc_der])
        _checksslerr()
        _ssl.ECDSA_SIG_free(norm_sig_p[0])
        _checksslerr()
        verify_res = _ssl.ECDSA_verify(0, hash, len(hash), uc_der, derlen, self.k)
        _checksslerr()

        # -1 = error, 0 = bad sig, 1 = good
        return verify_res == 1

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
        try:
            _cec_key.set_pubkey(self)
            self.is_fullyvalid = True
        except OpenSSLError:
            self.is_fullyvalid = False
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
