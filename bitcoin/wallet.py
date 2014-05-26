
#
# wallet.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

"""Wallet-related functionality

Includes things like representing addresses and converting them to/from
scriptPubKeys; currently there is no actual wallet support implemented.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import sys
bchr = chr
bord = ord
if sys.version > '3':
        bchr = lambda x: bytes([x])
        bord = lambda x: x

import bitcoin
import bitcoin.base58
import bitcoin.core.script as script
import bitcoin.core.key

class CBitcoinAddressError(bitcoin.base58.Base58Error):
    """Raised when an invalid Bitcoin address is encountered"""

class CBitcoinAddress(bitcoin.base58.CBase58Data):
    """A Bitcoin address"""

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        if scriptPubKey.is_p2sh():
            return cls.from_bytes(scriptPubKey[2:22], bitcoin.params.BASE58_PREFIXES['SCRIPT_ADDR'])

        elif (len(scriptPubKey) == 25 and
              bord(scriptPubKey[0])  == script.OP_DUP and
              bord(scriptPubKey[1])  == script.OP_HASH160 and
              bord(scriptPubKey[2])  == 0x14 and
              bord(scriptPubKey[23]) == script.OP_EQUALVERIFY and
              bord(scriptPubKey[24]) == script.OP_CHECKSIG):
            return cls.from_bytes(scriptPubKey[3:23], bitcoin.params.BASE58_PREFIXES['PUBKEY_ADDR'])

        else:
            # FIXME: add bare CHECKSIG and support for non-standard PUSHDATA's
            raise ValueError('scriptPubKey not recognized')

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        if self.nVersion == bitcoin.params.BASE58_PREFIXES['PUBKEY_ADDR']:
            return script.CScript([script.OP_DUP, script.OP_HASH160, self, script.OP_EQUALVERIFY, script.OP_CHECKSIG])

        elif self.nVersion == bitcoin.params.BASE58_PREFIXES['SCRIPT_ADDR']:
            return script.CScript([script.OP_HASH160, self, script.OP_EQUAL])

        else:
            raise ValueError("CBitcoinAddress: Don't know how to convert version %d to a scriptPubKey" % self.nVersion)


class CKey(object):
    """An encapsulated private key

    Attributes:

    pub           - The corresponding CPubKey for this private key
    is_compressed - True if compressed

    """
    def __init__(self, secret, compressed=True):
        self._cec_key = bitcoin.core.key.CECKey()
        self._cec_key.set_secretbytes(secret)
        self._cec_key.set_compressed(compressed)

        self.pub = bitcoin.core.key.CPubKey(self._cec_key.get_pubkey(), self._cec_key)

    @property
    def is_compressed(self):
        return self.pub.is_compressed

    def sign(self, hash):
        return self._cec_key.sign(hash)


class CBitcoinSecretError(bitcoin.base58.Base58Error):
    pass

class CBitcoinSecret(bitcoin.base58.CBase58Data, CKey):
    """A base58-encoded secret key"""

    @classmethod
    def from_secret_bytes(cls, secret, compressed=True):
        """Create a secret key from a 32-byte secret"""
        self = cls.from_bytes(secret + (b'\x01' if compressed else b''),
                              bitcoin.params.BASE58_PREFIXES['SECRET_KEY'])
        self.__init__(None)
        return self

    def __init__(self, s):
        if self.nVersion != bitcoin.params.BASE58_PREFIXES['SECRET_KEY']:
            raise CBitcoinSecretError('Not a base58-encoded secret key: got nVersion=%d; expected nVersion=%d' % \
                                      (self.nVersion, bitcoin.params.BASE58_PREFIXES['SECRET_KEY']))

        CKey.__init__(self, self[0:32], len(self) > 32 and bord(self[32]) == 1)
