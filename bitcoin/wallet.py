
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

import bitcoin
import bitcoin.base58
import bitcoin.core.script as script

class CBitcoinAddress(bitcoin.base58.CBase58Data):
    """A Bitcoin address"""

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        if self.nVersion == bitcoin.params.BASE58_PREFIXES['PUBKEY_ADDR']:
            return script.CScript([script.OP_DUP, script.OP_HASH160, self, script.OP_EQUALVERIFY, script.OP_CHECKSIG])

        elif self.nVersion == bitcoin.params.BASE58_PREFIXES['SCRIPT_ADDR']:
            return script.CScript([script.OP_HASH160, self, script.OP_EQUAL])

        else:
            raise ValueError("CBitcoinAddress: Don't know how to convert version %d to a scriptPubKey" % self.nVersion)
