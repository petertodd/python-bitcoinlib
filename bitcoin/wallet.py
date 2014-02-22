
#
# wallet.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from __future__ import absolute_import, division, print_function, unicode_literals

import bitcoin.base58
import bitcoin.core.script as script

class CBitcoinAddress(bitcoin.base58.CBase58Data):
    """A Bitcoin address"""
    PUBKEY_ADDRESS = 0
    SCRIPT_ADDRESS = 5
    PUBKEY_ADDRESS_TEST = 111
    SCRIPT_ADDRESS_TEST = 196

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        if self.nVersion in (self.PUBKEY_ADDRESS, self.PUBKEY_ADDRESS_TEST):
            return script.CScript([script.OP_DUP, script.OP_HASH160, self, script.OP_EQUALVERIFY, script.OP_CHECKSIG])

        elif self.nVersion in (self.SCRIPT_ADDRESS, self.SCRIPT_ADDRESS_TEST):
            return script.CScript([script.OP_HASH160, self, script.OP_EQUAL])

        else:
            raise ValueError("CBitcoinAddress: Don't know how to convert version %d to a scriptPubKey" % self.nVersion)
