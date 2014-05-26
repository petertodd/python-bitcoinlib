#!/usr/bin/python3

# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Example of timestamping a file via OP_RETURN"""

import hashlib
import bitcoin.rpc
import sys

from bitcoin.core import *
from bitcoin.core.script import *

proxy = bitcoin.rpc.Proxy()

assert len(sys.argv) > 1

digests = []
for f in sys.argv[1:]:
    try:
        with open(f, 'rb') as fd:
            digests.append(Hash(fd.read()))
    except FileNotFoundError as exp:
        if len(f)/2 in (20, 32):
            digests.append(x(f))
        else:
            raise exp
    except IOError as exp:
        print(exp,file=sys.stderr)
        continue

for digest in digests:
    txouts = []

    unspent = sorted(proxy.listunspent(0), key=lambda x: hash(x['amount']))

    txins = [CTxIn(unspent[-1]['outpoint'])]
    value_in = unspent[-1]['amount']

    change_addr = proxy.getnewaddress()
    change_pubkey = proxy.validateaddress(change_addr)['pubkey']
    change_out = CTxOut(MAX_MONEY, CScript([change_pubkey, OP_CHECKSIG]))

    digest_outs = [CTxOut(0, CScript([script.OP_RETURN, digest]))]

    txouts = [change_out] + digest_outs

    tx = CTransaction(txins, txouts)


    FEE_PER_BYTE = 0.00025*COIN/1000
    while True:
        tx.vout[0].nValue = int(value_in - max(len(tx.serialize())*FEE_PER_BYTE, 0.00011*COIN))

        r = proxy.signrawtransaction(tx)
        assert r['complete']
        tx = r['tx']

        if value_in - tx.vout[0].nValue >= len(tx.serialize())*FEE_PER_BYTE:
            print(b2x(tx.serialize()))
            print(len(tx.serialize()),'bytes',file=sys.stderr)
            print(b2lx(proxy.sendrawtransaction(tx)))
            break
