#!/usr/bin/python3
#
# make-bootstrap-rpc.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

"""Make a boostrap.dat file by getting the blocks from the RPC interface."""

import sys
if sys.version_info.major < 3:
    sys.stderr.write('Sorry, Python 3.x required by this example.\n')
    sys.exit(1)

import bitcoin
from bitcoin.core import CBlock
import bitcoin.rpc

import struct
import sys
import time

try:
    if len(sys.argv) not in (2, 3):
        raise Exception

    n = int(sys.argv[1])

    if len(sys.argv) == 3:
        bitcoin.SelectParams(sys.argv[2])
except Exception as ex:
    print('Usage: %s <block-height> [network=(mainnet|testnet|regtest)] > bootstrap.dat' % sys.argv[0], file=sys.stderr)
    sys.exit(1)


proxy = bitcoin.rpc.Proxy()

total_bytes = 0
start_time = time.time()

fd = sys.stdout.buffer
for i in range(n+1):
    block = proxy.getblock(proxy.getblockhash(i))

    block_bytes = block.serialize()

    total_bytes += len(block_bytes)
    print('%.2f KB/s, height %d, %d bytes' %
            ((total_bytes/1000)/(time.time() - start_time),
             i, len(block_bytes)),
          file=sys.stderr)

    fd.write(bitcoin.params.MESSAGE_START)
    fd.write(struct.pack('<i', len(block_bytes)))
    fd.write(block_bytes)
