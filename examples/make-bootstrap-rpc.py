#!/usr/bin/python3
#
# make-bootstrap-rpc.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

"""Make a boostrap.dat file by getting the blocks from the RPC interface."""

from bitcoin.core import CBlock
import bitcoin.core.coredefs
import bitcoin.rpc

import struct
import sys
import time

msg_start = bitcoin.core.coredefs.NETWORKS['mainnet'].msg_start
try:
    if len(sys.argv) not in (2, 3):
        raise Exception

    n = int(sys.argv[1])

    if len(sys.argv) == 2:
        msg_start = bitcoin.core.coredefs.NETWORKS[sys.argv[2]].msg_start
except Exception as ex:
    print('Usage: %s <block-height> [network=mainnet] > bootstrap.dat' % sys.argv[0], file=sys.stderr)
    print('', file=sys.stderr)
    print('Where network is one of %s' % (tuple(bitcoin.core.coredefs.NETWORKS.keys()),), file=sys.stderr)
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

    fd.write(msg_start)
    fd.write(struct.pack('<i', len(block_bytes)))
    fd.write(block_bytes)
