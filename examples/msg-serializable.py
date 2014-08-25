#!/usr/bin/env python3
#
# serialize.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

"""Serialize some bitcoin datastructures and show them in serialized and repr form."""

import sys
if sys.version_info.major < 3:
    sys.stderr.write('Sorry, Python 3.x required by this example.\n')
    sys.exit(1)

from bitcoin import SelectParams
from bitcoin.messages import msg_version, msg_tx, msg_block

SelectParams('mainnet')


for c in [msg_version, msg_tx, msg_block]:
    # Instanciate the message with some default values
    msg = c()
    name = c.__name__
    print(name + " repr:")
    print(msg)
    print(name + " serialized:")
    print(msg.to_bytes())
