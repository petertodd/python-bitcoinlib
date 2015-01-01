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

from __future__ import absolute_import, division, print_function, unicode_literals

import bitcoin.core

class MainParams(bitcoin.core.CoreChainParams):
    MESSAGE_START = b'\xf9\xbe\xb4\xd9'
    DEFAULT_PORT = 8333
    RPC_PORT = 8332
    DNS_SEEDS = (('bitcoin.sipa.be', 'seed.bitcoin.sipa.be'),
                 ('bluematt.me', 'dnsseed.bluematt.me'),
                 ('dashjr.org', 'dnsseed.bitcoin.dashjr.org'),
                 ('bitcoinstats.com', 'seed.bitcoinstats.com'),
                 ('xf2.org', 'bitseed.xf2.org'))
    BASE58_PREFIXES = {'PUBKEY_ADDR':0,
                       'SCRIPT_ADDR':5,
                       'SECRET_KEY' :128}

class TestNetParams(bitcoin.core.CoreTestNetParams):
    MESSAGE_START = b'\x0b\x11\x09\x07'
    DEFAULT_PORT = 18333
    RPC_PORT = 18332
    DNS_SEEDS = (('bitcoin.petertodd.org', 'testnet-seed.bitcoin.petertodd.org'),
                 ('bluematt.me', 'testnet-seed.bluematt.me'))
    BASE58_PREFIXES = {'PUBKEY_ADDR':111,
                       'SCRIPT_ADDR':196,
                       'SECRET_KEY' :239}

class RegTestParams(bitcoin.core.CoreRegTestParams):
    MESSAGE_START = b'\xfa\xbf\xb5\xda'
    DEFAULT_PORT = 18444
    RPC_PORT = 18332
    DNS_SEEDS = ()
    BASE58_PREFIXES = {'PUBKEY_ADDR':111,
                       'SCRIPT_ADDR':196,
                       'SECRET_KEY' :239}

class DogeMainParams(bitcoin.core.CoreDogeMainParams):
    MESSAGE_START = b'\xc0\xc0\xc0\xc0'
    DEFAULT_PORT = 22556
    RPC_PORT = 22555
    DNS_SEEDS = (('dogecoin.com', 'seed.dogecoin.com'),
                 ('mophides.com', 'seed.mophides.com'),
                 ('dglibrary.org', 'seed.dglibrary.org'),
                 ('dogechain.info', 'seed.dogechain.info'))
    BASE58_PREFIXES = {'PUBKEY_ADDR':30,
                       'SCRIPT_ADDR':22,
                       'SECRET_KEY' :158}

class DogeTestNetParams(bitcoin.core.CoreDogeTestNetParams):
    MESSAGE_START = b'\xfc\xc1\xb7\xdc'
    DEFAULT_PORT = 44556
    RPC_PORT = 44555
    DNS_SEEDS = (('lionservers.de', 'testdoge-seed-static.lionservers.de'))
    BASE58_PREFIXES = {'PUBKEY_ADDR':113,
                       'SCRIPT_ADDR':196,
                       'SECRET_KEY' :241}

"""Master global setting for what chain params we're using.

However, don't set this directly, use SelectParams() instead so as to set the
bitcoin.core.params correctly too.
"""
#params = bitcoin.core.coreparams = MainParams()
params = MainParams()

def SelectParams(name, coin = 'BTC'):
    """Select the chain parameters to use

    name is one of 'mainnet', 'testnet', or 'regtest'

    Default chain is 'mainnet'
    """
    global params
    bitcoin.core._SelectCoreParams(name, coin)
    if coin == 'BTC':
        if name == 'mainnet':
            params = bitcoin.core.coreparams = MainParams()
        elif name == 'testnet':
            params = bitcoin.core.coreparams = TestNetParams()
        elif name == 'regtest':
            params = bitcoin.core.coreparams = RegTestParams()
        else:
            raise ValueError('Unknown Bitcoin chain %r' % name)
    elif coin == 'DOGE':
        if name == 'mainnet':
            params = bitcoin.core.coreparams = DogeMainParams()
        elif name == 'testnet':
            params = bitcoin.core.coreparams = DogeTestNetParams()
        else:
            raise ValueError('Unknown Dogecoin chain %r' % name)
    else:
        raise ValueError('Unknown coin %r' % coin)
