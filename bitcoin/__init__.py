# Copyright (C) 2012-2018 The python-bitcoinlib developers
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

# Note that setup.py can break if __init__.py imports any external
# dependencies, as these might not be installed when setup.py runs. In this
# case __version__ could be moved to a separate version.py and imported here.
__version__ = '0.10.2dev'

class MainParams(bitcoin.core.CoreMainParams):
    MESSAGE_START = b'\xf9\xbe\xb4\xd9'
    DEFAULT_PORT = 8333
    RPC_PORT = 8332
    DNS_SEEDS = (('bitcoin.sipa.be', 'seed.bitcoin.sipa.be'),
                 ('bluematt.me', 'dnsseed.bluematt.me'),
                 ('dashjr.org', 'dnsseed.bitcoin.dashjr.org'),
                 ('bitcoinstats.com', 'seed.bitcoinstats.com'),
                 ('xf2.org', 'bitseed.xf2.org'),
                 ('bitcoin.jonasschnelli.ch', 'seed.bitcoin.jonasschnelli.ch'))
    BASE58_PREFIXES = {'PUBKEY_ADDR':0,
                       'SCRIPT_ADDR':5,
                       'SECRET_KEY' :128}

class TestNetParams(bitcoin.core.CoreTestNetParams):
    MESSAGE_START = b'\x0b\x11\x09\x07'
    DEFAULT_PORT = 18333
    RPC_PORT = 18332
    DNS_SEEDS = (('testnetbitcoin.jonasschnelli.ch', 'testnet-seed.bitcoin.jonasschnelli.ch'),
                 ('petertodd.org', 'seed.tbtc.petertodd.org'),
                 ('bluematt.me', 'testnet-seed.bluematt.me'),
                 ('bitcoin.schildbach.de', 'testnet-seed.bitcoin.schildbach.de'))
    BASE58_PREFIXES = {'PUBKEY_ADDR':111,
                       'SCRIPT_ADDR':196,
                       'SECRET_KEY' :239}

class RegTestParams(bitcoin.core.CoreRegTestParams):
    MESSAGE_START = b'\xfa\xbf\xb5\xda'
    DEFAULT_PORT = 18444
    RPC_PORT = 18443
    DNS_SEEDS = ()
    BASE58_PREFIXES = {'PUBKEY_ADDR':111,
                       'SCRIPT_ADDR':196,
                       'SECRET_KEY' :239}

# DASH - https://github.com/dashpay/dash/blob/master/src/chainparams.cpp
#      - https://github.com/dashpay/dash/blob/master/src/base58.h
class MainDashParams(bitcoin.core.CoreMainParams):
    RPC_PORT = 9998
    BASE58_PREFIXES = {'PUBKEY_ADDR':76,
                       'SCRIPT_ADDR':16,
                       'SECRET_KEY' :204}
class TestNetDashParams(bitcoin.core.CoreTestNetParams):
    RPC_PORT = 19998
    BASE58_PREFIXES = {'PUBKEY_ADDR':140,
                       'SCRIPT_ADDR':19,
                       'SECRET_KEY' :239}
class RegTestDashParams(bitcoin.core.CoreRegTestParams):
    #MESSAGE_START = b'\xfa\xbf\xb5\xda'
    #DEFAULT_PORT = 18444
    RPC_PORT = 19998
    #DNS_SEEDS = ()
    BASE58_PREFIXES = {'PUBKEY_ADDR':140,
                       'SCRIPT_ADDR':19,
                       'SECRET_KEY' :239}

# Litecoin - https://github.com/litecoin-project/litecoin/blob/master/src/chainparams.cpp
class MainLitecoinParams(bitcoin.core.CoreMainParams):
    RPC_PORT = 9332
    BASE58_PREFIXES = {'PUBKEY_ADDR':48,  # 0x30 - L addresses
                       'SCRIPT_ADDR':50,  # 0x32 - new M addresses
#                       'SCRIPT_ADDR':5,   # 0x05 - 3 addresses (deprecated)
                       'SECRET_KEY' :176} 
class TestNetLitecoinParams(bitcoin.core.CoreTestNetParams):
    RPC_PORT = 19332
    BASE58_PREFIXES = {'PUBKEY_ADDR':111,
                       'SCRIPT_ADDR': 58,
#                       'SCRIPT_ADDR':196,
                       'SECRET_KEY' :239}
class RegTestLitecoinParams(bitcoin.core.CoreRegTestParams):
    RPC_PORT = 19332
    BASE58_PREFIXES = {'PUBKEY_ADDR':111,  # 0x6f - m or n addresses
                       'SCRIPT_ADDR': 58,  # 0x3a - new Q addresses
#                       'SCRIPT_ADDR':196,  # 0xC4 - 2 addresses (deprecated)
                       'SECRET_KEY' :239} 

#
# See:
#   https://github.com/libbitcoin/libbitcoin-system/wiki/Altcoin-Version-Mappings
#
ClientParams = {}

ClientParams["BTC"  ] = {}
ClientParams["BTC" ]["mainnet"] =    MainParams;
ClientParams["BTC" ]["testnet"] = TestNetParams;
ClientParams["BTC" ]["regtest"] = RegTestParams;

ClientParams["DASH" ] = {}
ClientParams["DASH"]["mainnet"] =    MainDashParams;
ClientParams["DASH"]["testnet"] = TestNetDashParams;
ClientParams["DASH"]["regtest"] = RegTestDashParams;

ClientParams["LTC"  ] = {}
ClientParams["LTC" ]["mainnet"] =    MainLitecoinParams;
ClientParams["LTC" ]["testnet"] = TestNetLitecoinParams;
ClientParams["LTC" ]["regtest"] = RegTestLitecoinParams;

"""Master global setting for what chain params we're using.

However, don't set this directly, use SelectParams() instead so as to set the
bitcoin.core.params correctly too.
"""
#params = bitcoin.core.coreparams = MainParams()
params = MainParams()

def SelectParams(name):
    """Select the chain parameters to use

    name is one of 'mainnet', 'testnet', 'regtest' or 'regtest-DASH'

    Default chain is 'mainnet'
    """
    global params


    # Split the name into coin name and network name.
    parts = name.split('-');
    if len(parts)==1:
        network = parts[0]
        coin = "BTC"
    else:
        network = parts[0]
        coin = parts[1]

    bitcoin.core._SelectCoreParams(network)
    try:
        params = ClientParams[coin][network]
    except:
        raise ValueError('Unknown chain %r and coin %r' % (network, coin))

