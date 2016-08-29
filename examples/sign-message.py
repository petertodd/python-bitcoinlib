#!/usr/bin/env python3
#
# Copyright (C) 2013-2015 The python-bitcoinlib developers
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

from bitcoin.wallet import CBitcoinSecret, P2PKHBitcoinAddress
from bitcoin.signmessage import BitcoinMessage, VerifyMessage, SignMessage

key = CBitcoinSecret("L4vB5fomsK8L95wQ7GFzvErYGht49JsCPJyJMHpB4xGM6xgi2jvG")
address = P2PKHBitcoinAddress.from_pubkey(key.pub)  # "1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G"
message = "Hey I just met you, and this is crazy, but I'll verify my address, maybe ..."

message = BitcoinMessage(message)

signature = SignMessage(key, message)

print(key, address)
print("Address: %s" % address)
print("Message: %s" % message)
print("\nSignature: %s" % signature)
print("\nVerified: %s" % VerifyMessage(address, message, signature))

print("\nTo verify using bitcoin core;")
print("`bitcoin-cli verifymessage %s \"%s\" \"%s\"`" % (address, signature.decode('ascii'), message))
