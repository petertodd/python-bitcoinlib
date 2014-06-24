#!/usr/bin/python2.7
#
# bip-0070-payment-protocol.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

"""Bip-0070-related functionality

Handles incoming serialized string data in the form of a http request 
and returns an appropriate response using googles protocol buffers.
"""

# https://github.com/bitcoin/bips/blob/master/bip-0070/paymentrequest.proto
import payments_pb2
o = payments_pb2

import bitcoin
#bitcoin.SelectParams('testnet')
from bitcoin.wallet import CBitcoinAddress
from bitcoin.core.script import CScript
from bitcoin.rpc import Proxy

from time import time

def payment_request(request):
    """Generates a PaymentRequest object"""

    bc = Proxy()
    btc = bc.getnewaddress()

#   Setting the 'amount' field to 0 (zero) should prompt the user to enter
#   the amount for us but a bug in bitcoin core qt version 0.9.1 (at time of
#   writing) wrongly informs us that the value is too small and aborts.
#   https://github.com/bitcoin/bitcoin/issues/3095
#   Also there can be no leading 0's (zeros).
    btc_amount = 100000
    serialized_pubkey = btc.to_scriptPubKey()

    pdo = o.PaymentDetails()
    pdo.outputs.add(amount = btc_amount,script = serialized_pubkey)
    pdo.time = int(time())
    pdo.memo = 'String shown to user before confirming payment'
    pdo.payment_url = 'http://payment_ack.url'

    pro = o.PaymentRequest()
    pro.serialized_payment_details = pdo.SerializeToString()

    return HttpResponse(pro.SerializeToString(), content_type="application/bitcoin-paymentrequest")


def payment_ack(request):
    """Generates a PaymentACK object, captures client refund address and returns a message"""

    pao = o.PaymentACK()
    pao.payment.ParseFromString(request.body)
    pao.memo = 'String shown to user after payment confirmation'

    refund_address = CBitcoinAddress.from_scriptPubKey(CScript(pao.payment.refund_to[0].script))

    return HttpResponse(pao.SerializeToString(), content_type="application/bitcoin-paymentack")
