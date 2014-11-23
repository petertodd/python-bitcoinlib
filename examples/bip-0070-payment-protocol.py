#!/usr/bin/python2.7

# Copyright (C) 2013-2014 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

"""Bip-0070-related functionality
Creates http(s) response objects suitable for use with
bitcoin bip 70 using googles protocol buffers.
"""

import urllib2

import bitcoin
#bitcoin.SelectParams('testnet')
from bitcoin.wallet import CBitcoinAddress
from bitcoin.core.script import CScript
from bitcoin.rpc import Proxy

from time import time

##  To access the following librarys you will need to install pycrypto.
##  This can be done using pip 'sudo pip install pycrypto'
##  pycrypto hashing library imports
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

##  The payments_pb2 template is available at
##  https://github.com/bitcoin/bips/blob/master/bip-0070/paymentrequest.proto
import payments_pb2
##  Instantiate main protobuf object (o).
o = payments_pb2

def paymentrequest():
    """Generates a http(s) PaymentRequest object"""

##  Setting the 'amount' field to 0 (zero) should prompt the user to enter
##  the amount for us but a bug in bitcoin core qt version 0.9.1 (at time of
##  writing) wrongly informs us that the value is too small and aborts.
##  https://github.com/bitcoin/bitcoin/issues/3095
##  Also there can be no leading 0's (zeros).
    btc_amount = 100000000 # 1 BTC
    serialized_pubkey = btc_address.to_scriptPubKey()

##  Instantiate PaymentDetails object (pdo).
    pdo = o.PaymentDetails()
    #pdo.network = 'test'
    pdo.outputs.add(amount = btc_amount, script = serialized_pubkey)
    pdo.time = int(time())
    pdo.memo = 'String shown to user before confirming payment'
    pdo.payment_url = 'http://payment_ack.url'

#####################################################################################################
##  If you want to enable ssl verification in your payment requests you will need to uncomment all ##
##  of the following CODE below.  If you're not interested in ssl then ignore the commented parts. ##
#####################################################################################################

##  Certificate chain example using nginx and ssl certificates obtained from comodo.com.
    #ssl_dir = '/etc/nginx/ssl/'
    #cert0 = open(ssl_dir + 'example_com.der', 'rb').read()
    #cert1 = open(ssl_dir + 'COMODORSADomainValidationSecureServerCA.der', 'rb').read()
    #cert2 = open(ssl_dir + 'COMODORSAAddTrustCA.der', 'rb').read()
    #cert3 = open(ssl_dir + 'AddTrustExternalCARoot.der', 'rb').read()

##  According to the documentation if you wish to use ssl the certificates are to be added one by one
##  using the 'append()' method in the correct order.
    #cert_list = (cert0, cert1, cert2, cert3)

##  Instantiate X509Certificates object (xco)
    #xco = o.X509Certificates()
    #for i in cert_list:
    #    xco.certificate.append(i)


##  Instantiate PaymentRequest object (pro)
    pro = o.PaymentRequest()
    #pro.pki_type = 'x509+sha256'
    #pro.pki_data = xco.SerializeToString()
    pro.serialized_payment_details = pdo.SerializeToString()

    #keyDER = open(ssl_dir + 'example.der', 'rb').read()

##  Documentation insists that the signature field should be manually set to empty before proceeding.
    #pro.signature = ""
    #pro_hash = SHA256.new(pro.SerializeToString())
    #private_key = RSA.importKey(keyDER)
    #signer = PKCS1_v1_5.new(private_key)
    #pro.signature = signer.sign(pro_hash)

    sds_pr = pro.SerializeToString()

    open('sds_pr_blob', 'wb').write(sds_pr)
    headers = {'Content-Type': 'application/bitcoin-payment',
               'Accept': 'application/bitcoin-paymentrequest'}
    http_response_object = urllib2.Request('file:sds_pr_blob', None, headers)

    return http_response_object

def payment_ack(serialized_Payment_message):
    """Generates a PaymentACK object, captures client refund address and returns a message"""

##  Instantiate PaymentACK object (pao)
    pao = o.PaymentACK()
    pao.payment.ParseFromString(serialized_Payment_message)
    pao.memo = 'String shown to user after payment confirmation'

    refund_address = CBitcoinAddress.from_scriptPubKey(CScript(pao.payment.refund_to[0].script))

    sds_pa = pao.SerializeToString()

    open('sds_pa_blob', 'wb').write(sds_pa)
    headers = {'Content-Type' : 'application/bitcoin-payment', 'Accept' : 'application/bitcoin-paymentack'}
    http_response_object = urllib2.Request('file:sds_pa_blob', None, headers)

    return http_response_object
