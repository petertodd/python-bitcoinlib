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

from __future__ import absolute_import, division, print_function, unicode_literals

import unittest
import base64

from bitcoin import SelectParams
from bitcoin.rpc import Proxy, split_hostport

class Test_RPC(unittest.TestCase):

    def tearDown(self):
        SelectParams('mainnet')

    def test_split_hostport(self):
        def T(hostport, expected_pair):
            (host, port) = split_hostport(hostport)
            self.assertEqual((host, port), expected_pair)

        T('localhost', ('localhost', None))
        T('localhost:123', ('localhost', 123))
        T('localhost:0', ('localhost:0', None))
        T('localhost:88888', ('localhost:88888', None))
        T('lo.cal.host:123', ('lo.cal.host', 123))
        T('lo.cal.host:123_', ('lo.cal.host:123_', None))
        T('lo:cal:host:123', ('lo:cal:host:123', None))
        T('local:host:123', ('local:host:123', None))
        T('[1a:2b:3c]:491', ('[1a:2b:3c]', 491))
        # split_hostport doesn't care what's in square brackets
        T('[local:host]:491', ('[local:host]', 491))
        T('[local:host]:491934', ('[local:host]:491934', None))
        T('.[local:host]:491', ('.[local:host]:491', None))
        T('[local:host].:491', ('[local:host].:491', None))
        T('[local:host]:p491', ('[local:host]:p491', None))

    def test_parse_config(self):
        conf_file_contents = """
            listen=1
            server=1

            rpcpassword=somepass # should be overriden

            regtest.rpcport = 8123

            rpcport = 8888

            [main]
            rpcuser=someuser1
            rpcpassword=somepass1
            rpcconnect=127.0.0.10

            [test]
            rpcpassword=somepass2
            rpcconnect=127.0.0.11
            rpcport = 9999

            [regtest]
            rpcuser=someuser3
            rpcpassword=somepass3
            rpcconnect=127.0.0.12
            """

        rpc = Proxy(btc_conf_file_contents=conf_file_contents)
        self.assertEqual(rpc._BaseProxy__service_url, 'http://127.0.0.10:8888')
        authpair = "someuser1:somepass1"
        authhdr = "Basic " + base64.b64encode(authpair.encode('utf8')
                                              ).decode('utf8')
        self.assertEqual(rpc._BaseProxy__auth_header, authhdr.encode('utf-8'))

        SelectParams('testnet')

        rpc = Proxy(btc_conf_file_contents=conf_file_contents)
        self.assertEqual(rpc._BaseProxy__service_url, 'http://127.0.0.11:9999')
        authpair = ":somepass2"  # no user specified
        authhdr = "Basic " + base64.b64encode(authpair.encode('utf8')
                                              ).decode('utf8')
        self.assertEqual(rpc._BaseProxy__auth_header, authhdr.encode('utf-8'))

        SelectParams('regtest')

        rpc = Proxy(btc_conf_file_contents=conf_file_contents)
        self.assertEqual(rpc._BaseProxy__service_url, 'http://127.0.0.12:8123')
        authpair = "someuser3:somepass3"
        authhdr = "Basic " + base64.b64encode(authpair.encode('utf8')
                                              ).decode('utf8')
        self.assertEqual(rpc._BaseProxy__auth_header, authhdr.encode('utf-8'))

        SelectParams('mainnet')

# The following Tests are disabled, see discussion below.
# "Looks like your unit tests won't work if Bitcoin Core isn't running;
# maybe they in turn need to check that and disable the test if core isn't available?"
# https://github.com/petertodd/python-bitcoinlib/pull/10
#    def test_can_validate(self):
#        working_address = '1CB2fxLGAZEzgaY4pjr4ndeDWJiz3D3AT7'
#        p = Proxy()
#        r = p.validateAddress(working_address)
#        self.assertEqual(r['address'], working_address)
#        self.assertEqual(r['isvalid'], True)
#
#    def test_cannot_validate(self):
#        non_working_address = 'LTatMHrYyHcxhxrY27AqFN53bT4TauR86h'
#        p = Proxy()
#        r = p.validateAddress(non_working_address)
#        self.assertEqual(r['isvalid'], False)
