# Copyright (C) The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.


import unittest
import tempfile
from bitcoin.rpc import Proxy, parse_conf_file, get_authpair


class TestConfigFileparser(unittest.TestCase):
    def test_parse(self):
        with tempfile.TemporaryFile("w+") as fd:
            fd.write("""
datadir = /home/user/.bitcoin
# Comment
dbcache = 300 # in MB # Inline comment
""")
            fd.seek(0)
            self.assertEqual(parse_conf_file(fd), {
                "datadir": "/home/user/.bitcoin",
                "dbcache": "300"
            })

    def test_authpair_from_conf(self):
        self.assertEqual(
            "user:insecure_youll_be_robed",
            get_authpair(
                {
                    "rpcuser": "user",
                    "rpcpassword": "insecure_youll_be_robed"
                }, "mainnet", "dummy.file"))

    def test_authpair_fail(self):
        with self.assertRaises(ValueError):
            get_authpair({}, "testnet", "ou/conf")



class Test_RPC(unittest.TestCase):
    # Tests disabled, see discussion below.
    # "Looks like your unit tests won't work if Bitcoin Core isn't running;
    # maybe they in turn need to check that and disable the test if core isn't available?"
    # https://github.com/petertodd/python-bitcoinlib/pull/10
    pass

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
