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

import bitcoin.rpc
from bitcoin.core import CBlock, CBlockHeader, lx, b2lx, COutPoint
from bitcoin.core.script import CScript
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret

def is_active():
    """
    Proxy raises ValueError if cookie file not found
    #FIXME is there a better way of doing this?
    """
    try:
        p = bitcoin.rpc.Proxy()
        return True
    except ValueError: 
        return False

class Test_RPC(unittest.TestCase):
    _IS_ACTIVE = is_active()
    # Tests disabled, see discussion below.
    # "Looks like your unit tests won't work if Bitcoin Core isn't running;
    # maybe they in turn need to check that and disable the test if core isn't available?"
    # https://github.com/petertodd/python-bitcoinlib/pull/10
    # Sachin Meier: "I've changed it so each test checks against the "
    #pass

    def test_getbestblockhash_and_header(self):
        if self._IS_ACTIVE:
            proxy = bitcoin.rpc.Proxy()
            blockhash = proxy.getbestblockhash()
            header = proxy.getblockheader(blockhash)
            self.assertTrue(isinstance(header, CBlockHeader))
        else:
            pass

    def test_getblock(self):
        if self._IS_ACTIVE:
            proxy = bitcoin.rpc.Proxy()
            blockhash = proxy.getbestblockhash()
            # Test from bytes
            block1 = proxy.getblock(blockhash)
            self.assertTrue(isinstance(block1, CBlock))
            # Test from str
            block2 = proxy.getblock("0000000000000000000b4b0daf89eac9d84138fc900b8c473d4da70742e93dd0")
            self.assertTrue(isinstance(block2, CBlock))
        else:
            pass

    def test_getblockcount_et_al(self):
        # This test could possibly false-fail if new blocks arrive. 
        # Highly unlikely since they're quick calls
        if self._IS_ACTIVE:
            proxy = bitcoin.rpc.Proxy()
            blockhash = proxy.getbestblockhash()
            height_from_hash = proxy.getblockstats(blockhash)["height"]
            height_from_count = proxy.getblockcount()
            height_from_chaintips = proxy.getchaintips()[0]["height"]
            height_from_chaintxstats = proxy.getchaintxstats()["window_final_block_height"]
            self.assertEqual(height_from_count, height_from_hash)
            self.assertEqual(height_from_chaintips, height_from_chaintxstats)
            self.assertEqual(height_from_chaintips, height_from_count)
        else:
            pass

    def test_txoutproofs(self):
        if self._IS_ACTIVE:
            proxy = bitcoin.rpc.Proxy()
            blockhash = "0000000000000000000317612505ebdbe2686856535903bb0a05d4629670d518"
            c_txid = "468564cfeba24ae321ee142e8786a53005f33051222e42f06fb2e9f048d0dba5"
            c_proof = "00e0ff3749d01e6bebeb55a3dc983f194a1e232dc7149aff308d0d000000000000000000e331c7b03923f8b98074c7abeb10f609804ea18a53389b310c560c555b5c7d90ac8f315ff8b41017108dcd6a2c0b00000da53b7cc71139618dee5368d2075cd50badb97b0b4e4ca07b3ff749006280ff05a5dbd048f0e9b26ff0422e225130f30530a586872e14ee21e34aa2ebcf648546a03eab6796b5ff607266d66cf75d10454ac8370f0630c02395da56e8a3f9bc07b5adf47993ba6e33a625a7243c87111a93b592627efe4d6a1c3385685e8b0ae37e05b93e0de10db4c82466baf83da8c32a599fe2b6cace3c7a1b0b59e591071a656f93a19c08a4cc93d95e511220db284c72da6669355aa49226d61287e6048166e87bf93847a39f1c7552088c1831aabb4a6f29aaaa951eaafeaca21aea982068a2a51ff1088df84cdb7d5cdfbad8f91f2f75f45403d78b0fee2e68fdf5f076e8cff72482184a62b37e5af25b9227f27bedd3ebef27d01b0f99e0c456922f8fd16ad36445ca52bde44e42b145803130a420feb6fc0d8d9f2b9e12954ad8ea537ea843e7bddad228f7a754df0bf4337361f6bde81304d9cae789adaafd7b607ac49e422c5b01b3b859f777bb86f69e4047b9fe9752db5822becaa579b0066dbfaced20ab383ea8caa113437564dbcef9c04f224b352364baaddd7bfdb517383a04ff2f0000"
            proof = proxy.gettxoutproof([c_txid], blockhash)
            txid = b2lx(proxy.verifytxoutproof(proof)[0])
            self.assertEqual(c_txid, txid) # CHECK THAT TXID comes out well. maybe hex it
            self.assertEqual(c_proof, proof)
        else:
            pass

    def test_can_validate(self):
        if self._IS_ACTIVE:
            p = bitcoin.rpc.Proxy()
            working_address = '1CB2fxLGAZEzgaY4pjr4ndeDWJiz3D3AT7'
            r = p.validateaddress(working_address)
            self.assertEqual(str(r['address']), working_address)
            self.assertEqual(r['isvalid'], True)
        else:
            pass

    def test_cannot_validate(self):
        if self._IS_ACTIVE:
          non_working_address = 'LTatMHrYyHcxhxrY27AqFN53bT4TauR86h'
          p = bitcoin.rpc.Proxy()
          r = p.validateaddress(non_working_address)
          self.assertEqual(r['isvalid'], False)
        else:
            pass

    def test_deterministic_multisig(self):
        if self._IS_ACTIVE:
            p = bitcoin.rpc.Proxy()
            pubkeys = ["02389e049d7baf3b4170ddb5c85f0ac22198572d76e0fee3fdb6c434ac689f270d", 
            "0364ca1b46c1aaee3f40a35b5d32937b2616ace2914fdacdc1bf95f53fe06514d0", 
            "03eac5ba66377c3bc1a92d1db3c22dc8cd0626a17f22c13d481fd14ca1fa2cf7f6"]
            multisig_addr = "39NHQCfNjGRLGuAH5tuPXfERJsDncYehyH"
            redeemScript = "522102389e049d7baf3b4170ddb5c85f0ac22198572d76e0fee3fdb6c434ac689f270d210364ca1b46c1aaee3f40a35b5d32937b2616ace2914fdacdc1bf95f53fe06514d02103eac5ba66377c3bc1a92d1db3c22dc8cd0626a17f22c13d481fd14ca1fa2cf7f653ae"
            r = p.createmultisig(2, pubkeys)
            self.assertEqual(str(r['address']), multisig_addr)
            self.assertEqual(r['redeemScript'].hex(), redeemScript)
        else:
            pass

    def test_signmessagewithprivkey(self):
        """As of now, signmessagewithprivkey returns string of 
        signature. Later this should change 
        """
        if self._IS_ACTIVE:    
            proxy = bitcoin.rpc.Proxy()
            c_sig = "Hy+OtvwJnE0ylgORtqG8/U9ZP11IW38GaSCxIvlAcrLVGWJV61Zxfb/h/A51VPEJZkIFogqxceIMTCppfEOyl5I="
            privkey_txt = "Kya9eoTsoct6rsztC5rSLfuU2S4Dw5xtgCy2uPJgbkSLXd4FqquD"
            privkey = CBitcoinSecret(privkey_txt)
            msg = "So Long as Men Die"
            # Check from CBitcoinSecret
            sig = proxy.signmessagewithprivkey(privkey, msg)
            self.assertEqual(sig, c_sig)
            # Check from str
            sig2 = proxy.signmessagewithprivkey(privkey_txt, msg)
            self.assertEqual(sig2, c_sig)
        else:
            pass

    def test_verifymessage(self):      
        if self._IS_ACTIVE: 
            proxy = bitcoin.rpc.Proxy()
            sig = "ILRG2SnP6oPIofrfEDVk71J8rvM2KKbXU+D4+xWB2RRST4I2ilCTc7rXCS0Zu1/ousOX4aFhCrF815De71xZyxY="
            addr_txt = "14wCZ9KpTuXB35kdYH2Loy1oP1ak1BT3JH" # Not corresponding addr as signwithprivkey
            addr = CBitcoinAddress(addr_txt)
            msg = "So Long as Men Die" 
            #Check with both address and str
            self.assertTrue(proxy.verifymessage(addr_txt, sig, msg))
            self.assertTrue(proxy.verifymessage(addr, sig, msg))
            return proxy.verifymessage(addr, sig, msg)
        else:
            pass

    # def test_setxfee(self):
    #     """ This test will change settings of user's core instance, so
    #     It is commented out for now. 
    #     """
    #     if self._IS_ACTIVE:
    #         proxy = bitcoin.rpc.Proxy()
    #         self.assertTrue( proxy.settxfee(2) )
    #     else:
    #         pass

    def test_gettxout(self):
        """Txout disappears if spent, so difficult to set static test"""
        if self._IS_ACTIVE:
            proxy = bitcoin.rpc.Proxy()
            txo = COutPoint(lx("2700507d971a25728a257ed208ba409e7510f861dec928a478ee92f5ef2b4527"), 0)
            r = proxy.gettxout(txo)
            script = CScript.fromhex("76a9147179f4af7439435720637ee3276aabed1440719188ac")
            self.assertEqual(r['txout'].scriptPubKey, script)
        else:
            pass


    def test_getmininginfo(self):
        if self._IS_ACTIVE:
            proxy = bitcoin.rpc.Proxy()
            proxy.getmininginfo()
        else:
            pass

