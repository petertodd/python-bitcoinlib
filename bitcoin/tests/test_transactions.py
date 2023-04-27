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


import json
import unittest
import os

from bitcoin.core import *
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH

from bitcoin.tests.test_scripteval import parse_script

def load_test_vectors(name):
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        for test_case in json.load(fd):
            # Comments designated by single length strings
            if len(test_case) == 1:
                continue
            assert len(test_case) == 3

            prevouts = {}
            for json_prevout in test_case[0]:
                assert len(json_prevout) == 3
                n = json_prevout[1]
                if n == -1:
                    n = 0xffffffff
                prevout = COutPoint(lx(json_prevout[0]), n)
                prevouts[prevout] = parse_script(json_prevout[2])

            tx = CTransaction.deserialize(x(test_case[1]))
            enforceP2SH = test_case[2]

            yield (prevouts, tx, enforceP2SH)

class Test_COutPoint(unittest.TestCase):
    def test_is_null(self):
        self.assertTrue(COutPoint().is_null())
        self.assertTrue(COutPoint(hash=b'\x00'*32,n=0xffffffff).is_null())
        self.assertFalse(COutPoint(hash=b'\x00'*31 + b'\x01').is_null())
        self.assertFalse(COutPoint(n=1).is_null())

    def test_repr(self):
        def T(outpoint, expected):
            actual = repr(outpoint)
            self.assertEqual(actual, expected)
        T( COutPoint(),
          'COutPoint()')
        T( COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0),
          "COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0)")

    def test_str(self):
        def T(outpoint, expected):
            actual = str(outpoint)
            self.assertEqual(actual, expected)
        T(COutPoint(),
          '0000000000000000000000000000000000000000000000000000000000000000:4294967295')
        T(COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0),
                       '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:0')
        T(COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 10),
                       '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:10')

class Test_CMutableOutPoint(unittest.TestCase):
    def test_GetHash(self):
        """CMutableOutPoint.GetHash() is not cached"""
        outpoint = CMutableOutPoint()

        h1 = outpoint.GetHash()
        outpoint.n = 1

        self.assertNotEqual(h1, outpoint.GetHash())


class Test_CTxIn(unittest.TestCase):
    def test_is_final(self):
        self.assertTrue(CTxIn().is_final())
        self.assertTrue(CTxIn(nSequence=0xffffffff).is_final())
        self.assertFalse(CTxIn(nSequence=0).is_final())

    def test_repr(self):
        def T(txin, expected):
            actual = repr(txin)
            self.assertEqual(actual, expected)
        T( CTxIn(),
          'CTxIn(COutPoint(), CScript([]), 0xffffffff)')

class Test_CMutableTxIn(unittest.TestCase):
    def test_GetHash(self):
        """CMutableTxIn.GetHash() is not cached"""
        txin = CMutableTxIn()

        h1 = txin.GetHash()
        txin.prevout.n = 1

        self.assertNotEqual(h1, txin.GetHash())

class Test_CTransaction(unittest.TestCase):
    def test_is_coinbase(self):
        tx = CMutableTransaction()
        self.assertFalse(tx.is_coinbase())

        tx.vin.append(CMutableTxIn())

        # IsCoinBase() in reference client doesn't check if vout is empty
        self.assertTrue(tx.is_coinbase())

        tx.vin[0].prevout.n = 0
        self.assertFalse(tx.is_coinbase())

        tx.vin[0] = CTxIn()
        tx.vin.append(CTxIn())
        self.assertFalse(tx.is_coinbase())

    def test_tx_valid(self):
        for prevouts, tx, enforceP2SH in load_test_vectors('tx_valid.json'):
            try:
                CheckTransaction(tx)
            except CheckTransactionError:
                self.fail('tx failed CheckTransaction(): ' \
                        + str((prevouts, b2x(tx.serialize()), enforceP2SH)))
                continue

            for i in range(len(tx.vin)):
                flags = set()
                if enforceP2SH:
                    flags.add(SCRIPT_VERIFY_P2SH)

                VerifyScript(tx.vin[i].scriptSig, prevouts[tx.vin[i].prevout], tx, i, flags=flags)


    def test_tx_invalid(self):
        for prevouts, tx, enforceP2SH in load_test_vectors('tx_invalid.json'):
            try:
                CheckTransaction(tx)
            except CheckTransactionError:
                continue

            with self.assertRaises(ValidationError):
                for i in range(len(tx.vin)):
                    flags = set()
                    if enforceP2SH:
                        flags.add(SCRIPT_VERIFY_P2SH)

                    VerifyScript(tx.vin[i].scriptSig, prevouts[tx.vin[i].prevout], tx, i, flags=flags)

    def test_calc_weight(self):
        # test vectors taken from rust-bitcoin
        txs = [
               # one segwit input (P2WPKH)
               ('020000000001018a763b78d3e17acea0625bf9e52b0dc1beb2241b2502185348ba8ff4a253176e0100000000ffffffff0280d725000000000017a914c07ed639bd46bf7087f2ae1dfde63b815a5f8b488767fda20300000000160014869ec8520fa2801c8a01bfdd2e82b19833cd0daf02473044022016243edad96b18c78b545325aaff80131689f681079fb107a67018cb7fb7830e02205520dae761d89728f73f1a7182157f6b5aecf653525855adb7ccb998c8e6143b012103b9489bde92afbcfa85129a82ffa512897105d1a27ad9806bded27e0532fc84e700000000', 565),
               # one segwit input (P2WSH)
               ('01000000000101a3ccad197118a2d4975fadc47b90eacfdeaf8268adfdf10ed3b4c3b7e1ad14530300000000ffffffff0200cc5501000000001976a91428ec6f21f4727bff84bb844e9697366feeb69f4d88aca2a5100d00000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220548f11130353b3a8f943d2f14260345fc7c20bde91704c9f1cbb5456355078cd0220383ed4ed39b079b618bcb279bbc1f2ca18cb028c4641cb522c9c5868c52a0dc20147304402203c332ecccb3181ca82c0600520ee51fee80d3b4a6ab110945e59475ec71e44ac0220679a11f3ca9993b04ccebda3c834876f353b065bb08f50076b25f5bb93c72ae1016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000', 766),
               # one segwit input (P2WPKH) and two legacy inputs (P2PKH)
               ('010000000001036b6b6ac7e34e97c53c1cc74c99c7948af2e6aac75d8778004ae458d813456764000000006a473044022001deec7d9075109306320b3754188f81a8236d0d232b44bc69f8309115638b8f02204e17a5194a519cf994d0afeea1268740bdc10616b031a521113681cc415e815c012103488d3272a9fad78ee887f0684cb8ebcfc06d0945e1401d002e590c7338b163feffffffffc75bd7aa6424aee972789ec28ba181254ee6d8311b058d165bd045154d7660b0000000006b483045022100c8641bcbee3e4c47a00417875015d8c5d5ea918fb7e96f18c6ffe51bc555b401022074e2c46f5b1109cd79e39a9aa203eadd1d75356415e51d80928a5fb5feb0efee0121033504b4c6dfc3a5daaf7c425aead4c2dbbe4e7387ce8e6be2648805939ecf7054ffffffff494df3b205cd9430a26f8e8c0dc0bb80496fbc555a524d6ea307724bc7e60eee0100000000ffffffff026d861500000000001976a9145c54ed1360072ebaf56e87693b88482d2c6a101588ace407000000000000160014761e31e2629c6e11936f2f9888179d60a5d4c1f900000247304402201fa38a67a63e58b67b6cfffd02f59121ca1c8a1b22e1efe2573ae7e4b4f06c2b022002b9b431b58f6e36b3334fb14eaecee7d2f06967a77ef50d8d5f90dda1057f0c01210257dc6ce3b1100903306f518ee8fa113d778e403f118c080b50ce079fba40e09a00000000', 1755),
               # three legacy inputs (P2PKH)
               ('0100000003e4d7be4314204a239d8e00691128dca7927e19a7339c7948bde56f669d27d797010000006b483045022100b988a858e2982e2daaf0755b37ad46775d6132057934877a5badc91dee2f66ff022020b967c1a2f0916007662ec609987e951baafa6d4fda23faaad70715611d6a2501210254a2dccd8c8832d4677dc6f0e562eaaa5d11feb9f1de2c50a33832e7c6190796ffffffff9e22eb1b3f24c260187d716a8a6c2a7efb5af14a30a4792a6eeac3643172379c000000006a47304402207df07f0cd30dca2cf7bed7686fa78d8a37fe9c2254dfdca2befed54e06b779790220684417b8ff9f0f6b480546a9e90ecee86a625b3ea1e4ca29b080da6bd6c5f67e01210254a2dccd8c8832d4677dc6f0e562eaaa5d11feb9f1de2c50a33832e7c6190796ffffffff1123df3bfb503b59769731da103d4371bc029f57979ebce68067768b958091a1000000006a47304402207a016023c2b0c4db9a7d4f9232fcec2193c2f119a69125ad5bcedcba56dd525e02206a734b3a321286c896759ac98ebfd9d808df47f1ce1fbfbe949891cc3134294701210254a2dccd8c8832d4677dc6f0e562eaaa5d11feb9f1de2c50a33832e7c6190796ffffffff0200c2eb0b000000001976a914e5eb3e05efad136b1405f5c2f9adb14e15a35bb488ac88cfff1b000000001976a9144846db516db3130b7a3c92253599edec6bc9630b88ac00000000', 2080),
               # one segwit input (P2TR)
               ('01000000000101b5cee87f1a60915c38bb0bc26aaf2b67be2b890bbc54bb4be1e40272e0d2fe0b0000000000ffffffff025529000000000000225120106daad8a5cb2e6fc74783714273bad554a148ca2d054e7a19250e9935366f3033760000000000002200205e6d83c44f57484fd2ef2a62b6d36cdcd6b3e06b661e33fd65588a28ad0dbe060141df9d1bfce71f90d68bf9e9461910b3716466bfe035c7dbabaa7791383af6c7ef405a3a1f481488a91d33cd90b098d13cb904323a3e215523aceaa04e1bb35cdb0100000000', 617),
               # one legacy input (P2PKH)
               ('0100000001c336895d9fa674f8b1e294fd006b1ac8266939161600e04788c515089991b50a030000006a47304402204213769e823984b31dcb7104f2c99279e74249eacd4246dabcf2575f85b365aa02200c3ee89c84344ae326b637101a92448664a8d39a009c8ad5d147c752cbe112970121028b1b44b4903c9103c07d5a23e3c7cf7aeb0ba45ddbd2cfdce469ab197381f195fdffffff040000000000000000536a4c5058325bb7b7251cf9e36cac35d691bd37431eeea426d42cbdecca4db20794f9a4030e6cb5211fabf887642bcad98c9994430facb712da8ae5e12c9ae5ff314127d33665000bb26c0067000bb0bf00322a50c300000000000017a9145ca04fdc0a6d2f4e3f67cfeb97e438bb6287725f8750c30000000000001976a91423086a767de0143523e818d4273ddfe6d9e4bbcc88acc8465003000000001976a914c95cbacc416f757c65c942f9b6b8a20038b9b12988ac00000000', 1396),
              ]

        for tx, expected_wu in txs:
            tx = CTransaction.deserialize(x(tx))
            self.assertEqual(tx.calc_weight(), expected_wu)
