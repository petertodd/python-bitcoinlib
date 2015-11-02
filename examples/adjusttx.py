"""
for bitcoin malleability attack
"""
import struct
from bitcoin.core import CTransaction, x, bord, b2x, CScript, b2lx, Hash
from bitcoin.core.script import IsLowDERSignature

curveN = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
def signature_to_low_s(sig):
    # A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
    len_total = bord(sig[1])
    len_r = bord(sig[3])
    len_s = bord(sig[len_r + 5])
    s_val = sig[6 + len_r:6 + len_r + len_s]
    s_val = curveN - long(s_val.encode('hex'), 16)
    
    s_val = hex(s_val).lstrip("0x").rstrip("L").zfill(64).decode('hex')
    len_new_s = len(s_val)
    len_total = len_r + len_new_s + 4
    return sig[0] + struct.pack("B", len_total) + sig[2:len_r+5] +  struct.pack("B", len_new_s) + s_val + sig[-1:]

def adjust_transaction(tx_hex):
    # if you don't want change you wallet signature code
    # you can use this to adjust high S signature to a canonical signature
    tx = CTransaction.deserialize(x(tx_hex))
    for vin in tx.vin:
        script_lst = list(vin.scriptSig)
        sig = script_lst[0]
        # normal signature format <sig> <pubkey>
        if len(script_lst) == 2 and not IsLowDERSignature(sig):
            low_s_sig = signature_to_low_s(sig)#.encode('hex')
            #print sig.encode('hex'), low_s_sig.encode('hex')
            script_lst[0] = low_s_sig
            vin.scriptSig = CScript(script_lst)
        # 2/2 or 2/3 multisig format <0> <signature> <signature> <redeemscript>
        elif len(script_lst) == 4:
            script_lst_new = []
            for idx, sig in enumerate(script_lst[1:3]):
                if not IsLowDERSignature(sig):
                    low_s_sig = signature_to_low_s(sig)#.encode('hex')
                    #print sig.encode('hex'), low_s_sig.encode('hex')
                    script_lst_new.append(low_s_sig)
                else:
                    script_lst_new.append(sig)
            script_lst_new.append(script_lst[3])
            vin.scriptSig = "\x00" + CScript(script_lst_new)
    return b2x(tx.serialize())
    
if __name__ == "__main__":
    print adjust_transaction("010000000845250df911c3971c9f177a43b764d6da0ce478a55eec7d6e316a735ef06c32db00000000fa00473044022075fce99be66fde74d495849823283f8dde9b2cc2b6ac3a81b532870884a616d402200c3e25d236236a548caa6b46da43d0bca8122065106514fd432d321e369ad82501473044022007796b9090076c025cf36ee480b6b7a2c1125f139d21faca737c280f216159ae022025c235d55ab18ae1bac36593a6b703701529bbc9f330980b87b1542431fa03a0014c67524104330c0e76bec22bf47c5799bc55352948a70cd4d7b61df2b9265c053df82af0ce0b51267c6c2ae253970104bfe6e6e8215c666ea0c030cdbee30e4f51e27e83ae2102006d84d5c0536b6d66ced41b48785e25d02bca9ac571f441e0b9c14d138aa1e252aeffffffff75b91e5438eb830b99e48ae0923d3901775a60560778c15e3908b8c7c616d107fa0e0000fdfd0000483045022100ff5567617c7b9706389b9d7336182a675b42b054eaf0ee3defb30818e43786fb02203fe106210c0070e8f14b432ffbe1157788a4c399e8e7cb0de9488da58f8869b101493046022100a06be9ef58d96ec0c4cd0c77fa77aa4739966e55b0ddffcf5e8ac756eb7180ad022100f0f608017e70a6b5f9be81c825b7635e759bd7bcc05976d54490554d4a613b1a014c67524104330c0e76bec22bf47c5799bc55352948a70cd4d7b61df2b9265c053df82af0ce0b51267c6c2ae253970104bfe6e6e8215c666ea0c030cdbee30e4f51e27e83ae2102006d84d5c0536b6d66ced41b48785e25d02bca9ac571f441e0b9c14d138aa1e252aeffffffffd2137e78171fa24196b28be9d54b33fa5f701ce3da3e169c6f9e6102799b5a93d20e0000fb004730440220457d1589a00c2c1a39e62cb60e3e66eb6edfd70c4f6b70bb903fd1532a76809902207c855a18ad5b05f3d76b513911fe26e750700a1d68d5c6217d30138237e4e5b201483045022100adfbbbde5c572c55c75c3b8b23ab25655d23739abe5b1bb6b78dd5487ae3b8f202200817b06f84b4bbd6feb76447cb75b1d784e0055a33843004071b8f0789703e0d014c67524104330c0e76bec22bf47c5799bc55352948a70cd4d7b61df2b9265c053df82af0ce0b51267c6c2ae253970104bfe6e6e8215c666ea0c030cdbee30e4f51e27e83ae2102006d84d5c0536b6d66ced41b48785e25d02bca9ac571f441e0b9c14d138aa1e252aeffffffff6c3f0b54990bb02b597b2e186b45c0a4b8297411aa3a44ac187bdbaf114abf22b40e0000fdfd0000493046022100fbde39d881469297dbb7e8b0c0b08e6c0b8bcb833d511838cb510aad905c22a102210096ae62d5bab2e8c84d9d0702d2076eecaac9a7b9e4d7114ec40725b38326ce9601483045022100f32e90164a6ce65794820cb213acae610fc94a1933b273ee2c1e8452fb096d08022005078740070cc5a1bfb9eb150e37a1342c1c5e949a8a03915bab42195a445f9c014c67524104330c0e76bec22bf47c5799bc55352948a70cd4d7b61df2b9265c053df82af0ce0b51267c6c2ae253970104bfe6e6e8215c666ea0c030cdbee30e4f51e27e83ae2102006d84d5c0536b6d66ced41b48785e25d02bca9ac571f441e0b9c14d138aa1e252aeffffffffc5a47e8aa32236e3d97a71147d357cf850c242d1e01f71f7e5fa6544ab59bf3a4a0e0000fdfd000048304502201341383b14f76f0e1d5871d9eea94885003098cecb8fe96f14639c81748615cc022100d423a4a9415ad0a00b9567a3ee648b42154d373b06686679ddaf131c73ff921601493046022100d7ec37889dd0bb57d72a0a5a3ad877152ff681736f32a397bf6b51b5177f7132022100d638443fc9f493da3746213488d96d4d93356df910a7e11a4ca33f104859436f014c67524104330c0e76bec22bf47c5799bc55352948a70cd4d7b61df2b9265c053df82af0ce0b51267c6c2ae253970104bfe6e6e8215c666ea0c030cdbee30e4f51e27e83ae2102006d84d5c0536b6d66ced41b48785e25d02bca9ac571f441e0b9c14d138aa1e252aeffffffffdee1bbac83019e74138ea8e6509fed35631530d8e34548b0a5f1491554992f99ae0e0000fc00473044022077d2d486904454ddcf222074f6f0ba54899976264ab56c8a88af165e0ee5ef1b02200d4d42e37f0dc74bea05717fa82558b512a1955428b811cbceeabf8b2066179301493046022100a497a4df27a70bdebe25459f75dcc202b090072b4b0562f6d468a90663654726022100b0805d3d1b70a2265dc103289f69554c5efec5e0748ee2cd3de7f15c8659856d014c67524104330c0e76bec22bf47c5799bc55352948a70cd4d7b61df2b9265c053df82af0ce0b51267c6c2ae253970104bfe6e6e8215c666ea0c030cdbee30e4f51e27e83ae2102006d84d5c0536b6d66ced41b48785e25d02bca9ac571f441e0b9c14d138aa1e252aeffffffff922593c16057a8421862124bd8545bc5ad81aea5a9ef390d8840bbe3a1612007870e0000fc00483045022100be10158c39c4f2e62158e5c3db43be1b195912404a42d8eb07e5f86146aa8dc40220647dc7de44ca6ae021d65c087f34fce082291dce71fbe4f8ef2b332151d5d1140148304502202dd07825cb77de644cfdadaf1a9f0b651c19036e239614ca953d9962d84d721b022100aabf11910e4ff827833895b29e7d0b8e1ec0b41898feb613672757da419467f6014c67524104330c0e76bec22bf47c5799bc55352948a70cd4d7b61df2b9265c053df82af0ce0b51267c6c2ae253970104bfe6e6e8215c666ea0c030cdbee30e4f51e27e83ae2102006d84d5c0536b6d66ced41b48785e25d02bca9ac571f441e0b9c14d138aa1e252aeffffffff5958d3caf04ce5223870dea8f12f641e3d59ec46db5b91940d38ca04665b95acb00e0000fb00473044022005fec129c83e3ebad5e80219fd2e46511add9c3ff1384ef8ba09670d171d73e7022040d41ed006b363a1771e64575158e28001536a23cd166547f3dc3f93606ace050148304502200c894f8210b23c84b76bc199f64a7442508b1a1ad296ba0723163f779cf43d66022100881585d8ed3ab8a91ce580b59cdd6c0b2e4cbf12d4ed76bc9c529d8eb44493d9014c67524104330c0e76bec22bf47c5799bc55352948a70cd4d7b61df2b9265c053df82af0ce0b51267c6c2ae253970104bfe6e6e8215c666ea0c030cdbee30e4f51e27e83ae2102006d84d5c0536b6d66ced41b48785e25d02bca9ac571f441e0b9c14d138aa1e252aeffffffff0155233b000000000017a914cd888fd2bd4013e79ca810f0103146beb54dca528700000000")
