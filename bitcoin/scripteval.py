
#
# scripteval.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from __future__ import absolute_import, division, print_function, unicode_literals

import sys
if sys.version > '3':
    long = int

import hashlib
from bitcoin.serialize import Hash, Hash160, ser_uint256, ser_uint160
from bitcoin.script import *
from bitcoin.core import CTxOut, CTransaction
from bitcoin.key import CKey
from bitcoin.bignum import bn2vch, vch2bn

def SignatureHash(script, txTo, inIdx, hashtype):
    if inIdx >= len(txTo.vin):
        return (1, "inIdx %d out of range (%d)" % (inIdx, len(txTo.vin)))
    txtmp = CTransaction()
    txtmp.copy(txTo)

    for txin in txtmp.vin:
        txin.scriptSig = b''
    txtmp.vin[inIdx].scriptSig = script.vch

    if (hashtype & 0x1f) == SIGHASH_NONE:
        txtmp.vout = []

        for i in range(len(txtmp.vin)):
            if i != inIdx:
                txtmp.vin[i].nSequence = 0

    elif (hashtype & 0x1f) == SIGHASH_SINGLE:
        outIdx = inIdx
        if outIdx >= len(txtmp.vout):
            return (1, "outIdx %d out of range (%d)" % (outIdx, len(txtmp.vout)))

        tmp = txtmp.vout[outIdx]
        txtmp.vout = []
        for i in range(outIdx):
            txtmp.vout.append(CTxOut())
        txtmp.vout.append(tmp)

        for i in range(len(txtmp.vin)):
            if i != inIdx:
                txtmp.vin[i].nSequence = 0

    if hashtype & SIGHASH_ANYONECANPAY:
        tmp = txtmp.vin[inIdx]
        txtmp.vin = []
        txtmp.vin.append(tmp)

    s = txtmp.serialize()
    s += struct.pack(b"<I", hashtype)

    hash = Hash(s)

    return (hash,)

def CheckSig(sig, pubkey, script, txTo, inIdx, hashtype):
    key = CKey()
    key.set_pubkey(pubkey)

    if len(sig) == 0:
        return False
    if hashtype == 0:
        hashtype = ord(sig[-1])
    elif hashtype != ord(sig[-1]):
        return False
    sig = sig[:-1]

    tup = SignatureHash(script, txTo, inIdx, hashtype)
    return key.verify(ser_uint256(tup[0]), sig)

def CheckMultiSig(opcode, script, stack, txTo, inIdx, hashtype):
    i = 1
    if len(stack) < i:
        return False

    keys_count = CastToBigNum(stack[-i])
    if keys_count < 0 or keys_count > 20:
        return False
    i += 1
    ikey = i
    i += keys_count
    if len(stack) < i:
        return False

    sigs_count = CastToBigNum(stack[-i])
    if sigs_count < 0 or sigs_count > keys_count:
        return False
    i += 1
    isig = i
    i += sigs_count
    if len(stack) < i:
        return False

    for k in range(sigs_count):
        sig = stack[-isig-k]
        # FIXME: find-and-delete sig in script

    success = True

    while success and sigs_count > 0:
        sig = stack[-isig]
        pubkey = stack[-ikey]

        if CheckSig(sig, pubkey, script, txTo, inIdx, hashtype):
            isig += 1
            sigs_count -= 1

        ikey += 1
        keys_count -= 1

        if sigs_count > keys_count:
            success = False

    while i > 0:
        stack.pop()
        i -= 1

    if success:
        stack.append(b"\x01")
    else:
        stack.append(b"\x00")

    if opcode == OP_CHECKMULTISIGVERIFY:
        if success:
            stack.pop()
        else:
            return False

    return True

def dumpstack(msg, stack):
    print("%s stacksz %d" % (msg, len(stack)))
    for i in range(len(stack)):
        vch = stack[i]
        print("#%d: %s" % (i, vch.encode('hex')))

ISA_UNOP = {
    OP_1ADD,
    OP_1SUB,
    OP_2MUL,
    OP_2DIV,
    OP_NEGATE,
    OP_ABS,
    OP_NOT,
    OP_0NOTEQUAL,
}

def UnaryOp(opcode, stack):
    if len(stack) < 1:
        return False
    bn = CastToBigNum(stack.pop())

    if opcode == OP_1ADD:
        bn += 1

    elif opcode == OP_1SUB:
        bn -= 1

    elif opcode == OP_2MUL:
        bn <<= 1

    elif opcode == OP_2DIV:
        bn >>= 1

    elif opcode == OP_NEGATE:
        bn = -bn

    elif opcode == OP_ABS:
        if bn < 0:
            bn = -bn

    elif opcode == OP_NOT:
        bn = long(bn == 0)

    elif opcode == OP_0NOTEQUAL:
        bn = long(bn != 0)

    else:
        return False

    stack.append(bn2vch(bn))

    return True

ISA_BINOP = {
    OP_ADD,
    OP_SUB,
    OP_LSHIFT,
    OP_RSHIFT,
    OP_BOOLAND,
    OP_BOOLOR,
    OP_NUMEQUAL,
    OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL,
    OP_LESSTHAN,
    OP_GREATERTHAN,
    OP_LESSTHANOREQUAL,
    OP_GREATERTHANOREQUAL,
    OP_MIN,
    OP_MAX,
}

def BinOp(opcode, stack):
    if len(stack) < 2:
        return False

    bn2 = CastToBigNum(stack.pop())
    bn1 = CastToBigNum(stack.pop())

    if opcode == OP_ADD:
        bn = bn1 + bn2

    elif opcode == OP_SUB:
        bn = bn1 - bn2

    elif opcode == OP_LSHIFT:
        if bn2 < 0 or bn2 > 2048:
            return False
        bn = bn1 << bn2

    elif opcode == OP_RSHIFT:
        if bn2 < 0 or bn2 > 2048:
            return False
        bn = bn1 >> bn2

    elif opcode == OP_BOOLAND:
        bn = long(bn1 != 0 and bn2 != 0)

    elif opcode == OP_BOOLOR:
        bn = long(bn1 != 0 or bn2 != 0)

    elif opcode == OP_NUMEQUAL or opcode == OP_NUMEQUALVERIFY:
        bn = long(bn1 == bn2)

    elif opcode == OP_NUMNOTEQUAL:
        bn = long(bn1 != bn2)

    elif opcode == OP_LESSTHAN:
        bn = long(bn1 < bn2)

    elif opcode == OP_GREATERTHAN:
        bn = long(bn1 > bn2)

    elif opcode == OP_LESSTHANOREQUAL:
        bn = long(bn1 <= bn2)

    elif opcode == OP_GREATERTHANOREQUAL:
        bn = long(bn1 >= bn2)

    elif opcode == OP_MIN:
        if bn1 < bn2:
            bn = bn1
        else:
            bn = bn2

    elif opcode == OP_MAX:
        if bn1 > bn2:
            bn = bn1
        else:
            bn = bn2

    else:
        return False            # unknown binop opcode

    stack.append(bn2vch(bn))

    if opcode == OP_NUMEQUALVERIFY:
        if CastToBool(stack[-1]):
            stack.pop()
        else:
            return False

    return True

def CheckExec(vfExec):
    for b in vfExec:
        if not b:
            return False
    return True

def EvalScript(stack, scriptIn, txTo, inIdx, hashtype):
    altstack = []
    vfExec = []
    script = CScript(scriptIn)
    while script.pc < script.pend:
        if not script.getop():
            return False
        sop = script.sop

        fExec = CheckExec(vfExec)

        if fExec and sop.op <= OP_PUSHDATA4:
            stack.append(sop.data)
            continue

        elif fExec and sop.op == OP_1NEGATE or ((sop.op >= OP_1) and (sop.op <= OP_16)):
            v = sop.op - (OP_1 - 1)
            stack.append(bn2vch(v))

        elif fExec and sop.op in ISA_BINOP:
            if not BinOp(sop.op, stack):
                return False

        elif fExec and sop.op in ISA_UNOP:
            if not UnaryOp(sop.op, stack):
                return False

        elif fExec and sop.op == OP_2DROP:
            if len(stack) < 2:
                return False
            stack.pop()
            stack.pop()

        elif fExec and sop.op == OP_2DUP:
            if len(stack) < 2:
                return False
            v1 = stack[-2]
            v2 = stack[-1]
            stack.append(v1)
            stack.append(v2)

        elif fExec and sop.op == OP_2OVER:
            if len(stack) < 4:
                return False
            v1 = stack[-4]
            v2 = stack[-3]
            stack.append(v1)
            stack.append(v2)

        elif fExec and sop.op == OP_2SWAP:
            if len(stack) < 4:
                return False
            tmp = stack[-4]
            stack[-4] = stack[-2]
            stack[-2] = tmp

            tmp = stack[-3]
            stack[-3] = stack[-1]
            stack[-1] = tmp

        elif fExec and sop.op == OP_3DUP:
            if len(stack) < 3:
                return False
            v1 = stack[-3]
            v2 = stack[-2]
            v3 = stack[-1]
            stack.append(v1)
            stack.append(v2)
            stack.append(v3)

        elif fExec and sop.op == OP_CHECKMULTISIG or sop.op == OP_CHECKMULTISIGVERIFY:
            tmpScript = CScript(script.vch[script.pbegincodehash:script.pend])
            ok = CheckMultiSig(sop.op, tmpScript, stack, txTo,
                       inIdx, hashtype)
            if not ok:
                return False

        elif fExec and sop.op == OP_CHECKSIG or sop.op == OP_CHECKSIGVERIFY:
            if len(stack) < 2:
                return False
            vchPubKey = stack.pop()
            vchSig = stack.pop()
            tmpScript = CScript(script.vch[script.pbegincodehash:script.pend])

            # FIXME: find-and-delete vchSig

            ok = CheckSig(vchSig, vchPubKey, tmpScript,
                      txTo, inIdx, hashtype)
            if ok:
                if sop.op != OP_CHECKSIGVERIFY:
                    stack.append(b"\x01")
            else:
                if sop.op == OP_CHECKSIGVERIFY:
                    return False
                stack.append(b"\x00")

        elif fExec and sop.op == OP_CODESEPARATOR:
            script.pbegincodehash = script.pc

        elif fExec and sop.op == OP_DEPTH:
            bn = len(stack)
            stack.append(bn2vch(bn))

        elif fExec and sop.op == OP_DROP:
            if len(stack) < 1:
                return False
            stack.pop()

        elif fExec and sop.op == OP_DUP:
            if len(stack) < 1:
                return False
            v = stack[-1]
            stack.append(v)

        elif sop.op == OP_ELSE:
            if len(vfExec) == 0:
                return false
            vfExec[-1] = not vfExec[-1]

        elif sop.op == OP_ENDIF:
            if len(vfExec) == 0:
                return false
            vfExec.pop()

        elif fExec and sop.op == OP_EQUAL or sop.op == OP_EQUALVERIFY:
            if len(stack) < 2:
                return False
            v1 = stack.pop()
            v2 = stack.pop()

            is_equal = (v1 == v2)
            if is_equal:
                stack.append(b"\x01")
            else:
                stack.append(b"\x00")

            if sop.op == OP_EQUALVERIFY:
                if is_equal:
                    stack.pop()
                else:
                    return False

        elif fExec and sop.op == OP_FROMALTSTACK:
            if len(altstack) < 1:
                return False
            v = altstack.pop()
            stack.append(v)

        elif fExec and sop.op == OP_HASH160:
            if len(stack) < 1:
                return False
            stack.append(ser_uint160(Hash160(stack.pop())))

        elif fExec and sop.op == OP_HASH256:
            if len(stack) < 1:
                return False
            stack.append(ser_uint256(Hash(stack.pop())))

        elif sop.op == OP_IF or sop.op == OP_NOTIF:
            val = False

            if fExec:
                if len(stack) < 1:
                    return False
                vch = stack.pop()
                val = CastToBool(vch)
                if sop.op == OP_NOTIF:
                    val = not val

            vfExec.append(val)

        elif fExec and sop.op == OP_IFDUP:
            if len(stack) < 1:
                return False
            vch = stack[-1]
            if CastToBool(vch):
                stack.append(vch)

        elif fExec and sop.op == OP_NIP:
            if len(stack) < 2:
                return False
            del stack[-2]

        elif fExec and sop.op == OP_NOP or (sop.op >= OP_NOP1 and sop.op <= OP_NOP10):
            pass

        elif fExec and sop.op == OP_OVER:
            if len(stack) < 2:
                return False
            vch = stack[-2]
            stack.append(vch)

        elif fExec and sop.op == OP_PICK or sop.op == OP_ROLL:
            if len(stack) < 2:
                return False
            n = CastToBigNum(stack.pop())
            if n < 0 or n >= len(stack):
                return False
            vch = stack[-n-1]
            if sop.op == OP_ROLL:
                del stack[-n-1]
            stack.append(vch)

        elif fExec and sop.op == OP_RETURN:
            return False

        elif fExec and sop.op == OP_RIPEMD160:
            if len(stack) < 1:
                return False

            h = hashlib.new('ripemd160')
            h.update(stack.pop())
            stack.append(h.digest())

        elif fExec and sop.op == OP_ROT:
            if len(stack) < 3:
                return False
            tmp = stack[-3]
            stack[-3] = stack[-2]
            stack[-2] = tmp

            tmp = stack[-2]
            stack[-2] = stack[-1]
            stack[-1] = tmp

        elif fExec and sop.op == OP_SIZE:
            if len(stack) < 1:
                return False
            bn = len(stack[-1])
            stack.append(bn2vch(bn))

        elif fExec and sop.op == OP_SHA256:
            if len(stack) < 1:
                return False
            stack.append(hashlib.sha256(stack.pop()).digest())

        elif fExec and sop.op == OP_SWAP:
            if len(stack) < 2:
                return False
            tmp = stack[-2]
            stack[-2] = stack[-1]
            stack[-1] = tmp

        elif fExec and sop.op == OP_TOALTSTACK:
            if len(stack) < 1:
                return False
            v = stack.pop()
            altstack.append(v)

        elif fExec and sop.op == OP_TUCK:
            if len(stack) < 2:
                return False
            vch = stack[-1]
            stack.insert(len(stack) - 2, vch)

        elif fExec and sop.op == OP_VERIFY:
            if len(stack) < 1:
                return False
            v = CastToBool(stack[-1])
            if v:
                stack.pop()
            else:
                return False

        elif fExec and sop.op == OP_WITHIN:
            if len(stack) < 3:
                return False
            bn3 = CastToBigNum(stack.pop())
            bn2 = CastToBigNum(stack.pop())
            bn1 = CastToBigNum(stack.pop())
            v = (bn2 <= bn1) and (bn1 < bn3)
            if v:
                stack.append(b"\x01")
            else:
                stack.append(b"\x00")

        elif fExec:
            #print("Unsupported opcode", OPCODE_NAMES[sop.op])
            return False

    return True

def CastToBigNum(s):
    v = vch2bn(s)
    return v

def CastToBool(s):
    for i in range(len(s)):
        sv = ord(s[i])
        if sv != 0:
            if (i == (len(s) - 1)) and (sv == 0x80):
                return False
            return True

    return False

def VerifyScript(scriptSig, scriptPubKey, txTo, inIdx, hashtype):
    stack = []
    if not EvalScript(stack, scriptSig, txTo, inIdx, hashtype):
        return False
    if not EvalScript(stack, scriptPubKey, txTo, inIdx, hashtype):
        return False
    if len(stack) == 0:
        return False
    return CastToBool(stack[-1])

def VerifySignature(txFrom, txTo, inIdx, hashtype):
    if inIdx >= len(txTo.vin):
        return False
    txin = txTo.vin[inIdx]

    if txin.prevout.n >= len(txFrom.vout):
        return False
    txout = txFrom.vout[txin.prevout.n]

    txFrom.calc_sha256()

    if txin.prevout.hash != txFrom.sha256:
        return False

    if not VerifyScript(txin.scriptSig, txout.scriptPubKey, txTo, inIdx,
                hashtype):
        return False

    return True




