
#
# scripteval.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from __future__ import absolute_import, division, print_function, unicode_literals

import sys
bord = ord
if sys.version > '3':
    long = int
    bord = lambda x: x

import hashlib
from bitcoin.serialize import Hash, Hash160
from bitcoin.script import *
from bitcoin.core import CTxOut, CTransaction
from bitcoin.key import CKey
from bitcoin.bignum import bn2vch, vch2bn

nMaxNumSize = 4
MAX_SCRIPT_SIZE = 10000
MAX_SCRIPT_ELEMENT_SIZE = 520
MAX_SCRIPT_OPCODES = 201
MAX_STACK_ITEMS = 1000

SCRIPT_VERIFY_P2SH = object()
SCRIPT_VERIFY_STRICTENC = object()
SCRIPT_VERIFY_EVEN_S = object()
SCRIPT_VERIFY_NOCACHE = object()

# Invalid even when occuring in an unexecuted OP_IF branch due to either being
# disabled, or never implemented.
disabled_opcodes = set((OP_VERIF, OP_VERNOTIF,
                        OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_INVERT, OP_AND,
                        OP_OR, OP_XOR, OP_2MUL, OP_2DIV, OP_MUL, OP_DIV, OP_MOD,
                        OP_LSHIFT, OP_RSHIFT))

class EvalScriptError(Exception):
    def __init__(self, msg):
        super(EvalScriptError, self).__init__('EvalScript: %s' % msg)

def MissingOpArgumentsError(opcode, stack, n):
    return EvalScriptError('missing arguments for %s; need %d items, but only %d on stack' %
                                   (OPCODE_NAMES[opcode], n, len(stack)))

def CastToBigNum(s):
    v = vch2bn(s)
    if len(s) > nMaxNumSize:
        raise EvalScriptError('CastToBigNum(): overflow')
    return v

def CastToBool(s):
    for i in range(len(s)):
        sv = bord(s[i])
        if sv != 0:
            if (i == (len(s) - 1)) and (sv == 0x80):
                return False
            return True

    return False


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
        hashtype = bord(sig[-1])
    elif hashtype != bord(sig[-1]):
        return False
    sig = sig[:-1]

    tup = SignatureHash(script, txTo, inIdx, hashtype)
    return key.verify(tup[0], sig)

def CheckMultiSig(opcode, script, stack, txTo, inIdx, hashtype):
    i = 1
    if len(stack) < i:
        raise MissingOpArgumentsError(opcode, stack, i)

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
        raise MissingOpArgumentsError(opcode, stack, i)

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
        raise MissingOpArgumentsError(opcode, stack, 1)
    bn = CastToBigNum(stack.pop())

    if opcode == OP_1ADD:
        bn += 1

    elif opcode == OP_1SUB:
        bn -= 1

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
        raise MissingOpArgumentsError(opcode, stack, 2)

    bn2 = CastToBigNum(stack.pop())
    bn1 = CastToBigNum(stack.pop())

    if opcode == OP_ADD:
        bn = bn1 + bn2

    elif opcode == OP_SUB:
        bn = bn1 - bn2

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
        assert False # unknown binop opcode, shouldn't happen
        return False # Python strips out assertions with -O flag...

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


def _EvalScript(stack, scriptIn, txTo, inIdx, hashtype, flags=()):
    if len(scriptIn) > MAX_SCRIPT_SIZE:
        raise EvalScriptError('script too large; got %d bytes; maximum %d bytes' %
                (len(scriptIn), MAX_SCRIPT_SIZE))

    altstack = []
    vfExec = []
    pbegincodehash = 0
    nOpCount = 0
    for (sop, sop_data, sop_pc) in scriptIn.raw_iter():
        fExec = CheckExec(vfExec)

        if sop in disabled_opcodes:
            raise EvalScriptError('opcode %s is disabled' % OPCODE_NAMES[sop])

        if sop > OP_16:
            nOpCount += 1
            if nOpCount > MAX_SCRIPT_OPCODES:
                raise EvalScriptError('max opcode count exceeded')

        def check_args(n):
            if len(stack) < n:
                raise MissingOpArgumentsError(sop, stack, n)


        if sop <= OP_PUSHDATA4:
            if len(sop_data) > MAX_SCRIPT_ELEMENT_SIZE:
                raise EvalScriptError('PUSHDATA of length %d; maximum allowed is %d' %
                        (len(sop_data), MAX_SCRIPT_ELEMENT_SIZE))

            elif fExec:
                stack.append(sop_data)
                continue

        elif fExec and (sop == OP_1NEGATE or ((sop >= OP_1) and (sop <= OP_16))):
            v = sop - (OP_1 - 1)
            stack.append(bn2vch(v))

        elif fExec and sop in ISA_BINOP:
            if not BinOp(sop, stack):
                return False

        elif fExec and sop in ISA_UNOP:
            if not UnaryOp(sop, stack):
                return False

        elif fExec and sop == OP_2DROP:
            check_args(2)
            stack.pop()
            stack.pop()

        elif fExec and sop == OP_2DUP:
            check_args(2)
            v1 = stack[-2]
            v2 = stack[-1]
            stack.append(v1)
            stack.append(v2)

        elif fExec and sop == OP_2OVER:
            check_args(4)
            v1 = stack[-4]
            v2 = stack[-3]
            stack.append(v1)
            stack.append(v2)

        elif fExec and sop == OP_2ROT:
            check_args(6)
            v1 = stack[-6]
            v2 = stack[-5]
            del stack[-6]
            del stack[-5]
            stack.append(v1)
            stack.append(v2)

        elif fExec and sop == OP_2SWAP:
            check_args(4)
            tmp = stack[-4]
            stack[-4] = stack[-2]
            stack[-2] = tmp

            tmp = stack[-3]
            stack[-3] = stack[-1]
            stack[-1] = tmp

        elif fExec and sop == OP_3DUP:
            check_args(3)
            v1 = stack[-3]
            v2 = stack[-2]
            v3 = stack[-1]
            stack.append(v1)
            stack.append(v2)
            stack.append(v3)

        elif fExec and sop == OP_CHECKMULTISIG or sop == OP_CHECKMULTISIGVERIFY:
            tmpScript = CScript(scriptIn[pbegincodehash:])
            ok = CheckMultiSig(sop, tmpScript, stack, txTo,
                       inIdx, hashtype)
            if not ok:
                return False

        elif fExec and sop == OP_CHECKSIG or sop == OP_CHECKSIGVERIFY:
            check_args(2)
            vchPubKey = stack.pop()
            vchSig = stack.pop()
            tmpScript = CScript(scriptIn[pbegincodehash:])

            # FIXME: find-and-delete vchSig

            ok = CheckSig(vchSig, vchPubKey, tmpScript,
                      txTo, inIdx, hashtype)
            if ok:
                if sop != OP_CHECKSIGVERIFY:
                    stack.append(b"\x01")
            else:
                if sop == OP_CHECKSIGVERIFY:
                    return False
                stack.append(b"\x00")

        elif fExec and sop == OP_CODESEPARATOR:
            pbegincodehash = sop_pc

        elif fExec and sop == OP_DEPTH:
            bn = len(stack)
            stack.append(bn2vch(bn))

        elif fExec and sop == OP_DROP:
            check_args(1)
            stack.pop()

        elif fExec and sop == OP_DUP:
            check_args(1)
            v = stack[-1]
            stack.append(v)

        elif sop == OP_ELSE:
            if len(vfExec) == 0:
                raise EvalScriptError('ELSE found without preceeding IF')
            vfExec[-1] = not vfExec[-1]

        elif sop == OP_ENDIF:
            if len(vfExec) == 0:
                return False
            vfExec.pop()

        elif fExec and sop == OP_EQUAL or sop == OP_EQUALVERIFY:
            check_args(2)
            v1 = stack.pop()
            v2 = stack.pop()

            is_equal = (v1 == v2)
            if is_equal:
                stack.append(b"\x01")
            else:
                stack.append(b"\x00")

            if sop == OP_EQUALVERIFY:
                if is_equal:
                    stack.pop()
                else:
                    return False

        elif fExec and sop == OP_FROMALTSTACK:
            if len(altstack) < 1:
                raise MissingOpArgumentsError(sop, altstack, 1)
            v = altstack.pop()
            stack.append(v)

        elif fExec and sop == OP_HASH160:
            check_args(1)
            stack.append(Hash160(stack.pop()))

        elif fExec and sop == OP_HASH256:
            check_args(1)
            stack.append(Hash(stack.pop()))

        elif sop == OP_IF or sop == OP_NOTIF:
            val = False

            if fExec:
                check_args(1)
                vch = stack.pop()
                val = CastToBool(vch)
                if sop == OP_NOTIF:
                    val = not val

            vfExec.append(val)


        elif fExec and sop == OP_IFDUP:
            check_args(1)
            vch = stack[-1]
            if CastToBool(vch):
                stack.append(vch)

        elif fExec and sop == OP_NIP:
            check_args(2)
            del stack[-2]

        elif fExec and sop == OP_NOP or (sop >= OP_NOP1 and sop <= OP_NOP10):
            pass

        elif fExec and sop == OP_OVER:
            check_args(2)
            vch = stack[-2]
            stack.append(vch)

        elif fExec and sop == OP_PICK or sop == OP_ROLL:
            check_args(2)
            n = CastToBigNum(stack.pop())
            if n < 0 or n >= len(stack):
                return False
            vch = stack[-n-1]
            if sop == OP_ROLL:
                del stack[-n-1]
            stack.append(vch)

        elif fExec and sop == OP_RETURN:
            return False

        elif fExec and sop == OP_RIPEMD160:
            check_args(1)

            h = hashlib.new('ripemd160')
            h.update(stack.pop())
            stack.append(h.digest())

        elif fExec and sop == OP_ROT:
            check_args(3)
            tmp = stack[-3]
            stack[-3] = stack[-2]
            stack[-2] = tmp

            tmp = stack[-2]
            stack[-2] = stack[-1]
            stack[-1] = tmp

        elif fExec and sop == OP_SIZE:
            check_args(1)
            bn = len(stack[-1])
            stack.append(bn2vch(bn))

        elif fExec and sop == OP_SHA1:
            check_args(1)
            stack.append(hashlib.sha1(stack.pop()).digest())

        elif fExec and sop == OP_SHA256:
            check_args(1)
            stack.append(hashlib.sha256(stack.pop()).digest())

        elif fExec and sop == OP_SWAP:
            check_args(2)
            tmp = stack[-2]
            stack[-2] = stack[-1]
            stack[-1] = tmp

        elif fExec and sop == OP_TOALTSTACK:
            check_args(1)
            v = stack.pop()
            altstack.append(v)

        elif fExec and sop == OP_TUCK:
            check_args(2)
            vch = stack[-1]
            stack.insert(len(stack) - 2, vch)

        elif fExec and sop == OP_VERIFY:
            if len(stack) < 1:
                return False
            v = CastToBool(stack[-1])
            if v:
                stack.pop()
            else:
                return False

        elif fExec and sop == OP_WITHIN:
            check_args(3)
            bn3 = CastToBigNum(stack.pop())
            bn2 = CastToBigNum(stack.pop())
            bn1 = CastToBigNum(stack.pop())
            v = (bn2 <= bn1) and (bn1 < bn3)
            if v:
                stack.append(b"\x01")
            else:
                stack.append(b"\x00")

        elif fExec:
            raise EvalScriptError('unsupported opcode 0x%x' % sop)

        # size limits
        if len(stack) + len(altstack) > MAX_STACK_ITEMS:
            raise EvalScriptError('max stack items limit reached')

    # Unterminated IF/NOTIF/ELSE block
    if len(vfExec):
        raise EvalScriptError('Unterminated IF/ELSE block')

    return True

def EvalScript(stack, scriptIn, txTo, inIdx, hashtype, flags=()):
    try:
        return _EvalScript(stack, scriptIn, txTo, inIdx, hashtype, flags=flags)
    except CScriptInvalidException:
        return False
    except EvalScriptError:
        return False


def VerifyScript(scriptSig, scriptPubKey, txTo, inIdx, hashtype, flags=()):
    stack = []
    if not EvalScript(stack, scriptSig, txTo, inIdx, hashtype, flags=flags):
        return False
    if SCRIPT_VERIFY_P2SH in flags:
        stackCopy = list(stack)
    if not EvalScript(stack, scriptPubKey, txTo, inIdx, hashtype, flags=flags):
        return False
    if len(stack) == 0:
        return False
    if not CastToBool(stack[-1]):
        return False

    # Additional validation for spend-to-script-hash transactions
    if SCRIPT_VERIFY_P2SH in flags and scriptPubKey.is_p2sh():
        if not scriptSig.is_push_only():
            return False

        # stackCopy cannot be empty here, because if it was the
        # P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        # an empty stack and the EvalScript above would return false.
        assert len(stackCopy)

        pubKey2 = CScript(stackCopy.pop())

        if not EvalScript(stackCopy, pubKey2, txTo, inIdx, hashtype, flags=flags):
            return False

        if not len(stackCopy):
            return False

        return CastToBool(stack[-1])

    return True

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




