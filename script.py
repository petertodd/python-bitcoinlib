
#
# script.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import struct
import copy
from serialize import Hash
from key import CKey

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

# push value
OP_0 = 0x00
OP_FALSE = OP_0
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e
OP_1NEGATE = 0x4f
OP_RESERVED = 0x50
OP_1 = 0x51
OP_TRUE=OP_1
OP_2 = 0x52
OP_3 = 0x53
OP_4 = 0x54
OP_5 = 0x55
OP_6 = 0x56
OP_7 = 0x57
OP_8 = 0x58
OP_9 = 0x59
OP_10 = 0x5a
OP_11 = 0x5b
OP_12 = 0x5c
OP_13 = 0x5d
OP_14 = 0x5e
OP_15 = 0x5f
OP_16 = 0x60

# control
OP_NOP = 0x61
OP_VER = 0x62
OP_IF = 0x63
OP_NOTIF = 0x64
OP_VERIF = 0x65
OP_VERNOTIF = 0x66
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_VERIFY = 0x69
OP_RETURN = 0x6a

# stack ops
OP_TOALTSTACK = 0x6b
OP_FROMALTSTACK = 0x6c
OP_2DROP = 0x6d
OP_2DUP = 0x6e
OP_3DUP = 0x6f
OP_2OVER = 0x70
OP_2ROT = 0x71
OP_2SWAP = 0x72
OP_IFDUP = 0x73
OP_DEPTH = 0x74
OP_DROP = 0x75
OP_DUP = 0x76
OP_NIP = 0x77
OP_OVER = 0x78
OP_PICK = 0x79
OP_ROLL = 0x7a
OP_ROT = 0x7b
OP_SWAP = 0x7c
OP_TUCK = 0x7d

# splice ops
OP_CAT = 0x7e
OP_SUBSTR = 0x7f
OP_LEFT = 0x80
OP_RIGHT = 0x81
OP_SIZE = 0x82

# bit logic
OP_INVERT = 0x83
OP_AND = 0x84
OP_OR = 0x85
OP_XOR = 0x86
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_RESERVED1 = 0x89
OP_RESERVED2 = 0x8a

# numeric
OP_1ADD = 0x8b
OP_1SUB = 0x8c
OP_2MUL = 0x8d
OP_2DIV = 0x8e
OP_NEGATE = 0x8f
OP_ABS = 0x90
OP_NOT = 0x91
OP_0NOTEQUAL = 0x92

OP_ADD = 0x93
OP_SUB = 0x94
OP_MUL = 0x95
OP_DIV = 0x96
OP_MOD = 0x97
OP_LSHIFT = 0x98
OP_RSHIFT = 0x99

OP_BOOLAND = 0x9a
OP_BOOLOR = 0x9b
OP_NUMEQUAL = 0x9c
OP_NUMEQUALVERIFY = 0x9d
OP_NUMNOTEQUAL = 0x9e
OP_LESSTHAN = 0x9f
OP_GREATERTHAN = 0xa0
OP_LESSTHANOREQUAL = 0xa1
OP_GREATERTHANOREQUAL = 0xa2
OP_MIN = 0xa3
OP_MAX = 0xa4

OP_WITHIN = 0xa5

# crypto
OP_RIPEMD160 = 0xa6
OP_SHA1 = 0xa7
OP_SHA256 = 0xa8
OP_HASH160 = 0xa9
OP_HASH256 = 0xaa
OP_CODESEPARATOR = 0xab
OP_CHECKSIG = 0xac
OP_CHECKSIGVERIFY = 0xad
OP_CHECKMULTISIG = 0xae
OP_CHECKMULTISIGVERIFY = 0xaf

# expansion
OP_NOP1 = 0xb0
OP_NOP2 = 0xb1
OP_NOP3 = 0xb2
OP_NOP4 = 0xb3
OP_NOP5 = 0xb4
OP_NOP6 = 0xb5
OP_NOP7 = 0xb6
OP_NOP8 = 0xb7
OP_NOP9 = 0xb8
OP_NOP10 = 0xb9

# template matching params
OP_SMALLINTEGER = 0xfa
OP_PUBKEYS = 0xfb
OP_PUBKEYHASH = 0xfd
OP_PUBKEY = 0xfe

OP_INVALIDOPCODE = 0xff

VALID_OPCODES = {
	OP_1NEGATE : True,
	OP_RESERVED : True,
	OP_1 : True,
	OP_2 : True,
	OP_3 : True,
	OP_4 : True,
	OP_5 : True,
	OP_6 : True,
	OP_7 : True,
	OP_8 : True,
	OP_9 : True,
	OP_10 : True,
	OP_11 : True,
	OP_12 : True,
	OP_13 : True,
	OP_14 : True,
	OP_15 : True,
	OP_16 : True,

	OP_NOP : True,
	OP_VER : True,
	OP_IF : True,
	OP_NOTIF : True,
	OP_VERIF : True,
	OP_VERNOTIF : True,
	OP_ELSE : True,
	OP_ENDIF : True,
	OP_VERIFY : True,
	OP_RETURN : True,

	OP_TOALTSTACK : True,
	OP_FROMALTSTACK : True,
	OP_2DROP : True,
	OP_2DUP : True,
	OP_3DUP : True,
	OP_2OVER : True,
	OP_2ROT : True,
	OP_2SWAP : True,
	OP_IFDUP : True,
	OP_DEPTH : True,
	OP_DROP : True,
	OP_DUP : True,
	OP_NIP : True,
	OP_OVER : True,
	OP_PICK : True,
	OP_ROLL : True,
	OP_ROT : True,
	OP_SWAP : True,
	OP_TUCK : True,

	OP_CAT : True,
	OP_SUBSTR : True,
	OP_LEFT : True,
	OP_RIGHT : True,
	OP_SIZE : True,

	OP_INVERT : True,
	OP_AND : True,
	OP_OR : True,
	OP_XOR : True,
	OP_EQUAL : True,
	OP_EQUALVERIFY : True,
	OP_RESERVED1 : True,
	OP_RESERVED2 : True,

	OP_1ADD : True,
	OP_1SUB : True,
	OP_2MUL : True,
	OP_2DIV : True,
	OP_NEGATE : True,
	OP_ABS : True,
	OP_NOT : True,
	OP_0NOTEQUAL : True,

	OP_ADD : True,
	OP_SUB : True,
	OP_MUL : True,
	OP_DIV : True,
	OP_MOD : True,
	OP_LSHIFT : True,
	OP_RSHIFT : True,

	OP_BOOLAND : True,
	OP_BOOLOR : True,
	OP_NUMEQUAL : True,
	OP_NUMEQUALVERIFY : True,
	OP_NUMNOTEQUAL : True,
	OP_LESSTHAN : True,
	OP_GREATERTHAN : True,
	OP_LESSTHANOREQUAL : True,
	OP_GREATERTHANOREQUAL : True,
	OP_MIN : True,
	OP_MAX : True,

	OP_WITHIN : True,

	OP_RIPEMD160 : True,
	OP_SHA1 : True,
	OP_SHA256 : True,
	OP_HASH160 : True,
	OP_HASH256 : True,
	OP_CODESEPARATOR : True,
	OP_CHECKSIG : True,
	OP_CHECKSIGVERIFY : True,
	OP_CHECKMULTISIG : True,
	OP_CHECKMULTISIGVERIFY : True,

	OP_NOP1 : True,
	OP_NOP2 : True,
	OP_NOP3 : True,
	OP_NOP4 : True,
	OP_NOP5 : True,
	OP_NOP6 : True,
	OP_NOP7 : True,
	OP_NOP8 : True,
	OP_NOP9 : True,
	OP_NOP10 : True,

	OP_SMALLINTEGER : True,
	OP_PUBKEYS : True,
	OP_PUBKEYHASH : True,
	OP_PUBKEY : True,
}


class CScriptOp(object):
	def __init__(self):
		self.op = OP_INVALIDOPCODE
		self.data = ''

class CScript(object):
	def __init__(self, vch=None):
		self.ops = []
		self.vch = vch
		if vch is not None:
			self.valid = False
		else:
			self.valid = True

	def tokenize(self, vch_in=None):
		if vch_in is not None:
			self.vch = vch_in
		self.valid = False
		vch = self.vch
		while len(vch) > 0:
			opcode = ord(vch[0])

			sop = CScriptOp()
			sop.op = opcode

			vch = vch[1:]

			if opcode > OP_PUSHDATA4:
				if opcode not in VALID_OPCODES:
					return False
				self.ops.append(sop)
				continue

			if opcode < OP_PUSHDATA1:
				datasize = opcode

			elif opcode == OP_PUSHDATA1:
				if len(vch) < 1:
					return False
				datasize = ord(vch[0])
				vch = vch[1:]

			elif opcode == OP_PUSHDATA2:
				if len(vch) < 2:
					return False
				datasize = struct.unpack("<H", vch[:2])[0]
				vch = vch[2:]

			elif opcode == OP_PUSHDATA4:
				if len(vch) < 4:
					return False
				datasize = struct.unpack("<I", vch[:4])[0]
				vch = vch[4:]

			if len(vch) < datasize:
				return False

			sop.data = vch[:datasize]
			vch = vch[datasize:]

			self.ops.append(sop)

		self.valid = True
		return True

def SignatureHash(script, txTo, inIdx, hashtype):
	if inIdx < len(txTo.vin):
		return (0L, "inIdx %d out of range" % (inIdx,))
	txtmp = copy.deepcopy(txTo)
	for txin in txtmp.vin:
		txin.scriptSig = ''
	txtmp.vin[inIdx].scriptSig = script

	if (hashtype & 0x1f) == SIGHASH_NONE:
		txtmp.vout = []

		for i in xrange(len(txtmp.vin)):
			if i != inIdx:
				txtmp.vin[i].nSequence = 0

	elif (hashtype & 0x1f) == SIGHASH_SINGLE:
		outIdx = inIdx
		if outIdx >= len(txtmp.vout):
			return (0L, "outIdx %d out of range" % (outIdx,))

		tmp = txtmp.vout[outIdx]
		txtmp.vout = []
		for i in xrange(outIdx):
			txtmp.vout.append(CTxOut())
		txtmp.vout.append(tmp)

		for i in xrange(len(txtmp.vin)):
			if i != inIdx:
				txtmp.vin[i].nSequence = 0

	if hashtype & SIGHASH_ANYONECANPAY:
		tmp = txtmp.vin[inIdx]
		txtmp.vin = []
		txtmp.vin.append(tmp)

	s = txtmp.serialize()
	s += struct.pack("<I", self.nTime)

	return Hash(s)

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

	hash = SignatureHash(script, txTo, inIdx, hashtype)
	return key.verify(hash, sig)



