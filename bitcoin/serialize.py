
#
# serialize.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import struct
import hashlib

def deser_string(f):
	nit = struct.unpack("<B", f.read(1))[0]
	if nit == 253:
		nit = struct.unpack("<H", f.read(2))[0]
	elif nit == 254:
		nit = struct.unpack("<I", f.read(4))[0]
	elif nit == 255:
		nit = struct.unpack("<Q", f.read(8))[0]
	return f.read(nit)

def ser_string(s):
	if len(s) < 253:
		return chr(len(s)) + s
	elif len(s) < 0x10000:
		return chr(253) + struct.pack("<H", len(s)) + s
	elif len(s) < 0x100000000L:
		return chr(254) + struct.pack("<I", len(s)) + s
	return chr(255) + struct.pack("<Q", len(s)) + s

def deser_uint256(f):
	r = 0L
	for i in xrange(8):
		t = struct.unpack("<I", f.read(4))[0]
		r += t << (i * 32)
	return r

def ser_uint256(u):
	rs = ""
	for i in xrange(8):
		rs += struct.pack("<I", u & 0xFFFFFFFFL)
		u >>= 32
	return rs

def ser_uint160(u):
	rs = ""
	for i in xrange(5):
		rs += struct.pack("<I", u & 0xFFFFFFFFL)
		u >>= 32
	return rs

def uint160_from_str(s):
	r = 0L
	t = struct.unpack("<IIIII", s[:20])
	for i in xrange(5):
		r += t[i] << (i * 32)
	return r

def uint256_from_str(s):
	r = 0L
	t = struct.unpack("<IIIIIIII", s[:32])
	for i in xrange(8):
		r += t[i] << (i * 32)
	return r

def uint256_from_compact(c):
	nbytes = (c >> 24) & 0xFF
	v = (c & 0xFFFFFFL) << (8 * (nbytes - 3))
	return v

def uint256_to_shortstr(u):
	s = "%064x" % (u,)
	return s[:16]

def deser_vector(f, c, arg1=None):
	nit = struct.unpack("<B", f.read(1))[0]
	if nit == 253:
		nit = struct.unpack("<H", f.read(2))[0]
	elif nit == 254:
		nit = struct.unpack("<I", f.read(4))[0]
	elif nit == 255:
		nit = struct.unpack("<Q", f.read(8))[0]
	r = []
	for i in xrange(nit):
		if arg1 is not None:
			t = c(arg1)
		else:
			t = c()
		t.deserialize(f)
		r.append(t)
	return r

def ser_vector(l):
	r = ""
	if len(l) < 253:
		r = chr(len(l))
	elif len(l) < 0x10000:
		r = chr(253) + struct.pack("<H", len(l))
	elif len(l) < 0x100000000L:
		r = chr(254) + struct.pack("<I", len(l))
	else:
		r = chr(255) + struct.pack("<Q", len(l))
	for i in l:
		r += i.serialize()
	return r

def deser_uint256_vector(f):
	nit = struct.unpack("<B", f.read(1))[0]
	if nit == 253:
		nit = struct.unpack("<H", f.read(2))[0]
	elif nit == 254:
		nit = struct.unpack("<I", f.read(4))[0]
	elif nit == 255:
		nit = struct.unpack("<Q", f.read(8))[0]
	r = []
	for i in xrange(nit):
		t = deser_uint256(f)
		r.append(t)
	return r

def ser_uint256_vector(l):
	r = ""
	if len(l) < 253:
		r = chr(len(l))
	elif len(s) < 0x10000:
		r = chr(253) + struct.pack("<H", len(l))
	elif len(s) < 0x100000000L:
		r = chr(254) + struct.pack("<I", len(l))
	else:
		r = chr(255) + struct.pack("<Q", len(l))
	for i in l:
		r += ser_uint256(i)
	return r

def deser_string_vector(f):
	nit = struct.unpack("<B", f.read(1))[0]
	if nit == 253:
		nit = struct.unpack("<H", f.read(2))[0]
	elif nit == 254:
		nit = struct.unpack("<I", f.read(4))[0]
	elif nit == 255:
		nit = struct.unpack("<Q", f.read(8))[0]
	r = []
	for i in xrange(nit):
		t = deser_string(f)
		r.append(t)
	return r

def ser_string_vector(l):
	r = ""
	if len(l) < 253:
		r = chr(len(l))
	elif len(s) < 0x10000:
		r = chr(253) + struct.pack("<H", len(l))
	elif len(s) < 0x100000000L:
		r = chr(254) + struct.pack("<I", len(l))
	else:
		r = chr(255) + struct.pack("<Q", len(l))
	for sv in l:
		r += ser_string(sv)
	return r

def deser_int_vector(f):
	nit = struct.unpack("<B", f.read(1))[0]
	if nit == 253:
		nit = struct.unpack("<H", f.read(2))[0]
	elif nit == 254:
		nit = struct.unpack("<I", f.read(4))[0]
	elif nit == 255:
		nit = struct.unpack("<Q", f.read(8))[0]
	r = []
	for i in xrange(nit):
		t = struct.unpack("<i", f.read(4))[0]
		r.append(t)
	return r

def ser_int_vector(l):
	r = ""
	if len(l) < 253:
		r = chr(len(l))
	elif len(s) < 0x10000:
		r = chr(253) + struct.pack("<H", len(l))
	elif len(s) < 0x100000000L:
		r = chr(254) + struct.pack("<I", len(l))
	else:
		r = chr(255) + struct.pack("<Q", len(l))
	for i in l:
		r += struct.pack("<i", i)
	return r

def Hash(s):
	return uint256_from_str(hashlib.sha256(hashlib.sha256(s).digest()).digest())

def Hash160(s):
	h = hashlib.new('ripemd160')
	h.update(hashlib.sha256(s).digest())
	return uint160_from_str(h.digest())

