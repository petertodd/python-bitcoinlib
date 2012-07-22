#!/usr/bin/python
#
# node.py - Bitcoin P2P network half-a-node
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import struct
import socket
import asyncore
import binascii
import time
import sys
import re
import random
import cStringIO
from Crypto.Hash import SHA256

import ChainDb
import MemPool
from defs import *
from datatypes import *
from serialize import *
from messages import *

settings = {}
debugnet = False

class Log(object):
	def __init__(self, filename=None):
		if filename is not None:
			self.fh = open(filename, 'a+', 0)
		else:
			self.fh = sys.stdout

	def write(self, msg):
		line = "%s\n" % msg
		self.fh.write(line)

def verbose_sendmsg(message):
	if debugnet:
		return True
	if message.command != 'getdata':
		return True
	return False

def verbose_recvmsg(message):
	skipmsg = {
		'tx' : True,
		'block' : True,
		'inv' : True,
		'addr' : True
	}
	if debugnet:
		return True
	if message.command in skipmsg:
		return False
	return True

class NodeConn(asyncore.dispatcher):
	messagemap = {
		"version": msg_version,
		"verack": msg_verack,
		"addr": msg_addr,
		"alert": msg_alert,
		"inv": msg_inv,
		"getdata": msg_getdata,
		"getblocks": msg_getblocks,
		"tx": msg_tx,
		"block": msg_block,
		"getaddr": msg_getaddr,
		"ping": msg_ping
	}
	def __init__(self, dstaddr, dstport, log, mempool, chaindb):
		asyncore.dispatcher.__init__(self)
		self.log = log
		self.mempool = mempool
		self.chaindb = chaindb
		self.dstaddr = dstaddr
		self.dstport = dstport
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sendbuf = ""
		self.recvbuf = ""
		self.ver_send = 209
		self.ver_recv = 209
		self.last_sent = 0
		self.last_block_rx = time.time()
		self.last_getblocks = 0
		self.remote_height = -1
		self.state = "connecting"

		#stuff version msg into sendbuf
		vt = msg_version()
		vt.addrTo.ip = self.dstaddr
		vt.addrTo.port = self.dstport
		vt.addrFrom.ip = "0.0.0.0"
		vt.addrFrom.port = 0
		vt.nStartingHeight = self.chaindb.getheight()
		self.send_message(vt, True)

		self.log.write("connecting")
		try:
			self.connect((dstaddr, dstport))
		except:
			self.handle_close()
	def handle_connect(self):
		self.log.write("connected")
		self.state = "connected"
		#send version msg
#		t = msg_version()
#		t.addrTo.ip = self.dstaddr
#		t.addrTo.port = self.dstport
#		t.addrFrom.ip = "0.0.0.0"
#		t.addrFrom.port = 0
#		self.send_message(t)
	def handle_close(self):
		self.log.write("close")
		self.state = "closed"
		self.recvbuf = ""
		self.sendbuf = ""
		try:
			self.close()
		except:
			pass
	def handle_read(self):
		try:
			t = self.recv(8192)
		except:
			self.handle_close()
			return
		if len(t) == 0:
			self.handle_close()
			return
		self.recvbuf += t
		self.got_data()
	def readable(self):
		return True
	def writable(self):
		return (len(self.sendbuf) > 0)
	def handle_write(self):
		try:
			sent = self.send(self.sendbuf)
		except:
			self.handle_close()
			return
		self.sendbuf = self.sendbuf[sent:]
	def got_data(self):
		while True:
			if len(self.recvbuf) < 4:
				return
			if self.recvbuf[:4] != MSG_START:
				raise ValueError("got garbage %s" % repr(self.recvbuf))
			# check checksum
			if len(self.recvbuf) < 4 + 12 + 4 + 4:
				return
			command = self.recvbuf[4:4+12].split("\x00", 1)[0]
			msglen = struct.unpack("<i", self.recvbuf[4+12:4+12+4])[0]
			checksum = self.recvbuf[4+12+4:4+12+4+4]
			if len(self.recvbuf) < 4 + 12 + 4 + 4 + msglen:
				return
			msg = self.recvbuf[4+12+4+4:4+12+4+4+msglen]
			th = SHA256.new(msg).digest()
			h = SHA256.new(th).digest()
			if checksum != h[:4]:
				raise ValueError("got bad checksum %s" % repr(self.recvbuf))
			self.recvbuf = self.recvbuf[4+12+4+4+msglen:]

			if command in self.messagemap:
				f = cStringIO.StringIO(msg)
				t = self.messagemap[command]()
				t.deserialize(f)
				self.got_message(t)
			else:
				self.log.write("UNKNOWN COMMAND %s %s" % (command, repr(msg)))
	def send_message(self, message, pushbuf=False):
		if self.state != "connected" and not pushbuf:
			return

		if verbose_sendmsg(message):
			self.log.write("send %s" % repr(message))

		command = message.command
		data = message.serialize()
		tmsg = MSG_START
		tmsg += command
		tmsg += "\x00" * (12 - len(command))
		tmsg += struct.pack("<I", len(data))

		# add checksum
		th = SHA256.new(data).digest()
		h = SHA256.new(th).digest()
		tmsg += h[:4]

		tmsg += data
		self.sendbuf += tmsg
		self.last_sent = time.time()

	def send_getblocks(self):
		now = time.time()
		if (now - self.last_getblocks) < 5:
			return
		self.last_getblocks = now

		our_height = self.chaindb.getheight()
		if our_height < 0:
			gd = msg_getdata()
			inv = CInv()
			inv.type = 2
			inv.hash = BLOCK0
			gd.inv.append(inv)
			self.send_message(gd)
		elif our_height < self.remote_height:
			gb = msg_getblocks()
			if our_height >= 0:
				gb.locator.vHave.append(self.chaindb.gettophash())
			self.send_message(gb)

	def got_message(self, message):
		if self.last_sent + 30 * 60 < time.time():
			self.send_message(msg_ping())

		if verbose_recvmsg(message):
			self.log.write("recv %s" % repr(message))

		if message.command  == "version":
			self.ver_send = min(MY_VERSION, message.nVersion)
			self.remote_height = message.nStartingHeight
			self.send_message(msg_verack())
			self.send_message(msg_getaddr())
			self.send_getblocks()

		elif message.command == "verack":
			self.ver_recv = self.ver_send

		elif message.command == "addr":
			self.log.write("Received %d new addresses" % (len(message.addrs),))

		elif message.command == "inv":
			want = msg_getdata()
			for i in message.inv:
				if i.type == 1:
					want.inv.append(i)
				elif i.type == 2:
					want.inv.append(i)
			if len(want.inv):
				self.send_message(want)

		elif message.command == "tx":
			self.mempool.add(message.tx)

		elif message.command == "block":
			self.chaindb.putblock(message.block)
			self.last_block_rx = time.time()

		# if we haven't seen a 'block' message in a little while,
		# and we're still not caught up, send another getblocks
		last_blkmsg = time.time() - self.last_block_rx
		if last_blkmsg > 5:
			self.send_getblocks()

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print "Usage: node.py CONFIG-FILE"
		sys.exit(1)

	f = open(sys.argv[1])
	for line in f:
		m = re.search('^(\w+)\s*=\s*(\S.*)$', line)
		if m is None:
			continue
		settings[m.group(1)] = m.group(2)
	f.close()

	if 'host' not in settings:
		settings['host'] = '127.0.0.1'
	if 'port' not in settings:
		settings['port'] = 8333
	if 'db' not in settings:
		settings['db'] = '/tmp/chaindb'
	if 'log' not in settings or (settings['log'] == '-'):
		settings['log'] = None

	settings['port'] = int(settings['port'])

	log = Log(settings['log'])
	mempool = MemPool.MemPool(log)
	chaindb = ChainDb.ChainDb(settings['db'], log, mempool)

	log.write("\n\n\n\n")

	if 'loadblock' in settings:
		chaindb.loadfile(settings['loadblock'])

	c = NodeConn(settings['host'], settings['port'], log, mempool, chaindb)
	asyncore.loop()

