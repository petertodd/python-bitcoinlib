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
from datatypes import *
from serialize import *
from messages import *

BLOCK0 = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26fL

settings = {}
debugnet = False

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
	def __init__(self, dstaddr, dstport, mempool, chaindb):
		asyncore.dispatcher.__init__(self)
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
		self.state = "connecting"

		#stuff version msg into sendbuf
		vt = msg_version()
		vt.addrTo.ip = self.dstaddr
		vt.addrTo.port = self.dstport
		vt.addrFrom.ip = "0.0.0.0"
		vt.addrFrom.port = 0
		vt.nStartingHeight = self.chaindb.getheight()
		self.send_message(vt, True)

		print "connecting"
		try:
			self.connect((dstaddr, dstport))
		except:
			self.handle_close()
	def handle_connect(self):
		print "connected"
		self.state = "connected"
		#send version msg
#		t = msg_version()
#		t.addrTo.ip = self.dstaddr
#		t.addrTo.port = self.dstport
#		t.addrFrom.ip = "0.0.0.0"
#		t.addrFrom.port = 0
#		self.send_message(t)
	def handle_close(self):
		print "close"
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
			if self.recvbuf[:4] != "\xf9\xbe\xb4\xd9":
				raise ValueError("got garbage %s" % repr(self.recvbuf))
			if self.ver_recv < 209:
				if len(self.recvbuf) < 4 + 12 + 4:
					return
				command = self.recvbuf[4:4+12].split("\x00", 1)[0]
				msglen = struct.unpack("<i", self.recvbuf[4+12:4+12+4])[0]
				checksum = None
				if len(self.recvbuf) < 4 + 12 + 4 + msglen:
					return
				msg = self.recvbuf[4+12+4:4+12+4+msglen]
				self.recvbuf = self.recvbuf[4+12+4+msglen:]
			else:
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
				print "UNKNOWN COMMAND", command, repr(msg)
	def send_message(self, message, pushbuf=False):
		if self.state != "connected" and not pushbuf:
			return

		if verbose_sendmsg(message):
			print "send %s" % repr(message)

		command = message.command
		data = message.serialize()
		tmsg = "\xf9\xbe\xb4\xd9"
		tmsg += command
		tmsg += "\x00" * (12 - len(command))
		tmsg += struct.pack("<I", len(data))
		if self.ver_send >= 209:
			th = SHA256.new(data).digest()
			h = SHA256.new(th).digest()
			tmsg += h[:4]
		tmsg += data
		self.sendbuf += tmsg
		self.last_sent = time.time()
	def got_message(self, message):
		if self.last_sent + 30 * 60 < time.time():
			self.send_message(msg_ping())

		if verbose_recvmsg(message):
			print "recv %s" % repr(message)

		if message.command  == "version":
			if message.nVersion >= 209:
				self.send_message(msg_verack())
				self.send_message(msg_getaddr())
			self.ver_send = min(MY_VERSION, message.nVersion)
			if message.nVersion < 209:
				self.ver_recv = self.ver_send

		elif message.command == "verack":
			self.ver_recv = self.ver_send

		elif message.command == "addr":
			print "Received %d new addresses" % (len(message.addrs),)

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

	settings['port'] = int(settings['port'])

	mempool = MemPool.MemPool()
	chaindb = ChainDb.ChainDb(settings['db'], mempool)

	c = NodeConn(settings['host'], settings['port'], mempool, chaindb)
	asyncore.loop()

