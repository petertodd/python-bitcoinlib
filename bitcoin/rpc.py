# Copyright 2011 Jeff Garzik
#
# RawProxy has the following improvements over python-jsonrpc's ServiceProxy
# class:
#
# - HTTP connections persist for the life of the RawProxy object (if server
#   supports HTTP/1.1)
# - sends protocol 'version', per JSON-RPC 1.1
# - sends proper, incrementing 'id'
# - sends Basic HTTP authentication headers
# - parses all JSON numbers that look like floats as Decimal
# - uses standard Python json lib
#
# Previous copyright, from python-jsonrpc/jsonrpc/proxy.py:
#
# Copyright (c) 2007 Jan-Klaas Kollhof
#
# This file is part of jsonrpc.
#
# jsonrpc is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this software; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

"""Bitcoin Core RPC support"""

from __future__ import absolute_import, division, print_function, unicode_literals

try:
    import http.client as httplib
except ImportError:
    import httplib
import base64
import binascii
import decimal
import json
import os
import platform
import sys
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

import bitcoin
from bitcoin.core import COIN, lx, b2lx, CBlock, CTransaction, COutPoint, CTxOut
from bitcoin.core.script import CScript
from bitcoin.wallet import CBitcoinAddress

USER_AGENT = "AuthServiceProxy/0.1"

HTTP_TIMEOUT = 30

# (un)hexlify to/from unicode, needed for Python3
unhexlify = binascii.unhexlify
hexlify = binascii.hexlify
if sys.version > '3':
    unhexlify = lambda h: binascii.unhexlify(h.encode('utf8'))
    hexlify = lambda b: binascii.hexlify(b).decode('utf8')


class JSONRPCException(Exception):
    def __init__(self, rpc_error):
        super(JSONRPCException, self).__init__('msg: %r  code: %r' %
                (rpc_error['message'], rpc_error['code']))
        self.error = rpc_error


class RawProxy(object):
    # FIXME: need a CChainParams rather than hard-coded service_port
    def __init__(self, service_url=None,
                       service_port=None,
                       btc_conf_file=None,
                       timeout=HTTP_TIMEOUT,
                       _connection=None):
        """Low-level JSON-RPC proxy

        Unlike Proxy no conversion is done from the raw JSON objects.
        """

        if service_url is None:
            # Figure out the path to the bitcoin.conf file
            if btc_conf_file is None:
                if platform.system() == 'Darwin':
                    btc_conf_file = os.path.expanduser('~/Library/Application Support/Bitcoin/')
                elif platform.system() == 'Windows':
                    btc_conf_file = os.path.join(os.environ['APPDATA'], 'Bitcoin')
                else:
                    btc_conf_file = os.path.expanduser('~/.bitcoin')
                btc_conf_file = os.path.join(btc_conf_file, 'bitcoin.conf')

            # Extract contents of bitcoin.conf to build service_url
            with open(btc_conf_file, 'r') as fd:
                conf = {}
                for line in fd.readlines():
                    if '#' in line:
                        line = line[:line.index('#')]
                    if '=' not in line:
                        continue
                    k, v = line.split('=', 1)
                    conf[k.strip()] = v.strip()

                if service_port is None:
                    service_port = bitcoin.params.RPC_PORT
                conf['rpcport'] = int(conf.get('rpcport', service_port))
                conf['rpcssl'] = conf.get('rpcssl', '0')

                if conf['rpcssl'].lower() in ('0', 'false'):
                    conf['rpcssl'] = False
                elif conf['rpcssl'].lower() in ('1', 'true'):
                    conf['rpcssl'] = True
                else:
                    raise ValueError('Unknown rpcssl value %r' % conf['rpcssl'])

                service_url = ('%s://%s:%s@localhost:%d' %
                    ('https' if conf['rpcssl'] else 'http',
                     conf['rpcuser'], conf['rpcpassword'],
                     conf['rpcport']))

        self.__service_url = service_url
        self.__url = urlparse.urlparse(service_url)
        if self.__url.port is None:
            port = 80
        else:
            port = self.__url.port
        self.__id_count = 0
        authpair = "%s:%s" % (self.__url.username, self.__url.password)
        authpair = authpair.encode('utf8')
        self.__auth_header = b"Basic " + base64.b64encode(authpair)

        if _connection:
            # Callables re-use the connection of the original proxy
            self.__conn = _connection
        elif self.__url.scheme == 'https':
            self.__conn = httplib.HTTPSConnection(self.__url.hostname, port=port,
                                                  key_file=None, cert_file=None,
                                                  timeout=timeout)
        else:
            self.__conn = httplib.HTTPConnection(self.__url.hostname, port=port,
                                                 timeout=timeout)


    def _call(self, service_name, *args):
        self.__id_count += 1

        postdata = json.dumps({'version': '1.1',
                               'method': service_name,
                               'params': args,
                               'id': self.__id_count})
        self.__conn.request('POST', self.__url.path, postdata,
                            {'Host': self.__url.hostname,
                             'User-Agent': USER_AGENT,
                             'Authorization': self.__auth_header,
                             'Content-type': 'application/json'})

        response = self._get_response()
        if response['error'] is not None:
            raise JSONRPCException(response['error'])
        elif 'result' not in response:
            raise JSONRPCException({
                'code': -343, 'message': 'missing JSON-RPC result'})
        else:
            return response['result']


    def __getattr__(self, name):
        if name.startswith('__') and name.endswith('__'):
            # Python internal stuff
            raise AttributeError

        # Create a callable to do the actual call
        f = lambda *args: self._call(name, *args)

        # Make debuggers show <function bitcoin.rpc.name> rather than <function
        # bitcoin.rpc.<lambda>>
        f.__name__ = name
        return f


    def _batch(self, rpc_call_list):
        postdata = json.dumps(list(rpc_call_list))
        self.__conn.request('POST', self.__url.path, postdata,
                            {'Host': self.__url.hostname,
                             'User-Agent': USER_AGENT,
                             'Authorization': self.__auth_header,
                             'Content-type': 'application/json'})

        return self._get_response()

    def _get_response(self):
        http_response = self.__conn.getresponse()
        if http_response is None:
            raise JSONRPCException({
                'code': -342, 'message': 'missing HTTP response from server'})

        return json.loads(http_response.read().decode('utf8'),
                          parse_float=decimal.Decimal)


class Proxy(RawProxy):
    def __init__(self, service_url=None,
                       service_port=None,
                       btc_conf_file=None,
                       timeout=HTTP_TIMEOUT,
                       **kwargs):
        """Create a proxy to a bitcoin RPC service

        Unlike RawProxy data is passed as objects, rather than JSON. (not yet
        fully implemented) Assumes Bitcoin Core version >= 0.9; older versions
        mostly work, but there are a few incompatibilities.

        If service_url is not specified the username and password are read out
        of the file btc_conf_file. If btc_conf_file is not specified
        ~/.bitcoin/bitcoin.conf or equivalent is used by default. The default
        port is set according to the chain parameters in use: mainnet, testnet,
        or regtest.

        Usually no arguments to Proxy() are needed; the local bitcoind will be
        used.

        timeout - timeout in seconds before the HTTP interface times out
        """
        super(Proxy, self).__init__(service_url=service_url, service_port=service_port, btc_conf_file=btc_conf_file,
                                    timeout=HTTP_TIMEOUT,
                                    **kwargs)
    def getaccountaddress(self, account=None):
        """Return the current Bitcoin address for receiving payments to this account."""
        r = self._call('getaccountaddress', account)
        return CBitcoinAddress(r)

    def getblock(self, block_hash):
        """Get block <block_hash>

        Raises IndexError if block_hash is not valid.
        """
        try:
            block_hash = b2lx(block_hash)
        except TypeError:
            raise TypeError('%s.getblock(): block_hash must be bytes; got %r instance' %
                    (self.__class__.__name__, block_hash.__class__))
        try:
            r = self._call('getblock', block_hash, False)
        except JSONRPCException as ex:
            raise IndexError('%s.getblock(): %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))
        return CBlock.deserialize(unhexlify(r))

    def getblockhash(self, height):
        """Return hash of block in best-block-chain at height.

        Raises IndexError if height is not valid.
        """
        try:
            return lx(self._call('getblockhash', height))
        except JSONRPCException as ex:
            raise IndexError('%s.getblockhash(): %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))

    def getinfo(self):
        """Return an object containing various state info"""
        r = self._call('getinfo')
        r['balance'] = int(r['balance'] * COIN)
        r['paytxfee'] = int(r['paytxfee'] * COIN)
        return r

    def getnewaddress(self, account=None):
        """Return a new Bitcoin address for receiving payments.

        If account is not None, it is added to the address book so payments
        received with the address will be credited to account.
        """
        r = None
        if account is not None:
            r = self._call('getnewaddress', account)
        else:
            r = self._call('getnewaddress')

        return CBitcoinAddress(r)

    def getrawtransaction(self, txid, verbose=False):
        """Return transaction with hash txid

        Raises IndexError if transaction not found.

        verbse - If true a dict is returned instead with additional information
                 on the transaction.

        Note that if all txouts are spent and the transaction index is not
        enabled the transaction may not be available.
        """
        try:
            r = self._call('getrawtransaction', b2lx(txid), 1 if verbose else 0)
        except JSONRPCException as ex:
            raise IndexError('%s.getrawtransaction(): %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))
        if verbose:
            r['tx'] = CTransaction.deserialize(unhexlify(r['hex']))
            del r['hex']
            del r['txid']
            del r['version']
            del r['locktime']
            del r['vin']
            del r['vout']
            r['blockhash'] = lx(r['blockhash']) if 'blockhash' in r else None
        else:
            r = CTransaction.deserialize(unhexlify(r))

        return r

    def gettxout(self, outpoint, includemempool=True):
        """Return details about an unspent transaction output.

        Raises IndexError if outpoint is not found or was spent.

        includemempool - Include mempool txouts
        """
        r = self._call('gettxout', b2lx(outpoint.hash), outpoint.n, includemempool)

        if r is None:
            raise IndexError('%s.gettxout(): unspent txout %r not found' % (self.__class__.__name__, outpoint))

        r['txout'] = CTxOut(int(r['value'] * COIN),
                            CScript(unhexlify(r['scriptPubKey']['hex'])))
        del r['value']
        del r['scriptPubKey']
        r['bestblock'] = lx(r['bestblock'])
        return r

    def listunspent(self, minconf=0, maxconf=9999999, addrs=None):
        """Return unspent transaction outputs in wallet

        Outputs will have between minconf and maxconf (inclusive)
        confirmations, optionally filtered to only include txouts paid to
        addresses in addrs.
        """
        r = None
        if addrs is None:
            r = self._call('listunspent', minconf, maxconf)
        else:
            addrs = [str(addr) for addr in addrs]
            r = self._call('listunspent', minconf, maxconf, addrs)

        r2 = []
        for unspent in r:
            unspent['outpoint'] = COutPoint(lx(unspent['txid']), unspent['vout'])
            del unspent['txid']
            del unspent['vout']

            unspent['address'] = CBitcoinAddress(unspent['address'])
            unspent['scriptPubKey'] = CScript(unhexlify(unspent['scriptPubKey']))
            unspent['amount'] = int(unspent['amount'] * COIN)
            r2.append(unspent)
        return r2

    def lockunspent(self, unlock, outpoints):
        """Lock or unlock outpoints"""
        json_outpoints = [{'txid':b2lx(outpoint.hash),'vout':outpoint.n} for outpoint in outpoints]
        return self._call('lockunspent', unlock, json_outpoints)

    def sendrawtransaction(self, tx):
        """Submit transaction to local node and network."""
        hextx = hexlify(tx.serialize())
        r = self._call('sendrawtransaction', hextx)
        return lx(r)

    def signrawtransaction(self, tx, *args):
        """Sign inputs for transaction

        FIXME: implement options
        """
        hextx = hexlify(tx.serialize())
        r = self._call('signrawtransaction', hextx, *args)
        r['tx'] = CTransaction.deserialize(unhexlify(r['hex']))
        del r['hex']
        return r

    def submitblock(self, block, params=None):
        """Submit a new block to the network.

        params is optional and is currently ignored by bitcoind. See
        https://en.bitcoin.it/wiki/BIP_0022 for full specification.
        """
        hexblock = hexlify(block.serialize())
        if params is not None:
            return self._call('submitblock', hexblock, params)
        else:
            return self._call('submitblock', hexblock)

    def validateaddress(self, address):
        """Return information about an address"""
        r = self._call('validateaddress', str(address))
        r['address'] = CBitcoinAddress(r['address'])
        r['pubkey'] = unhexlify(r['pubkey'])
        return r
