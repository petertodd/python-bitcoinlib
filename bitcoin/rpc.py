# Copyright (C) 2007 Jan-Klaas Kollhof
# Copyright (C) 2011-2015 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

"""Bitcoin Core RPC support

By default this uses the standard library ``json`` module. By monkey patching,
a different implementation can be used instead, at your own risk:

>>> import simplejson
>>> import bitcoin.rpc
>>> bitcoin.rpc.json = simplejson

(``simplejson`` is the externally maintained version of the same module and
thus better optimized but perhaps less stable.)
"""

from __future__ import absolute_import, division, print_function, unicode_literals
import ssl

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
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret

DEFAULT_USER_AGENT = "AuthServiceProxy/0.1"

DEFAULT_HTTP_TIMEOUT = 30

# (un)hexlify to/from unicode, needed for Python3
unhexlify = binascii.unhexlify
hexlify = binascii.hexlify
if sys.version > '3':
    unhexlify = lambda h: binascii.unhexlify(h.encode('utf8'))
    hexlify = lambda b: binascii.hexlify(b).decode('utf8')


class JSONRPCError(Exception):
    """JSON-RPC protocol error"""

    def __init__(self, rpc_error):
        super(JSONRPCException, self).__init__(
            'msg: %r  code: %r' %
            (rpc_error['message'], rpc_error['code']))
        self.error = rpc_error


# 0.4.0 compatibility
JSONRPCException = JSONRPCError


class BaseProxy(object):
    """Base JSON-RPC proxy class. Contains only private methods; do not use
    directly."""

    def __init__(self,
                 service_url=None,
                 service_port=None,
                 btc_conf_file=None,
                 timeout=DEFAULT_HTTP_TIMEOUT):

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
                # Bitcoin Core accepts empty rpcuser, not specified in btc_conf_file
                conf = {'rpcuser': ""}
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
                conf['rpchost'] = conf.get('rpcconnect', 'localhost')

                if conf['rpcssl'].lower() in ('0', 'false'):
                    conf['rpcssl'] = False
                elif conf['rpcssl'].lower() in ('1', 'true'):
                    conf['rpcssl'] = True
                else:
                    raise ValueError('Unknown rpcssl value %r' % conf['rpcssl'])

                if conf['rpcssl'] and 'rpcsslcertificatechainfile' in conf and 'rpcsslprivatekeyfile' in conf:
                    self.__ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                    if os.path.exists(conf['rpcsslcertificatechainfile']):
                        certificate = conf['rpcsslcertificatechainfile']
                    elif os.path.exists(os.path.join(os.path.dirname(btc_conf_file), conf['rpcsslcertificatechainfile'])):
                        certificate = os.path.join(os.path.dirname(btc_conf_file), conf['rpcsslcertificatechainfile'])
                    else:
                        raise ValueError('The value of rpcsslcertificatechainfile is not correctly specified in the configuration file: %s' % btc_conf_file)
                    if os.path.exists(conf['rpcsslprivatekeyfile']):
                        private_key = conf['rpcsslprivatekeyfile']
                    elif os.path.exists(os.path.join(os.path.dirname(btc_conf_file), conf['rpcsslprivatekeyfile'])):
                        private_key = os.path.join(os.path.dirname(btc_conf_file), conf['rpcsslprivatekeyfile'])
                    else:
                        raise ValueError('The value of rpcsslprivatekeyfile is not correctly specified in the configuration file: %s' % btc_conf_file)
                    self.__ssl_context.load_cert_chain(certificate, private_key)

                if 'rpcpassword' not in conf:
                    raise ValueError('The value of rpcpassword not specified in the configuration file: %s' % btc_conf_file)

                service_url = ('%s://%s:%s@%s:%d' %
                    ('https' if conf['rpcssl'] else 'http',
                     conf['rpcuser'], conf['rpcpassword'],
                     conf['rpchost'], conf['rpcport']))

        self.__service_url = service_url
        self.__url = urlparse.urlparse(service_url)

        if self.__url.scheme not in ('https', 'http'):
            raise ValueError('Unsupported URL scheme %r' % self.__url.scheme)

        if self.__url.port is None:
            if self.__url.scheme == 'https':
                port = httplib.HTTPS_PORT
            else:
                port = httplib.HTTP_PORT
        else:
            port = self.__url.port
        self.__id_count = 0
        authpair = "%s:%s" % (self.__url.username, self.__url.password)
        authpair = authpair.encode('utf8')
        self.__auth_header = b"Basic " + base64.b64encode(authpair)

        if self.__url.scheme == 'https':
            self.__conn = httplib.HTTPSConnection(self.__url.hostname, port=port,
                                                  context=self.__ssl_context,
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
                             'User-Agent': DEFAULT_USER_AGENT,
                             'Authorization': self.__auth_header,
                             'Content-type': 'application/json'})

        response = self._get_response()
        if response['error'] is not None:
            raise JSONRPCError(response['error'])
        elif 'result' not in response:
            raise JSONRPCError({
                'code': -343, 'message': 'missing JSON-RPC result'})
        else:
            return response['result']


    def _batch(self, rpc_call_list):
        postdata = json.dumps(list(rpc_call_list))
        self.__conn.request('POST', self.__url.path, postdata,
                            {'Host': self.__url.hostname,
                             'User-Agent': DEFAULT_USER_AGENT,
                             'Authorization': self.__auth_header,
                             'Content-type': 'application/json'})

        return self._get_response()

    def _get_response(self):
        http_response = self.__conn.getresponse()
        if http_response is None:
            raise JSONRPCError({
                'code': -342, 'message': 'missing HTTP response from server'})

        return json.loads(http_response.read().decode('utf8'),
                          parse_float=decimal.Decimal)

    def __del__(self):
        self.__conn.close()


class RawProxy(BaseProxy):
    """Low-level proxy to a bitcoin JSON-RPC service

    Unlike ``Proxy``, no conversion is done besides parsing JSON. As far as
    Python is concerned, you can call any method; ``JSONRPCError`` will be
    raised if the server does not recognize it.
    """
    def __init__(self,
                 service_url=None,
                 service_port=None,
                 btc_conf_file=None,
                 timeout=DEFAULT_HTTP_TIMEOUT,
                 **kwargs):
        super(RawProxy, self).__init__(service_url=service_url,
                                       service_port=service_port,
                                       btc_conf_file=btc_conf_file,
                                       timeout=timeout,
                                       **kwargs)

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


class Proxy(BaseProxy):
    """Proxy to a bitcoin RPC service

    Unlike ``RawProxy``, data is passed as ``bitcoin.core`` objects or packed
    bytes, rather than JSON or hex strings. Not all methods are implemented
    yet; you can use ``call`` to access missing ones in a forward-compatible
    way. Assumes Bitcoin Core version >= 0.9; older versions mostly work, but
    there are a few incompatibilities.
    """

    def __init__(self,
                 service_url=None,
                 service_port=None,
                 btc_conf_file=None,
                 timeout=DEFAULT_HTTP_TIMEOUT,
                 **kwargs):
        """Create a proxy object

        If ``service_url`` is not specified, the username and password are read
        out of the file ``btc_conf_file``. If ``btc_conf_file`` is not
        specified, ``~/.bitcoin/bitcoin.conf`` or equivalent is used by
        default.  The default port is set according to the chain parameters in
        use: mainnet, testnet, or regtest.

        Usually no arguments to ``Proxy()`` are needed; the local bitcoind will
        be used.

        ``timeout`` - timeout in seconds before the HTTP interface times out
        """

        super(Proxy, self).__init__(service_url=service_url,
                                    service_port=service_port,
                                    btc_conf_file=btc_conf_file,
                                    timeout=timeout,
                                    **kwargs)

    def call(self, service_name, *args):
        """Call an RPC method by name and raw (JSON encodable) arguments"""
        return self._call(service_name, *args)

    def dumpprivkey(self, addr):
        """Return the private key matching an address
        """
        r = self._call('dumpprivkey', str(addr))

        return CBitcoinSecret(r)

    def getaccountaddress(self, account=None):
        """Return the current Bitcoin address for receiving payments to this
        account."""
        r = self._call('getaccountaddress', account)
        return CBitcoinAddress(r)

    def getbalance(self, account='*', minconf=1):
        """Get the balance

        account - The selected account. Defaults to "*" for entire wallet. It
        may be the default account using "".

        minconf - Only include transactions confirmed at least this many times.
        (default=1)
        """
        r = self._call('getbalance', account, minconf)
        return int(r*COIN)

    def getbestblockhash(self):
        """Return hash of best (tip) block in longest block chain."""
        return lx(self._call('getbestblockhash'))

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
        except JSONRPCError as ex:
            raise IndexError('%s.getblock(): %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))
        return CBlock.deserialize(unhexlify(r))

    def getblockcount(self):
        """Return the number of blocks in the longest block chain"""
        return self._call('getblockcount')

    def getblockhash(self, height):
        """Return hash of block in best-block-chain at height.

        Raises IndexError if height is not valid.
        """
        try:
            return lx(self._call('getblockhash', height))
        except JSONRPCError as ex:
            raise IndexError('%s.getblockhash(): %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))

    def getinfo(self):
        """Return a JSON object containing various state info"""
        r = self._call('getinfo')
        if 'balance' in r:
            r['balance'] = int(r['balance'] * COIN)
        if 'paytxfee' in r:
            r['paytxfee'] = int(r['paytxfee'] * COIN)
        return r

    def getmininginfo(self):
        """Return a JSON object containing mining-related information"""
        return self._call('getmininginfo')

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

    def getrawchangeaddress(self):
        """Returns a new Bitcoin address, for receiving change.

        This is for use with raw transactions, NOT normal use.
        """
        r = self._call('getrawchangeaddress')
        return CBitcoinAddress(r)

    def getrawmempool(self, verbose=False):
        """Return the mempool"""
        if verbose:
            return self._call('getrawmempool', verbose)

        else:
            r = self._call('getrawmempool')
            r = [lx(txid) for txid in r]
            return r

    def getrawtransaction(self, txid, verbose=False):
        """Return transaction with hash txid

        Raises IndexError if transaction not found.

        verbose - If true a dict is returned instead with additional
        information on the transaction.

        Note that if all txouts are spent and the transaction index is not
        enabled the transaction may not be available.
        """
        try:
            r = self._call('getrawtransaction', b2lx(txid), 1 if verbose else 0)
        except JSONRPCError as ex:
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

    def getreceivedbyaddress(self, addr, minconf=1):
        """Return total amount received by given a (wallet) address

        Get the amount received by <address> in transactions with at least
        [minconf] confirmations.

        Works only for addresses in the local wallet; other addresses will
        always show zero.

        addr    - The address. (CBitcoinAddress instance)

        minconf - Only include transactions confirmed at least this many times.
        (default=1)
        """
        r = self._call('getreceivedbyaddress', str(addr), minconf)
        return int(r * COIN)

    def gettransaction(self, txid):
        """Get detailed information about in-wallet transaction txid

        Raises IndexError if transaction not found in the wallet.

        FIXME: Returned data types are not yet converted.
        """
        try:
            r = self._call('gettransaction', b2lx(txid))
        except JSONRPCError as ex:
            raise IndexError('%s.getrawtransaction(): %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))
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

    def importaddress(self, addr, label='', rescan=True):
        """Adds an address or pubkey to wallet without the associated privkey."""
        addr = str(addr)

        r = self._call('importaddress', addr, label, rescan)
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
        json_outpoints = [{'txid':b2lx(outpoint.hash), 'vout':outpoint.n}
                          for outpoint in outpoints]
        return self._call('lockunspent', unlock, json_outpoints)

    def sendrawtransaction(self, tx, allowhighfees=False):
        """Submit transaction to local node and network.

        allowhighfees - Allow even if fees are unreasonably high.
        """
        hextx = hexlify(tx.serialize())
        r = None
        if allowhighfees:
            r = self._call('sendrawtransaction', hextx, True)
        else:
            r = self._call('sendrawtransaction', hextx)
        return lx(r)

    def sendmany(self, fromaccount, payments, minconf=1, comment=''):
        """Sent amount to a given address"""
        json_payments = {str(addr):float(amount)/COIN
                         for addr, amount in payments.items()}
        r = self._call('sendmany', fromaccount, json_payments, minconf, comment)
        return lx(r)

    def sendtoaddress(self, addr, amount):
        """Sent amount to a given address"""
        addr = str(addr)
        amount = float(amount)/COIN
        r = self._call('sendtoaddress', addr, amount)
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
        if r['isvalid']:
            r['address'] = CBitcoinAddress(r['address'])
        if 'pubkey' in r:
            r['pubkey'] = unhexlify(r['pubkey'])
        return r

    def _addnode(self, node, arg):
        r = self._call('addnode', node, arg)
        return r

    def addnode(self, node):
        return self._addnode(node, 'add')

    def addnodeonetry(self, node):
        return self._addnode(node, 'onetry')

    def removenode(self, node):
        return self._addnode(node, 'remove')

__all__ = (
    'JSONRPCError',
    'JSONRPCException',
    'RawProxy',
    'Proxy',
)
