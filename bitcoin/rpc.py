# Copyright (C) 2007 Jan-Klaas Kollhof
# Copyright (C) 2011-2018 The python-bitcoinlib developers
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
import warnings
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse
if sys.version > '3':
    from io import BytesIO as _BytesIO
else:
    from cStringIO import StringIO as _BytesIO

import bitcoin
from bitcoin.core import COIN, x, lx, b2lx, CBlock, CBlockHeader, CTransaction, COutPoint, CTxOut, CTxIn
from bitcoin.core.script import CScript
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret, CBitcoinAddressError
from bitcoin.core.key import CPubKey

DEFAULT_USER_AGENT = "AuthServiceProxy/0.1"

DEFAULT_HTTP_TIMEOUT = 30

# (un)hexlify to/from unicode, needed for Python3
unhexlify = binascii.unhexlify
hexlify = binascii.hexlify
if sys.version > '3':
    unhexlify = lambda h: binascii.unhexlify(h.encode('utf8'))
    hexlify = lambda b: binascii.hexlify(b).decode('utf8')


class JSONRPCError(Exception):
    """JSON-RPC protocol error base class

    Subclasses of this class also exist for specific types of errors; the set
    of all subclasses is by no means complete.
    """

    SUBCLS_BY_CODE = {}

    @classmethod
    def _register_subcls(cls, subcls):
        cls.SUBCLS_BY_CODE[subcls.RPC_ERROR_CODE] = subcls
        return subcls

    def __new__(cls, rpc_error):
        assert cls is JSONRPCError
        cls = JSONRPCError.SUBCLS_BY_CODE.get(rpc_error['code'], cls)

        self = Exception.__new__(cls)

        super(JSONRPCError, self).__init__(
            'msg: %r  code: %r' %
            (rpc_error['message'], rpc_error['code']))
        self.error = rpc_error

        return self

@JSONRPCError._register_subcls
class ForbiddenBySafeModeError(JSONRPCError):
    RPC_ERROR_CODE = -2

@JSONRPCError._register_subcls
class InvalidAddressOrKeyError(JSONRPCError):
    RPC_ERROR_CODE = -5

@JSONRPCError._register_subcls
class InvalidParameterError(JSONRPCError):
    RPC_ERROR_CODE = -8

@JSONRPCError._register_subcls
class VerifyError(JSONRPCError):
    RPC_ERROR_CODE = -25

@JSONRPCError._register_subcls
class VerifyRejectedError(JSONRPCError):
    RPC_ERROR_CODE = -26

@JSONRPCError._register_subcls
class VerifyAlreadyInChainError(JSONRPCError):
    RPC_ERROR_CODE = -27

@JSONRPCError._register_subcls
class InWarmupError(JSONRPCError):
    RPC_ERROR_CODE = -28




class BaseProxy(object):
    """Base JSON-RPC proxy class. Contains only private methods; do not use
    directly."""

    def __init__(self,
                 service_url=None,
                 service_port=None,
                 btc_conf_file=None,
                 timeout=DEFAULT_HTTP_TIMEOUT,
                 connection=None):

        # Create a dummy connection early on so if __init__() fails prior to
        # __conn being created __del__() can detect the condition and handle it
        # correctly.
        self.__conn = None
        authpair = None

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

            # Bitcoin Core accepts empty rpcuser, not specified in btc_conf_file
            conf = {'rpcuser': ""}

            # Extract contents of bitcoin.conf to build service_url
            try:
                with open(btc_conf_file, 'r') as fd:
                    for line in fd.readlines():
                        if '#' in line:
                            line = line[:line.index('#')]
                        if '=' not in line:
                            continue
                        k, v = line.split('=', 1)
                        conf[k.strip()] = v.strip()

            # Treat a missing bitcoin.conf as though it were empty
            except FileNotFoundError:
                pass

            if service_port is None:
                service_port = bitcoin.params.RPC_PORT
            conf['rpcport'] = int(conf.get('rpcport', service_port))
            conf['rpchost'] = conf.get('rpcconnect', 'localhost')

            service_url = ('%s://%s:%d' %
                ('http', conf['rpchost'], conf['rpcport']))

            cookie_dir = conf.get('datadir', os.path.dirname(btc_conf_file))
            if bitcoin.params.NAME != "mainnet":
                cookie_dir = os.path.join(cookie_dir, bitcoin.params.NAME)
            cookie_file = os.path.join(cookie_dir, ".cookie")
            try:
                with open(cookie_file, 'r') as fd:
                    authpair = fd.read()
            except IOError as err:
                if 'rpcpassword' in conf:
                    authpair = "%s:%s" % (conf['rpcuser'], conf['rpcpassword'])

                else:
                    raise ValueError('Cookie file unusable (%s) and rpcpassword not specified in the configuration file: %r' % (err, btc_conf_file))

        else:
            url = urlparse.urlparse(service_url)
            authpair = "%s:%s" % (url.username, url.password)

        self.__service_url = service_url
        self.__url = urlparse.urlparse(service_url)

        if self.__url.scheme not in ('http',):
            raise ValueError('Unsupported URL scheme %r' % self.__url.scheme)

        if self.__url.port is None:
            port = httplib.HTTP_PORT
        else:
            port = self.__url.port
        self.__id_count = 0

        if authpair is None:
            self.__auth_header = None
        else:
            authpair = authpair.encode('utf8')
            self.__auth_header = b"Basic " + base64.b64encode(authpair)

        if connection:
            self.__conn = connection
        else:
            self.__conn = httplib.HTTPConnection(self.__url.hostname, port=port,
                                                 timeout=timeout)

    def _call(self, service_name, *args):
        self.__id_count += 1

        postdata = json.dumps({'version': '1.1',
                               'method': service_name,
                               'params': args,
                               'id': self.__id_count})

        headers = {
            'Host': self.__url.hostname,
            'User-Agent': DEFAULT_USER_AGENT,
            'Content-type': 'application/json',
        }

        if self.__auth_header is not None:
            headers['Authorization'] = self.__auth_header

        self.__conn.request('POST', self.__url.path, postdata, headers)

        response = self._get_response()
        err = response.get('error')
        if err is not None:
            if isinstance(err, dict):
                raise JSONRPCError(
                    {'code': err.get('code', -345),
                     'message': err.get('message', 'error message not specified')})
            raise JSONRPCError({'code': -344, 'message': str(err)})
        elif 'result' not in response:
            raise JSONRPCError({
                'code': -343, 'message': 'missing JSON-RPC result'})
        else:
            return response['result']

    def _batch(self, rpc_call_list):
        postdata = json.dumps(list(rpc_call_list))

        headers = {
            'Host': self.__url.hostname,
            'User-Agent': DEFAULT_USER_AGENT,
            'Content-type': 'application/json',
        }

        if self.__auth_header is not None:
            headers['Authorization'] = self.__auth_header

        self.__conn.request('POST', self.__url.path, postdata, headers)
        return self._get_response()

    def _get_response(self):
        http_response = self.__conn.getresponse()
        if http_response is None:
            raise JSONRPCError({
                'code': -342, 'message': 'missing HTTP response from server'})

        rdata = http_response.read().decode('utf8')
        try:
            return json.loads(rdata, parse_float=decimal.Decimal)
        except Exception:
            raise JSONRPCError({
                'code': -342,
                'message': ('non-JSON HTTP response with \'%i %s\' from server: \'%.20s%s\''
                            % (http_response.status, http_response.reason,
                               rdata, '...' if len(rdata) > 20 else ''))})

    def close(self):
        if self.__conn is not None:
            self.__conn.close()

    def __del__(self):
        if self.__conn is not None:
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
            # Prevent RPC calls for non-existing python internal attribute
            # access. If someone tries to get an internal attribute
            # of RawProxy instance, and the instance does not have this
            # attribute, we do not want the bogus RPC call to happen.
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
    way. Assumes Bitcoin Core version >= v0.16.0; older versions mostly work,
    but there are a few incompatibilities.
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

    # == Blockchain ==

    def getbestblockhash(self):
        """Return hash of best block in longest block chain."""
        return lx(self._call('getbestblockhash'))

    def getblockheader(self, block_hash, verbose=False):
        """Get block header <block_hash>

        verbose - If true a dict is returned with the values returned by
                  getblockheader that are not in the block header itself
                  (height, nextblockhash, etc.)

        Raises IndexError if block_hash is not valid.
        """
        if not isinstance(block_hash, str):
            try:
                block_hash = b2lx(block_hash)
            except TypeError:
                raise TypeError('%s.getblockheader(): block_hash must be bytes or str; got %r instance' %
                        (self.__class__.__name__, block_hash.__class__))
        try:
            r = self._call('getblockheader', block_hash, verbose)
        except InvalidAddressOrKeyError as ex:
            raise IndexError('%s.getblockheader(): %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))

        if verbose:
            nextblockhash = None
            if 'nextblockhash' in r:
                nextblockhash = lx(r['nextblockhash'])
            return {'confirmations':r['confirmations'],
                    'height':r['height'],
                    'mediantime':r['mediantime'],
                    'nextblockhash':nextblockhash,
                    'chainwork':x(r['chainwork'])}
        else:
            return CBlockHeader.deserialize(unhexlify(r))

    def getblockchaininfo(self):
        """Return a JSON object containing blockchaininfo"""
        return self._call('getblockchaininfo')

    #Untested. Coudln't find valid filter_type? 
    def getblockfilter(self, block_hash, filter_type="basic"):
        """
        Return a JSON object containing filter data and header data
        Default filter_type must be changed
        #UNTESTED
        """
        if not isinstance(block_hash, str):
            try:
                block_hash = b2lx(block_hash)
            except TypeError:
                raise TypeError('%s.getblock(): block_hash must be bytes; got %r instance' %
                        (self.__class__.__name__, block_hash.__class__))

        try:
            r = self._call('getblockfilter', block_hash, filter_type)
        except InvalidAddressOrKeyError as ex:
            raise IndexError('%s.getblockfilter(): %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))
        except JSONRPCError as ex:
            raise IndexError('%s.getblockfilter(): %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))
        return r

    def getblock(self, block_hash):
        """Get block <block_hash>

        Raises IndexError if block_hash is not valid.
        """
        if not isinstance(block_hash, str):
            try:
                block_hash = b2lx(block_hash)
            except TypeError:
                raise TypeError('%s.getblock(): block_hash must be bytes or str; got %r instance' %
                        (self.__class__.__name__, block_hash.__class__))
        try:
            # With this change ( https://github.com/bitcoin/bitcoin/commit/96c850c20913b191cff9f66fedbb68812b1a41ea#diff-a0c8f511d90e83aa9b5857e819ced344 ),
            # bitcoin core's rpc takes 0/1/2 instead of true/false as the 2nd argument which specifies verbosity, since v0.15.0.
            # The change above is backward-compatible so far; the old "false" is taken as the new "0".
            r = self._call('getblock', block_hash, False)
        except InvalidAddressOrKeyError as ex:
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
        except InvalidParameterError as ex:
            raise IndexError('%s.getblockhash(): %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))

    def getblockstats(self, hash_or_height, *args):
        # On clients before PR #17831, passing hash as bytes will result in Block not found
        """Return a JSON object containing block stats"""

        if isinstance(hash_or_height, bytes): 
            hval = b2lx(hash_or_height)
        else: #int or str of block_hash or height
            hval = hash_or_height
        try:
            r = self._call('getblockstats', hval, args)
        except (InvalidAddressOrKeyError, InvalidParameterError) as ex:
            raise IndexError('%s.getblockstats(): %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))
        return r

    def getchaintips(self):
        """Returns JSON object with info on all current tips:"""
        return self._call('getchaintips')

    def getchaintxstats(self, nblocks=None, block_hash=None):
        """Compute stats about transactions in chain"""
        if block_hash is not None:
            if not isinstance(block_hash, str):
                block_hash = b2lx(block_hash)
        return self._call('getchaintxstats', nblocks, block_hash)

    def getdifficulty(self):
        return self._call('getdifficulty')

    def getmempoolancestors(self, txid, verbose=False):
        """Returns a list of txids for ancestor transactions"""
        if not isinstance(txid, str):
            try:
                txid = b2lx(txid)
            except TypeError:
                raise TypeError("%s.getmempoolancestors(): txid must be bytes or str")
        try:
            r = self._call('getmempoolancestors', txid, verbose)
        except InvalidAddressOrKeyError as ex:
            raise IndexError('%s.getmempoolancestors(): %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))
        return r

    def getmempooldescendants(self, txid, verbose=False):
        """Returns a list of txids for descendant transactions"""
        if not isinstance(txid, str):
            try:
                txid = b2lx(txid)
            except TypeError:
                raise TypeError("%s.getmempooldescendants(): txid must be bytes or str")
        try:
            r = self._call('getmempooldescendants', txid, verbose)
        except InvalidAddressOrKeyError as ex:
            raise IndexError('%s.getmempooldescendants(): %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))
        return r

    def getmempoolentry(self, txid):
        """Returns a JSON object for mempool transaction"""
        if not isinstance(txid, str):
            try:
                txid = b2lx(txid)
            except TypeError:
                raise TypeError("%s.getmempoolentry(): txid must be bytes or str")
        try:
            r = self._call('getmempoolentry', txid)
        except InvalidAddressOrKeyError as ex:
            raise IndexError('%s.getmempoolentry(): %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))
        return r

    def getmempoolinfo(self):
        """Returns a JSON object of mempool info"""
        return self._call('getmempoolinfo')

    #Untested
    def getrawmempool(self, verbose=False):
        """Return the mempool"""
        if verbose:
            return self._call('getrawmempool', verbose)

        else:
            r = self._call('getrawmempool')
            r = [lx(txid) for txid in r]
            return r

    def gettxout(self, outpoint, includemempool=True):
        """Return details about an unspent transaction output.
        outpoint - COutPoint or tuple (<txid>, n)
        Raises IndexError if outpoint is not found or was spent.

        includemempool - Include mempool txouts
        """
        if isinstance(outpoint, COutPoint): 
            r = self._call('gettxout', b2lx(outpoint.hash), outpoint.n, includemempool)
        else:
            r = self._call('gettxout', outpoint[0], outpoint[1], includemempool)
        if r is None:
            raise IndexError('%s.gettxout(): unspent txout %r not found' % (self.__class__.__name__, outpoint))

        r['txout'] = CTxOut(int(r['value'] * COIN),
                            CScript(unhexlify(r['scriptPubKey']['hex'])))
        del r['value']
        del r['scriptPubKey']
        r['bestblock'] = lx(r['bestblock'])
        return r

    def gettxoutproof(self, txids, block_hash=None):
        """Returns a hex string object of proof of inclusion in block"""
        if not isinstance(txids[0], str):
            txids = [b2lx(txid) for txid in txids]
        if not isinstance(block_hash, str):
            block_hash = b2lx(block_hash)
        return self._call('gettxoutproof', txids, block_hash)

    def gettxoutsetinfo(self):
        """Returns JSON object about utxo set"""
        # This call will probably time out on a mediocre machine
        return self._call('gettxoutsetinfo')

    #Untested
    def preciousblock(self, block_hash):
        """Marks a block as precious. No return"""
        if not isinstance(block_hash, str):
            block_hash = b2lx(block_hash)
        self._call('preciousblock', block_hash)

    def pruneblockchain(self, height):
        """Prune blockchain to height. No return"""
        self._call('pruneblockchain', height)

    #Untested
    def savemempool(self):
        """Save full mempool to disk. Will fail until
        Previous dump is loaded."""
        self._call('savemempool')

    def scantxoutset(self, action, objects):
        """Scans current utxo set
        Actions: "start", "abort", "status"
        objects: 
        (json array, required) Array of scan objects
        Every scan object is either a string descriptor or an object
        """
        return self._call('scantxoutset', action, objects)

    def verifychain(self, checklevel=3, nblocks=6):
        """Returns a bool upon verifying chain 
        Checklevel - thoroughness of verification (0-4)
        nblocks - number of blocks to check (0=all)
        """
        return self._call('verifychain', checklevel, nblocks)

    def verifytxoutproof(self, proof):
        """Verifies txoutproof.
        returns txid if verified
        returns [] on fail
        """
        #Had several timeouts on this function. Might be natural
        if not isinstance(proof,str):
            proof = proof.hex()
        r = self._call('verifytxoutproof', proof)
        return [lx(txid) for txid in r]

    # == Control ==
    def getmemoryinfo(self, mode=None):
        """Returns a JSON object of memory usage stats:
        Modes: "stats", "mallocinfo"""
        return self._call('getmemoryinfo', mode)

    def getrpcinfo(self):
        """Returns a JSON object of rpc info"""
        return self._call('getrpcinfo')

    def help(self, command=""):
        """Return Help Text"""
        return self._call('help', command)

    #Breaks connection with node. Bitcoin Core still thinks it's
    #Running but all commands (from this client and from cmd line)
    #stop working
    # def stop(self):
    #     """Stops bitcoind"""
    #     self._call('stop')
    
    def uptime(self):
        """Returns int of uptime"""
        return self._call('uptime')

    def logging(self, includes=None, excludes=None):
        """Returns a JSON object of log info"""
        return self._call('logging', includes, excludes)

    # == Generating ==
    def generate(self, numblocks):
        """
        DEPRECATED (will be removed in bitcoin-core v0.19)
        
        Mine blocks immediately (before the RPC call returns)

        numblocks - How many blocks are generated immediately.

        Returns iterable of block hashes generated.
        """
        r = self._call('generate', numblocks)
        return (lx(blk_hash) for blk_hash in r)

    def generatetoaddress(self, numblocks, addr):
        """Mine blocks immediately (before the RPC call returns) and
        allocate block reward to passed address. Replaces deprecated 
        "generate(self,numblocks)" method.

        numblocks - How many blocks are generated immediately.
        addr     - Address to receive block reward (CBitcoinAddress instance)

        Returns iterable of block hashes generated.
        """
        r = self._call('generatetoaddress', numblocks, str(addr))
        return (lx(blk_hash) for blk_hash in r)

    # == Mining ==
    # ALL MINING untested
    def getblocktemplate(self, template_request=None):
        """Returns a JSON object for a blocktemplate with which to mine:
        template_request:
        {
           "mode": "str",       (string, optional) This must be set to "template", "proposal" (see BIP 23), or omitted
           "capabilities": [    (json array, optional) A list of strings
             "support",         (string) client side supported feature, 'longpoll', 'coinbasetxn', 'coinbasevalue', 'proposal', 'serverlist', 'workid'
             ...
           ],
           "rules": [           (json array, required) A list of strings
             "support",         (string) client side supported softfork deployment
             ...
           ],
        }
        Result: JSON

        """
        return self._call('getblocktemplate', template_request)

    def getmininginfo(self):
        """Return a JSON object containing mining-related information"""
        return self._call('getmininginfo')

    def getnetworkhashps(self, nblocks=None, height=None):
        """Returns a int estimate of hashrate at block height
        measured since nblocks (default=120)
        """
        return self._call('getnetworkhashps', nblocks, height)

    def prioritisetransaction(self, txid, fee_delta, dummy=""):
        """Returns true. Prioritises transaction for mining"""
        if not isinstance(txid, str):
            txid = b2lx(txid)
        return self._call('prioritisetransaction', txid, dummy, fee_delta)

    def submitblock(self, block, params=None):
        """Submit a new block to the network.

        params is optional and is currently ignored by bitcoind. See
        https://en.bitcoin.it/wiki/BIP_0022 for full specification.
        """
        if not isinstance(block, str):
            hexblock = block
        else:
            hexblock = hexlify(block.serialize())
        if params is not None:
            return self._call('submitblock', hexblock, params)
        else:
            return self._call('submitblock', hexblock)

    def submitheader(self, hexdata):
        """Submit block to the network."""
        try:
            r = self._call('submitblock', hex_data)
        except VerifyError as ex:
            raise VerifyError('%s.submitheader() - Invalid Header: %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))
        return r

    # == Network ==
    def _addnode(self, node, arg):
        r = self._call('addnode', node, arg)
        return r

    def addnode(self, node):
        return self._addnode(node, 'add')

    def addnodeonetry(self, node):
        return self._addnode(node, 'onetry')

    def removenode(self, node):
        return self._addnode(node, 'remove')

    def clearbanned(self):
        """Clear list of banned IPs"""
        self._call('clearbanned')

    def disconnectnode(self, address="", nodeid=None):
        """Disconnect from node
        1. address    (string, optional, default=fallback to nodeid) The IP address/port of the node
        2. nodeid     (numeric, optional, default=fallback to address) The node ID (see getpeerinfo for node IDs)
        """
        self._call('disconnectnode', address, nodeid)

    def getaddednodeinfo(self, nodeid=None):
        """Returns a JSON object of added nodes (excluding onetry added nodes)"""
        return self._call('getaddednodeinfo',  nodeid)

    def getconnectioncount(self):
        """Return int of connection count"""
        return self._call('getconnectioncount')

    def getnettotals(self):
        """Returns a JSON object of net totals"""
        return self._call('getnettotals')

    def getnetworkinfo(self):
        """Returns a JSON object of network info"""
        return self._call('getnetworkinfo')

    def getnodeaddresses(self, count=None):
        """Returns a JSON object of node addresses"""
        return self._call('getnodeaddresses', count)

    def getpeerinfo(self):
        """Returns a JSON object of peer info"""
        return self._call('getpeerinfo')

    def listbanned(self):
        """Returns a JSON object of banned peers"""
        return self._call('listbanned')

    def ping(self):
        """Ping all connections and record ping time in 
        getpeerinfo
        """
        return self._call('ping')

    def setban(self, subnet, command, bantime=None, absolute=None):
        """Add or remove nodes from banlist"""
        return self._call('setban', subnet, command, bantime, absolute)

    def setnetworkactive(self, state):
        """Enable/Disable all p2p connections"""
        return self._call('setnetworkactive', state)

    # == Rawtransactions ==
    # PSBT
    def analyzepsbt(self, psbt_b64):
        #TODO create PSBT object to pass instead of psbt_b64
        """Return a JSON object of PSBT"""
        return self._call('analyzepsbt', psbt_b64)

    def combinepsbt(self, psbt_b64s):
        #is passing a list the best way?
        #TODO when PSBT object exists, decode this.
        """Return a base64 encoded PSBT"""
        return self._call('combinepsbt', psbt_b64s)

    def converttopsbt(self, tx, permitsigdata=None, iswitness=None):
        """Returns a base64 encoded PSBT"""
        if not isinstance(tx, str):
            tx = hexlify(tx.serialize())
        return self._call('converttopsbt', tx, permitsigdata, iswitness)

    # Python API is different from RPC API: data
    def createpsbt(self, vins, vouts, data="", locktime=0, replaceable=False):
        """Returns a base64-encoded PSBT object
        This is probably not the best implementation,
        but no existing object is suitable for vin or vout.
        vins - list of CTxIn or {"txid": "hex","vout": n,"sequence": n}
        vouts - list of CTxOut or {"address": amount},
        data - hex data NOT JSON
        """
        if isinstance(vins[0], CTxIn):
            ins = []
            for i in vins:
                txid = b2lx(i.prevout.hash)
                vout = i.prevout.n
                sequence = i.nSequence
                ins.append({"txid": txid, "vout": vout, "sequence": sequence})
            vins = ins
        if isinstance(vouts[0], COutPoint):
            outs = []
            for o in vouts:
                try:
                    addr = CBitcoinAddress.from_scriptPubKey(o.scriptPubKey)
                    amount = o.nValue
                    outs.append({str(addr): amount/COIN})
                except CBitcoinAddressError:
                    raise CBitcoinAddressError("Invalid output: %s" % repr(o))
            vouts = outs
        if data:
            vouts.append({"data": data})
        return self._call('createpsbt', vins, vouts, locktime, replaceable)

    def decodepsbt(self, psbt_b64):
        """Returns a JSON object of PSBT.
            Should return a PSBT object when created.
        """
        return self._call('decodepsbt', psbt_b64)

    def finalizepsbt(self, psbt_b64, extract=None):
        """Returns an extracted transaction hex or a PSBT, depending on
        extract
        {
          "psbt" : "value",          
          "hex" : "value",           
          "complete" : true|false,   
          ]
        }
        """
        r = self._call('finalizepsbt', psbt_b64, extract)
        if extract:
            r = CTransaction.deserialize(unhexlify(r))
        else:
            r['tx'] = CTransaction.deserialize(unhexlify(r['hex']))
            del r['hex']
        return r

    def joinpsbts(self, psbt_b64s):
        """Return a base64-encoded PSBT"""
        return self._call('joinpsbts', psbt_b64s)

    def utxoupdatepsbt(self, psbt_b64, data):
        """Return base64-encoded PSBT"""
        return self._call('utxoupdatepsbt', psbt_b64, data)

    #RAW TX
    def combinerawtransaction(self, hextxs):
        """Return raw hex of combined transaction"""
        if not isinstance(hextxs[0], str):
            hextxs = [hexlify(tx.serialize()) for tx in hextxs]
        return self._call('combinerawtransaction', hextxs)

    def createrawtransaction(self, vins, vouts, locktime=0, replaceable=False):
        """Returns a Transaction Object
        Again object should be created to allow vins and vouts
        """
        r = self._call('createrawtransactions', vins, vouts, locktime, replaceable)
        return CTransaction.deserialize(unhexlify(r))

    def getrawtransaction(self, txid, verbose=False, block_hash=None):
        """Return transaction with hash txid

        Raises IndexError if transaction not found.

        verbose - If true a dict is returned instead with additional
        information on the transaction.

        Note that if all txouts are spent and the transaction index is not
        enabled the transaction may not be available.
        """
        #Timeout issues depending on tx / machine
        if not isinstance(txid, str):
            txid = b2lx(txid)
        if not isinstance(block_hash, str):
            block_hash = b2lx(block_hash)
        try:
            r = self._call('getrawtransaction', txid, 1 if verbose else 0, block_hash)
        except InvalidAddressOrKeyError as ex:
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

    def sendrawtransactionv0_19(self, tx, maxfeerate=None):
        """Submit transaction to local node and network.

        maxfeerate - numeric or string for max fee rate
        """
        if not isinstance(tx, str):
            tx = hexlify(tx.serialize())
        r = self._call('sendrawtransaction', tx, maxfeerate)
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

    def decoderawtransaction(self, hex_data, iswitness=None):
        """Return a JSON object representing the transaction"""
        return self._call('decoderawtransaction', hex_data, iswitness)

    def decodescript(self, hex_data):
        """Returns a JSON object with script info"""
        return self._call('decodescript', hex_data)

    def fundrawtransaction(self, tx, include_watching=False):
        """Add inputs to a transaction until it has enough in value to meet its out value.

        include_watching - Also select inputs which are watch only

        Returns dict:

        {'tx':        Resulting tx,
         'fee':       Fee the resulting transaction pays,
         'changepos': Position of added change output, or -1,
        }
        """
        hextx = hexlify(tx.serialize())
        r = self._call('fundrawtransaction', hextx, include_watching)

        r['tx'] = CTransaction.deserialize(unhexlify(r['hex']))
        del r['hex']

        r['fee'] = int(r['fee'] * COIN)

        return r

    def fundrawtransactionv0_19(self, tx, options=None, iswitness=None):
        """
        Options - a JSON dictionary of options. if True is passed, watch-only is included.

        Returns a dict:   
        {'tx':        Resulting tx
         'fee':       Fee the resulting transaction pays,
         'changepos': Position of added change output, or -1,
        }
        """
        if not isinstance(tx, str):
            tx = hexlify(tx.serialize())
        r = self._call('fundrawtransaction', tx, options, iswitness)
        r['tx'] = CTransaction.deserialize(unhexlify(r['hex']))
        del r['hex']
        r['fee'] = int(r['fee'] * COIN) # BTC -> sats
        return r

    def signrawtransactionwithkey(self, tx, privkeys, prevtxs=None, sighashtype=None):
        """Return a transaction object
        privkeys - list of CBitcoinSecret objects or list of base58-encoded privkeys (str)
        prevtxs - JSON object containing info
        sighashtype - numeric sighashtype default=SIGHASH_ALL
        """
        if not isinstance(tx, str):
            tx = hexlify(tx.serialize())
        if isinstance(privkeys[0], CBitcoinSecret):
            privkeys = [str(sk) for sk in privkeys]
        elif isinstance(privkeys[0], bytes):
            privkeys = [sk.hex() for sk in privkeys]
        r = self._call('signrawtransactionwithkey', privkeys, prevtxs, )
        r['tx'] = CTransaction.deserialize(unhexlify(r['hex']))
        del r['hex']
        return r

    def testmempoolaccept(self, txs, maxfeerate=None):
        """Return a JSON object of each transaction's acceptance info"""
        if not isinstance(txs[0],str):
            txs = [hexlify(tx.serialize()) for tx in txs]
        return self._call('testmempoolaccept', txs, maxfeerate)

    # == Util ==

    def validateaddress(self, address):
        """Return information about an address"""
        r = self._call('validateaddress', str(address))
        if r['isvalid']:
            r['address'] = CBitcoinAddress(r['address'])
        if 'pubkey' in r:
            r['pubkey'] = unhexlify(r['pubkey'])
        return r

    def createmultisig(self, nrequired, keys, address_type=None):
        """Return a json object with the address and redeemScript
        nrequired - int required sigs
        keys - list of keys as str or CPubKey
        address_type - Options are "legacy", "p2sh-segwit", and "bech32"

        return:
        {
          "address": CBitcoinAddress,
          "redeemScript": CScript
        }

        """
        if not isinstance(keys[0], str):
            keys = [str(k) for k in keys]
        r = self._call('createmultisig', nrequired, keys, address_type)
        # PLEASE CHECK
        redeemScript = CScript.fromhex(r['redeemScript'])
        r['redeemScript'] = redeemScript
        r['address'] = CBitcoinAddress.from_scriptPubKey(redeemScript.to_p2sh_scriptPubKey())
        return r
    
    def deriveaddresses(self, descriptor, _range=None):
        """Returns addresses from descriptor

        """
        #TODO Descriptors need Implementing
        return self._call('deriveaddresses', descriptor, _range)
    
    def estimatesmartfee(self, conf_target, estimate_mode=None):
        """Returns a JSON object with feerate, errors, and block estimate
        conf_target - attempted number of blocks from current tip to place tx
        estimate_mode:
        "UNSET"
        "ECONOMICAL"            
        default="CONSERVATIVE"
        """
        return self._call('estimatesmartfee', conf_target, estimate_mode)

    def getdescriptorinfo(self, descriptor):
        """Returns a JSON object with info about the descriptor:
        {
          "descriptor" : "desc",         (string) The descriptor in canonical form, without private keys
          "checksum" : "chksum",         (string) The checksum for the input descriptor
          "isrange" : true|false,        (boolean) Whether the descriptor is ranged
          "issolvable" : true|false,     (boolean) Whether the descriptor is solvable
          "hasprivatekeys" : true|false, (boolean) Whether the input descriptor contained at least one private key
        }
        """
        return self._call('getdescriptorinfo', descriptor)

    def signmessagewithprivkey(self, privkey, message):
        """Return signature of signed message
        WARNING: only works with legacy keys. Not P2SH or SegWit
        """
        #TODO THIS SHOULD BE TURNED INTO DERSignature object
        return self._call('signmessagewithprivkey', str(privkey), message)
        
    def verifymessage(self, address, signature, message):
        """Return true/false if message signature is valid"""
        return self._call('verifymessage', str(address), str(signature), message)

    # == Wallet ==
    def abandontransaction(self, txid):
        """Marks in-wallet transaction as abandoned, allowing utxos to be 'respent'"""
        self._call('abandontransaction', b2lx(txid))

    def abortrescan(self):
        """Aborts wallet rescan triggered by an RPC call (ie. privkey)"""
        self._call('abortrescan')

    def addmultisigaddress(self, nrequired, keys, label=None, address_type=None):
        """Add a NON-watch-only multisig address to the wallet. Requires new backup."""
        #Works for both addresses and pubkeys, but hex() vs str() is annoying.
        #TODO see if CPubKey.__str__() is used elsewhere or can be changed.
        if isinstance(keys[0], CBitcoinAddress): 
            keys = [str(k) for k in keys]
        elif isinstance(keys[0], (CPubKey, bytes)):  
            keys = [k.hex() for k in keys]
        r = self._call('addmultisigaddress', nrequired, keys, label, address_type)
        r['address'] = CBitcoinAddress(r['address'])
        r['redeemScript'] = CScript.fromhex(r['redeemScript'])
        return r

    def backupwallet(self, destination):
        """copies current wallet file to destination
        destination - path to directory with or without filename
        """
        self._call('backupwallet', destination)

    def bumpfee(self, txid, options=None):
        """Bump fee of transation in mempool"""
        if not isinstance(txid, str):
            txid = b2lx(txid)
        return self._call('bumpfee', txid, options)

    def createwallet(self, wallet_name, disable_priv_keys=None, blank=None, passphrase=None, avoid_reuse=None ):
        """Create a new Wallet 
        wallet_name - name
        disable_priv_keys - watch_only, default=False
        blank - create a blank wallet with no seed or keys
        passphrase - encrypt wallet with passphrase
        avoid_reuse - segregate reused and clean coins. Better privacy
        Return a JSON object about the new wallet
        """
        return self._call('createwallet', wallet_name, disable_priv_keys, blank, passphrase, avoid_reuse)

    def dumpprivkey(self, addr):
        """Return the private key matching an address
        """
        r = self._call('dumpprivkey', str(addr))
        return CBitcoinSecret(r)
    
    def dumpwallet(self, filename):
        """Dump all wallet keys and imported keys to a file.
        NO OVERWRITING ALLOWED
        returns a JSON object with full absolute path
        """
        self._call('dumpwallet', filename)

    def encryptwallet(self, passphrase):
        """
        Encrypts wallet for the first time.
        This passphrase will be required for all signing after call.
        """
        self._call('encryptwallet', passphrase)

    def getaddressesbylabel(self, label):
        """Return a JSON object with addresses as keys"""
        # Convert to CBitcoinAddress? 
        # not converting addresses makes the dict searchable.
        return self._call('getaddressbylabel', label)

    def getaccountaddress(self, account=None):
        """Return the current Bitcoin address for receiving payments to this
        account."""
        r = self._call('getaccountaddress', account)
        return CBitcoinAddress(r)

    def getaddressinfo(self, address):
        """Return a JSON object of info about address"""
        address = str(address)
        r = self._call('getaddressinfo', address)
        if r['script'] == 'scripthash':
            r['redeemScript'] = CScript.fromhex(r['hex'])
            # Keeping with previous style. why not CPubKey?
            r['pubkey'] = unhexlify(r['pubkey']) 
            # PERHAPS ALSO CHANGE ScriptPubKey to CScript?
        return r

    def getbalance(self, account='*', minconf=1, include_watchonly=False):
        """Get the balance

        account - The selected account. Defaults to "*" for entire wallet. It
        may be the default account using "".

        minconf - Only include transactions confirmed at least this many times.
        (default=1)

        include_watchonly - Also include balance in watch-only addresses (see 'importaddress')
        (default=False)
        """
        r = self._call('getbalance', account, minconf, include_watchonly)
        return int(r*COIN)

    def getbalances(self):
        """Returns a JSON object of balances of all wallets and imported keys
        All balances shown in sats
        """
        r = self._call('getbalances')
        for k in r['mine'].keys():
            r['mine'][k] = int(r['mine'][k]* COIN)
        if 'watchonly' in r:
            for k in r['watchonly'].keys():
                r['watchonly'][k] = int(r['watchonly'][k]* COIN)
        return r

    def getnewaddress(self, account=None, address_type=None):
        """Return a new Bitcoin address for receiving payments.

        If account is not None, it is added to the address book so payments
        received with the address will be credited to account.

        address_type:
        "legacy"
        """
        r = None
        if account is not None or address_type is not None:
            r = self._call('getnewaddress', account, address_type)
        else:
            r = self._call('getnewaddress')

        return CBitcoinAddress(r)

    def getrawchangeaddress(self):
        """Returns a new Bitcoin address, for receiving change.

        This is for use with raw transactions, NOT normal use.
        """
        r = self._call('getrawchangeaddress')
        return CBitcoinAddress(r)

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
        except InvalidAddressOrKeyError as ex:
            raise IndexError('%s.getrawtransaction(): %s (%d)' %
                    (self.__class__.__name__, ex.error['message'], ex.error['code']))
        return r

    def getunconfirmedbalance(self):
        """Deprecated in v0.19.0.1"""
        r = None
        try:
            r = int(self._call('getunconfirmedbalance') * COIN)
            return r
        except:
            raise DeprecationWarning("Use %s.getbalances().mine.untrusted_pending" % self.__class__.__name__)
        
    def getwalletinfo(self):
        """Returns a JSON with wallet info
        Results vary by version.
        """
        r = self._call('getwalletinfo')
        r['paytxfee'] = int(r['paytxfee']*COIN)
        try: # Deprecated
            r['balance'] = int(r['balance']*COIN)
            r['unconfirmed_balance'] = int(r['unconfirmed_balance']*COIN)
            r['immature_balance'] = int(r['immature_balance']*COIN)
        except KeyError:
            pass
        return r
    
    #TODO ADD P2SH arg. This will cause JSONRPCError on older versions
    def importaddress(self, addr, label='', rescan=True):
        """Adds an address or pubkey to wallet without the associated privkey."""
        
        addr = str(addr)

        r = self._call('importaddress', addr, label, rescan)
        return r

    #Since Options is only rescan (bool), change this API?
    def importmulti(self, requests, options=None):
        """Import several pubkeys, privkeys, or scripts
        requests - a JSON object
        options - a JSON object
        return a JSON
        """
        # The Requests JSON is so large, I decided not 
        # to allow CObjects in the JSON. 
        # TODO Fix this?
        return self._call('importmulti', requests, options)

    def importprivkey(self, privkey, label=None, rescan=True):
        """Import a privkey and optionally rescan"""
        self._call('importprivkey', str(privkey), label, rescan)

    def importprunedfunds(self, tx, txout_proof):
        """Import a transaction. Address must already be in wallet.
        User must import subsequent transactions or rescan

        #TODO should txout_proof be an obj?
        """
        if not isinstance(tx, str):
            tx = hexlify(tx.serialize())
        return self._call('importprunedfunds', tx, txout_proof)

    def importpubkey(self, pubkey, label=None, rescan=None):
        """Import pubkey as watchonly"""
        if not isinstance(pubkey, str):
            pubkey = pubkey.hex()
        self._call('importpubkey', pubkey, label, rescan)

    def importwallet(self, filename):
        """Import wallet by filename"""
        self._call('importwallet')

    def keypoolrefill(self, new_size=100):
        """Add more keys to keypool
        new_size - int total size of pool after call
        """
        self._call('keypoolrefill')

    def listaddressgroupings(self):
        """Lists groups of addresses which have common ownership
        exposed by joint use
        Returns a JSON object with list of address groupings (lists)
        """
        # Make into address or leave readable/searchable?
        return self._call('listaddressgroupings')

    def listlabels(self, purpose=None):
        """List all labels that are assigned to addresses with specific purposes"""
        return self._call('listlabels')

    def listlockunspent(self):
        """Returns list of temporarily unspendable outputs."""
        r = self._call('listlockunspent')
        for unspent in r:
            unspent['outpoint'] = COutPoint(lx(unspent['txid']), unspent['vout'])
            del unspent['txid']
            del unspent['vout']
        return r

    def listreceivedbyaddress(self, minconf=1, include_empty=None, include_watchonly=None, address_filter=None):
        """List balances by receiving address
        Return a JSON of address infos
        """
        r = self._call('listreceivedbyaddress', minconf, include_empty, include_watchonly, address_filer)
        for recd in r:
            recd['address'] = CBitcoinAddress(recd['address'])
            recd['amount'] = int(recd['amount']*COIN)
            recd['txid'] = [lx(txid) for txid in recd['txid']]
        return r

    def listreceivedbylabel(self, minconf=1, include_empty=False, include_watchonly=None):
        """List balances by label
        Return a JSON of address infos
        """
        r = self._call('listreceivedbylabel', minconf, include_empty, include_watchonly)
        for recd in r:
            recd['address'] = CBitcoinAddress(recd['address'])
            recd['amount'] = int(recd['amount']*COIN)
            #listreceivedbylabel doesn't return TXIDs. 
            # I will be PR'ing Core to change this in Future.
            #recd['txid'] = [lx(txid) for txid in recd['txid']]
        return r

    def listsinceblock(self, block_hash=None, conf_target=1, include_watchonly=None, include_removed=True): 
        """List balances since block (determined by block_hash)
        """
        r = self._call('listsinceblock', block_hash, conf_target, include_watchonly, include_removed)
        for tx in r['transactions']:
            tx['address'] = CBitcoinAddress(tx['address'])
            tx['amount'] = int(tx['amount']*COIN)
            if 'fee' in tx:
                tx['fee'] = int(tx['fee']*COIN)
            tx['outpoint'] = COutPoint(lx(tx['txid']), tx['vout'])
            del tx['txid']
            del tx['vout']
        if 'removed' in r: # Only present if include_removed
            for tx in r['removed']:
                tx['address'] = CBitcoinAddress(tx['address'])
                tx['amount'] = int(tx['amount']*COIN)
                if 'fee' in tx:
                    tx['fee'] = int(tx['fee']*COIN)
                tx['outpoint'] = COutPoint(lx(tx['txid']), tx['vout'])
                del tx['txid']
                del tx['vout']
        return r

    def listtransactions(self, label=None, count=None, skip=None, include_watchonly=None):
        """List all transactions"""
        r = self._call('listtransaction', label, count, skip, include_watchonly)
        for tx in r['transactions']:
            tx['address'] = CBitcoinAddress(tx['address'])
            tx['amount'] = int(tx['amount']*COIN)
            if 'fee' in tx:
                tx['fee'] = int(tx['fee']*COIN)
            tx['outpoint'] = COutPoint(lx(tx['txid']), tx['vout'])
            del tx['txid']
            del tx['vout']
        if 'removed' in r: # Only present if include_removed
            for tx in r['removed']:
                tx['address'] = CBitcoinAddress(tx['address'])
                tx['amount'] = int(tx['amount']*COIN)
                if 'fee' in tx:
                    tx['fee'] = int(tx['fee']*COIN)
                tx['outpoint'] = COutPoint(lx(tx['txid']), tx['vout'])
                del tx['txid']
                del tx['vout']
        return r

    #TODO add include_unsafe, query_options
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

            # address isn't always available as Bitcoin Core allows scripts w/o
            # an address type to be imported into the wallet, e.g. non-p2sh
            # segwit
            try:
                unspent['address'] = CBitcoinAddress(unspent['address'])
            except KeyError:
                pass
            unspent['scriptPubKey'] = CScript(unhexlify(unspent['scriptPubKey']))
            unspent['amount'] = int(unspent['amount'] * COIN)
            r2.append(unspent)
        return r2

    def listwalletdir(self):
        """Return a JSON object of wallets in wallet directory"""
        return self._call('listwalletdir')

    def listwallets(self):
        """Return a list of currently loaded wallets"""
        return self._call('listwallets')

    def loadwallet(self, filename):
        """Load a wallet from filename or directory name
        Returns a JSON object of result
        """
        return self._call('loadwallet', filename)

    def lockunspent(self, unlock, outpoints):
        """Lock or unlock outpoints"""
        json_outpoints = [{'txid':b2lx(outpoint.hash), 'vout':outpoint.n}
                          for outpoint in outpoints]
        return self._call('lockunspent', unlock, json_outpoints)

    def removeprunedfunds(self, txid):
        """Remove pruned utxos from wallet"""
        if not isinstance(txid, str):
            txid = b2lx(txid)
        self._call('removeprunedfunds', txid)

    def rescanblockchain(self, start_height=0, stop_height=None):
        """Begin rescan of blockchain
        Return a JSON object of result
        """
        return self._call('rescanblockchain')

    #TODO API updates for sendmany and sendtoaddress
    def sendmany(self, fromaccount, payments, minconf=1, comment='', subtractfeefromamount=[]):
        """Send amount to given addresses.

        payments - dict with {address: amount}
        """
        json_payments = {str(addr):float(amount)/COIN
                         for addr, amount in payments.items()}
        r = self._call('sendmany', fromaccount, json_payments, minconf, comment, subtractfeefromamount)
        return lx(r)

    def sendtoaddress(self, addr, amount, comment='', commentto='', subtractfeefromamount=False):
        """Send amount to a given address"""
        addr = str(addr)
        amount = float(amount)/COIN
        r = self._call('sendtoaddress', addr, amount, comment, commentto, subtractfeefromamount)
        return lx(r)

    def sethdseed(self, newkeypool=True, seed=None):
        """Set HD Seed of Wallet
        newkeypool - bool flush old unused addresses, including change addresses
        seed - WIF Private Key. random seed if none
        """
        self._call('sethdseed', newkeypool, str(seed))

    def setlabel(self, address, label):
        """Apply a label to an existing address"""
        self._call('setlabel', str(address), label)

    def settxfee(self, amount):
        """Set fee for transactions of this wallet
        amount - int sats/Bytes
        return bool of success
        """
        # Convert from sats/B to BTC/kB
        amount = (amount/COIN)*1000
        return self._call('settxfee', amount)

    def setwalletflag(self, flag, value=True):
        """Change state of a given flag for a wallet
        flag - options: "avoid_reuse" 
        value - bool new value for flag

        returns a JSON objection with flag and new value
        """
        return self._call('setwalletflag', flag, value)

    def signmessage(self, address, message):
        """Sign a message using privkey associated with given address
        address - CBitcoinAddress or str
        message - full message to be signed
        return signature in base64
        #TODO convert base64 to DERSignature obj
        """
        return self._call('signmessage', str(address), message)

    def signrawtransactionwithwallet(self, tx, *args):
        """Sign inputs for transaction
            bicoincore >= 0.17.x

        FIXME: implement options
        """
        hextx = hexlify(tx.serialize())
        r = self._call('signrawtransactionwithwallet', hextx, *args)
        r['tx'] = CTransaction.deserialize(unhexlify(r['hex']))
        del r['hex']
        return r

    def unloadwallet(self, wallet_name=None):
        """Unload wallet"""
        self._call('unloadwallet')

    # Python API is different from RPC API: data
    def walletcreatefundedpsbt(self, vins, vouts, data=None, locktime=0, options=None, bip32derivs=None):
        """Create funded PSBT from wallet funds
        vins - a list of CTxIn
        vouts - a list of CTxOut
        locktime - raw locktime (block height or unix timestamp)
        options - a JSON object
        bip32derivs - bool include BIP32 paths in PSBT

        returns a JSON object with base64-encoded PSBT, fee, and changepos
        """
        if isinstance(vins[0], CTxIn):
            ins = []
            for i in vins:
                txid = b2lx(i.prevout.hash)
                vout = i.prevout.n
                sequence = i.nSequence
                ins.append({"txid": txid, "vout": vout, "sequence": sequence})
            vins = ins #Allow for JSON to be passed directly
        if isinstance(vouts[0], CTxOut):
            outs = []
            for o in vouts:
                try:
                    addr = CBitcoinAddress.from_scriptPubKey(o.scriptPubKey)
                    amount = o.nValue
                    outs.append({str(addr): amount/COIN})
                except CBitcoinAddressError:
                    raise CBitcoinAddressError("Invalid output: %s" % repr(o))
            vouts = outs
        if data:
            vouts.append({"data": data})
        #TODO allow for addresses in options
            
        r = self._call('walletcreatefundedpsbt', vins, vouts, locktime, options, bip32derivs)
        r['fee'] = int(r['fee'] * COIN)
        return r

    def walletlock(self):
        """locks wallet. Password will be required for future signing"""
        self._call('walletlock')

    def unlockwallet(self, password, timeout=60):
        """Stores the wallet decryption key in memory for 'timeout' seconds.

        password - The wallet passphrase.

        timeout - The time to keep the decryption key in seconds.
        (default=60)
        """
        r = self._call('walletpassphrase', password, timeout)
        #FIXME as of v0.19.0.1 no return
        return r

    def walletpassphrase(self, password, timeout=60):
        """Same as unlockwallet"""
        return self.unlockwallet(password, timeout)

    def walletpassphrasechange(self, oldpassphrase, newpassphrase):
        """Change passphrase from oldpassphrase to newpassphrase"""
        self._call('walletpassphrasechange')

    def walletprocesspsbt(self, psbt, sign=True, sighashtype=None, bip32derivs=None):
        """Process base64-encoded PSBT, add info and sign vins that belong to this wallet
        Return a base64-encoded PSBT
        """
        return self._call('walletprocesspsbt', psbt, sign, sighashtype, bip32derivs)

    def getinfo(self):
        """Return a JSON object containing various state info"""
        try:
            r = self._call('getinfo')
            if 'balance' in r:
                r['balance'] = int(r['balance'] * COIN)
            if 'paytxfee' in r:
                r['paytxfee'] = int(r['paytxfee'] * COIN)
            return r
        except:
            warnings.warn(
                "getinfo is deprecated from version 0.16.0 use getnetworkinfo instead", DeprecationWarning
            )
    


__all__ = (
    'JSONRPCError',
    'ForbiddenBySafeModeError',
    'InvalidAddressOrKeyError',
    'InvalidParameterError',
    'VerifyError',
    'VerifyRejectedError',
    'VerifyAlreadyInChainError',
    'InWarmupError',
    'RawProxy',
    'Proxy',
)
