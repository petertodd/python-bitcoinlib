

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

try:
    import http.client as httplib
except ImportError:
    import httplib
import base64
import decimal
import json
import os
import platform
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

from bitcoin.coredefs import COIN
from bitcoin.base58 import CBitcoinAddress

USER_AGENT = "AuthServiceProxy/0.1"

HTTP_TIMEOUT = 30


class JSONRPCException(Exception):
    def __init__(self, rpc_error):
        super(JSONRPCException, self).__init__('msg: %r  code: %r' %
                (rpc_error['message'], rpc_error['code']))
        self.error = rpc_error


class RawProxy(object):
    # FIXME: need a CChainParams rather than hard-coded service_port
    def __init__(self, service_url=None,
                       service_port=8332,
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
                    btc_conf_file = os.path.join(os.environ['APPDATA'], 'Bitcoin')
                elif platform.system() == 'Windows':
                    btc_conf_file = os.path.expanduser('~/Library/Application Support/Bitcoin/')
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
            self.__conn = httplib.HTTPSConnection(self.__url.hostname, port,
                                                  None, None, False,
                                                  timeout)
        else:
            self.__conn = httplib.HTTPConnection(self.__url.hostname, port,
                                                 False, timeout)


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
                       service_port=8332,
                       btc_conf_file=None,
                       timeout=HTTP_TIMEOUT,
                       **kwargs):
        """Create a proxy to a bitcoin RPC service

        Unlike RawProxy data is passed as objects, rather than JSON. (not yet
        fully implemented)

        If service_url is not specified the username and password are read out
        of the file btc_conf_file. If btc_conf_file is not specified
        ~/.bitcoin/bitcoin.conf or equivalent is used by default.

        Usually no arguments to Proxy() are needed; the local bitcoind will be
        used.

        timeout - timeout in seconds before the HTTP interface times out
        """
        super(Proxy, self).__init__(service_url=service_url, service_port=service_port, btc_conf_file=btc_conf_file,
                                    timeout=HTTP_TIMEOUT,
                                    **kwargs)

    def getinfo(self):
        """Returns an object containing various state info"""
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

        return CBitcoinAddress.from_str(r)

    def getaccountaddress(self, account=None):
        """Return the current Bitcoin address for receiving payments to this account."""
        r = self._call('getaccountaddress', account)
        return CBitcoinAddress.from_str(r)

    def validateaddress(self, address):
        """Return information about an address"""
        r = self._call('validateaddress', str(address))
        r['address'] = CBitcoinAddress.from_str(r['address'])
        return r
