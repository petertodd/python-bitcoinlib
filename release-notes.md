python-bitcoinlib release notes
===============================

v0.4.0
======

Major fix: OpenSSL 1.0.1k rejects non-canonical DER signatures, which Bitcoin
Core does not, so we now canonicalize signatures prior to passing them to
OpenSSL. Secondly we now only generate low-S DER signatures as per BIP62.

API changes that might break compatibility with existing code:

* MAX_MONEY is now a core chain parameter
* MainParams now inherits from CoreMainParams rather than CoreChainParams
* str(<COutPoint>) now returns hash:n format; previously was same as repr()
* RawProxy() no longer has _connection parameter

Notable bugfixes:

* MsgSerializable.to_bytes() no longer clobbers testnet params
* HTTPS RPC connections now use port 443 as default
* No longer assumes bitcoin.conf specifes rpcuser

New features:

* New RPC calls: dumpprivkey, importaddress
* Added P2P support for msg_notfound and msg_reject
* Added support for IPv6 addr messages


v0.3.0
======

Major change: cleaned up what symbols are exported by modules. \_\_all\_\_ is now
used extensively, which may break some applications that were not importing the
right modules. Along those lines some implementation details like the ssl
attribute of the bitcoin.core.key module, and the entire bitcoin.core.bignum
module, are no longer part of the public API. This should not affect too many
users, but it will break some code.

Other notable changes:

* New getreceivedbyaddress RPC call.
* Fixed getbalance RPC call when wallet is configured off.
* Various code cleanups and minor bug fixes.


v0.2.1
======

* Improve bitcoin address handling. P2SH and P2PKH addresses now get their own
  classes - P2SHBitcoinAddress and P2PKHBitcoinAddress respectively - and P2PKH
  can now convert scriptPubKeys containing non-canonical pushes as well as bare
  checksig to addresses.
* .deserialize() methods now fail if there is extra data left over.
* Various other small bugfixes.
* License is now LGPL v3 or later.


v0.2.0
======

Major change: CTransaction, CBlock, etc. now come in immutable (default) and
mutable forms. In most cases mutable and immutable can be used interchangeably;
when that is not possible methods are provided to create new (im)mutable
objects from (im)mutable ones efficiently.

Other changes:

* New BIP70 payment protocol example. (Derren Desouza)
* Rework of message serialization. Note that this may not represent the final
  form of P2P support, which is still in flux. (Florian Schmaus)
* Various bugfixes

Finally starting this release, git tags will be of the form
'python-bitcoinlib-(version)', replacing the less specific '(version)' form
previously used.

