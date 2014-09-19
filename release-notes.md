python-bitcoinlib release notes
===============================

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

