python-bitcoinlib release notes
===============================

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

