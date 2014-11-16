Advisories
==============

Mutable vs. Immutable objects
-----------------------------

Like the Bitcoin Core codebase CTransaction is immutable and
CMutableTransaction is mutable; unlike the Bitcoin Core codebase this
distinction also applies to COutPoint, CTxIn, CTxOut, and CBlock.


Endianness Gotchas
------------------

Rather confusingly Bitcoin Core shows transaction and block hashes as
little-endian hex rather than the big-endian the rest of the world uses for
SHA256. python-bitcoinlib provides the convenience functions x() and lx() in
bitcoin.core to convert from big-endian and little-endian hex to raw bytes to
accomodate this. In addition see b2x() and b2lx() for conversion from bytes to
big/little-endian hex.
