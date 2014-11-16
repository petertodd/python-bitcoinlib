python-bitcoinlib
-----------------
[![Build Status](https://travis-ci.org/icook/python-bitcoinlib.svg?branch=master)](https://travis-ci.org/icook/python-bitcoinlib)

This Python library provides an easy interface to the bitcoin data
structures and protocol. The approach is low-level and "ground up", with a
focus on providing tools to manipulate the internals of how Bitcoin works.

> "The Swiss Army Knife of Bitcoin protocol." - Wladimir J. van der Laan

Currently supported tested versions include:

* Python 3.4
* Python 3.3
* Python 3.2
* Python 2.7

Requirements
------------

    sudo apt-get install libssl-dev

The RPC interface, bitcoin.rpc, is designed to work with Bitcoin Core v0.9.
Older versions mostly work but there do exist some incompatibilities.


Structure
---------

Everything consensus critical is found in the modules under bitcoin.core. This
rule is followed pretty strictly, for instance chain parameters are split into
consensus critical and non-consensus-critical.

* bitcoin.core            - Basic core definitions, datastructures, and
  (context-independent) validation
* bitcoin.core.bignum     - Bignum handling
* bitcoin.core.key        - ECC pubkeys
* bitcoin.core.script     - Scripts and opcodes
* bitcoin.core.scripteval - Script evaluation/verification
* bitcoin.core.serialize  - Serialization

In the future the bitcoin.core may use the Satoshi sourcecode directly as a
libary. Non-consensus critical modules include the following:

* bitcoin            - Chain selection
* bitcoin.base58     - Base58 encoding
* bitcoin.bloom      - Bloom filters (incomplete)
* bitcoin.net        - Network communication (in flux)
* bitcoin.messages   - Network messages (in flux)
* bitcoin.rpc        - Bitcoin Core RPC interface support
* bitcoin.wallet     - Wallet-related code, currently Bitcoin address and
  private key support

Effort has been made to follow the Satoshi source relatively closely, for
instance Python code and classes that duplicate the functionality of
corresponding Satoshi C++ code uses the same naming conventions: CTransaction,
CBlockHeader, nValue etc. Otherwise Python naming conventions are followed.


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


Example Code
------------

See examples/ directory. For instance this example creates a transaction
spending a pay-to-script-hash transaction output:

    $ PYTHONPATH=. examples/spend-pay-to-script-hash-txout.py
    <hex-encoded transaction>

Also see dust-b-gone for a simple example of Bitcoin Core wallet interaction
through the RPC interface: https://github.com/petertodd/dust-b-gone


Selecting the chain to use
--------------------------

Do the following:

    import bitcoin
    bitcoin.SelectParams(NAME)

Where NAME is one of 'testnet', 'mainnet', or 'regtest'. The chain currently
selected is a global variable that changes behavior everywhere, just like in
the Satoshi codebase.


Unit tests
----------

Under bitcoin/tests using test data from Bitcoin Core. To run them:

python -m unittest discover
python3 -m unittest discover
