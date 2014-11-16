Getting Started
=================


Requirements
------------

To install python-bitcoinlib:

.. code-block:: bash

    sudo apt-get install libssl-dev
    pip install python-bitcoinlib
    # Or for the latest git version
    pip install git+https://github.com/petertodd/python-bitcoinlib

The RPC interface, ``bitcoin.rpc``, is designed to work with Bitcoin Core v0.9.
Older versions mostly work but there do exist some incompatibilities.

Example Code
------------

See examples/ directory. For instance this example creates a transaction
spending a pay-to-script-hash transaction output:

.. code-block:: bash

    $ PYTHONPATH=. examples/spend-pay-to-script-hash-txout.py
    <hex-encoded transaction>

Also see dust-b-gone for a simple example of Bitcoin Core wallet interaction
through the RPC interface: https://github.com/petertodd/dust-b-gone


Selecting the chain to use
--------------------------

Do the following:

.. code-block:: python

    import bitcoin
    bitcoin.SelectParams(NAME)

Where NAME is one of 'testnet', 'mainnet', or 'regtest'. The chain currently
selected is a global variable that changes behavior everywhere, just like in
the Satoshi codebase.


Unit tests
----------

Under bitcoin/tests using test data from Bitcoin Core. To run them:

.. code-block:: bash

    tox
