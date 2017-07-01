#!/usr/bin/env python3
#
# Copyright (C) 2013-2015 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from __future__ import absolute_import, division, print_function, unicode_literals

from bitcoin import base58

def parser():
    import argparse
    parser = argparse.ArgumentParser(
        description='Decode a minikey to base58 format.',
        epilog='Security warning: arguments may be visible to other users on the same host.')
    parser.add_argument(
        'minikey',
        help='the minikey')
    return parser

if __name__ == '__main__':
    args = parser().parse_args()
    try:
        base58_key = base58.decode_minikey(args.minikey)
    except Exception as error:
        print('%s: %s' % (error.__class__.__name__, str(error)))
        exit(1)
    else:
        print(base58_key)
