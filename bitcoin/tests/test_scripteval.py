# Copyright (C) 2013-2014 The python-bitcoinlib developers
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

import json
import os
import unittest

import sys
if sys.version > '3':
    long = int

from binascii import unhexlify

from bitcoin.core import ValidationError
from bitcoin.core.script import *
from bitcoin.core.scripteval import *

def parse_script(s):
    def ishex(s):
        return set(s).issubset(set('0123456789abcdefABCDEF'))

    r = []

    # Create an opcodes_by_name table with both OP_ prefixed names and
    # shortened ones with the OP_ dropped.
    opcodes_by_name = {}
    for name, code in OPCODES_BY_NAME.items():
        opcodes_by_name[name] = code
        opcodes_by_name[name[3:]] = code

    for word in s.split():
        if word.isdigit() or (word[0] == '-' and word[1:].isdigit()):
            r.append(CScript([long(word)]))
        elif word.startswith('0x') and ishex(word[2:]):
            # Raw ex data, inserted NOT pushed onto stack:
            r.append(unhexlify(word[2:].encode('utf8')))
        elif len(word) >= 2 and word[0] == "'" and word[-1] == "'":
            r.append(CScript([bytes(word[1:-1].encode('utf8'))]))
        elif word in opcodes_by_name:
            r.append(CScript([opcodes_by_name[word]]))
        else:
            raise ValueError("Error parsing script: %r" % s)

    return CScript(b''.join(r))


def load_test_vectors(name):
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        for test_case in json.load(fd):
            if len(test_case) < 3:
                test_case.append('')
            scriptSig, scriptPubKey, comment = test_case

            scriptSig = parse_script(scriptSig)
            scriptPubKey = parse_script(scriptPubKey)

            yield (scriptSig, scriptPubKey, comment, test_case)


class Test_EvalScript(unittest.TestCase):
    flags = (SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_STRICTENC)
    def test_script_valid(self):
        for scriptSig, scriptPubKey, comment, test_case in load_test_vectors('script_valid.json'):
            try:
                VerifyScript(scriptSig, scriptPubKey, None, 0, flags=self.flags)
            except ValidationError as err:
                self.fail('Script FAILED: %r %r %r with exception %r' % (scriptSig, scriptPubKey, comment, err))

    def test_script_invalid(self):
        for scriptSig, scriptPubKey, comment, test_case in load_test_vectors('script_invalid.json'):
            with self.assertRaises(ValidationError):
                VerifyScript(scriptSig, scriptPubKey, None, 0, flags=self.flags)
