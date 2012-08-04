
#
# Log.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import sys


class Log(object):
	def __init__(self, filename=None):
		if filename is not None:
			self.fh = open(filename, 'a+', 0)
		else:
			self.fh = sys.stdout

	def write(self, msg):
		line = "%s\n" % msg
		self.fh.write(line)

