"""
print difficult of blocks through time
"""

import bitcoin.rpc
import datetime

proxy = bitcoin.rpc.Proxy()

def datestr(utime):
    dateFormat = '%Y-%m-%d'
    return datetime.datetime.fromtimestamp(int(utime)).strftime(dateFormat)

n = 100
start = 1
n = 380965 #last block as of 2015-10-27
blocks_day = 144
skip = blocks_day*30*3 # every 3 months
print('*** Bitcoin difficulty ***')
for i in range(start, start+n,skip):
    h = proxy.getblockhash(i)
    block = proxy.getblock(h)

    print('%s %s'%(datestr(block.nTime),block.difficulty))
