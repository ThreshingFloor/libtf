from libtf.logparsers import *

FILE = "data/apache_sample.log"

f = open(FILE, 'r')

t = TFHttpLog(f, "XCX8a4r3fXg8UGnq7CsJ7yFMTK3rGd48KN68a6h0")

f.close()

for line in t.reduce():
    print line