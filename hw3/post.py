#!/usr/bin/python -u

import os
import sys

if len(sys.argv) < 3:
        print "Usage: %s <etype> <executable> <args...>" % (sys.argv[0])
        sys.exit(1)

etype      = sys.argv[1]
executable = sys.argv[2]
args       = sys.argv[3:]

print "POST /%s_%s HTTP/1.1\r\nContent-Length: 10000000\r\n\r\n" % (etype, os.environ['HOSTNAME'])
sys.stdout.flush()
p = os.popen("%s " % (executable, " ".join(args)), 'r', 0)
line = p.readline()

while line != '':
	sys.stdout.write(line)
	line = p.readline()

