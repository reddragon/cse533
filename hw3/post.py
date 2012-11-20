#!/usr/bin/python -u
import os
import sys
print "POST /%s HTTP/1.1\r\nContent-Length: 10000000\r\n\r\n" % os.environ['HOSTNAME']
sys.stdout.flush()
p = os.popen("./ODR_gmenghani " + sys.argv[1], 'r', 0)
line = p.readline()
while line != '':
	sys.stdout.write(line)
	line = p.readline()

