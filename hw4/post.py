#!/usr/bin/python -u

import os
import sys

if len(sys.argv) < 3:
        print "Usage: %s <etype> <executable> <args...>" % (sys.argv[0])
        sys.exit(1)

etype      = sys.argv[1]
executable = sys.argv[2]
args       = sys.argv[3:]

p = os.popen("hostname", 'r', 0)
hostname = p.readline()

print "POST /%s_%s HTTP/1.1\r\nContent-Length: 10000000\r\n\r\n" % (etype, hostname)
sys.stdout.flush()
# cmd = "gdb %s -batch -x /tmp/%s_gmenghani.gdb" % (executable, etype)
cmd = "valgrind %s %s" % (executable, (" ".join(args)))
f = open(("/tmp/%s_gmenghani.gdb" % etype), "w")
f.write("r "  + (" ".join(args)) + "\n" + "bt\n");
f.close()

(sin, sout) = os.popen4(cmd, 'r', 0)
line = sout.readline()

while line != '':
	sys.stdout.write(line)
	line = sout.readline()
