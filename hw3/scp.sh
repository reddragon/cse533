#!/bin/sh
tar -cf src.tar *.c *.h Makefile make_gitcommit.sh post.py scp.sh
scp src.tar minix:~/cse533/src/
ssh minix 'cd cse533/src/ && tar -xf src.tar && make clean debug && ../exec_vms "pgrep -f "gmenghani" | xargs kill -9" && ../deploy_app ODR_gmenghani client_gmenghani server_gmenghani post.py && ../exec_vms "/home/gmenghani/post.py ODR /home/gmenghani/ODR_gmenghani 2 | nc dhruvbird.com 7921" && ../exec_vms "/home/gmenghani/post.py server /home/gmenghani/server_gmenghani 2 | nc dhruvbird.com 7921"'
