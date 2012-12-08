#!/bin/sh
tar -cf src.tar *.c *.h Makefile README post.py scp.sh
scp src.tar minix:~/cse533/src/
ssh minix 'cd cse533/src/ && tar -xf src.tar && make clean all && ../exec_vms "rm -Rf /home/gmenghani && mkdir -p /home/gmenghani/ && mkdir -p /tmp/dynamic_duo/ && pgrep -f "gmenghani" | xargs kill -9" && ../deploy_app gmenghani_arp gmenghani_tour post.py && ../exec_vms "/home/gmenghani/post.py ARP /home/gmenghani/gmenghani_arp | nc dhruvbird.com 7922" && ../exec_vms "/home/gmenghani/post.py TOUR /home/gmenghani/gmenghani_tour | nc dhruvbird.com 7922"'

# ssh minix 'cd cse533/src/ && tar -xf src.tar && make clean all && ../exec_vms "pgrep -f "gmenghani" | xargs kill -9" && ../deploy_app gmenghani_arp post.py && ../exec_vms "/home/gmenghani/post.py ODR /home/gmenghani/ODR_gmenghani 6000 | nc dhruvbird.com 7921" && ../exec_vms "/home/gmenghani/post.py server /home/gmenghani/server_gmenghani | nc dhruvbird.com 7921"'
