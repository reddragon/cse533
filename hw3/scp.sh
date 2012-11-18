#!/bin/sh
tar -cf src.tar *.c *.h Makefile
scp src.tar minix:~/cse533/src/
ssh minix 'cd cse533/src/ && tar -xf src.tar && make clean debug && ../deploy_app ODR_gmenghani client_gmenghani'
