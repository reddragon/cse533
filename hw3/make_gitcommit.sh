#! /bin/bash
COMMITID=`git log | head -n 1 | cut -f 2 -d " "`
echo "#define COMMITID \"$COMMITID\"" > gitcommit.h
