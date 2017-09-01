#!/usr/bin/env bash

# id4.ck
r1=`grep "id has privkey 1" id4.out 2>/dev/null |wc -l`
r2=`grep "id1 has privkey 1" id4.out 2>/dev/null |wc -l`
r3=`grep "id2 has privkey 0" id4.out 2>/dev/null |wc -l`

if [ $r1 -eq 1 -a $r2 -eq 1 -a $r3 -eq 1 ]; then
    exit 0
else
    exit 1
fi
