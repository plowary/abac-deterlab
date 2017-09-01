#!/usr/bin/env sh
# newguy.sh

if [ -z "${TESTDIR}" ] ; then
    TESTDIR=../..
fi
. ${TESTDIR}/test_util.sh

$eloc/creddy --generate --cn newGuy 
mv newGuy_ID.pem newGuy.pem

