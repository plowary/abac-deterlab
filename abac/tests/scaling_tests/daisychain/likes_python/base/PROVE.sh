#!/usr/bin/env sh

if [ -z "${TESTDIR}" ] ; then
    TESTDIR=../../../..
fi
. $(TESTDIR)/test_util.sh

keystore=`pwd`
pID=`$eloc/creddy --keyid --cert ${keystore}/John#VAL#_ID.pem`
cID=`$eloc/creddy --keyid --cert ${keystore}/John0_ID.pem`

#JohnX likes John0?

role="${pID}.likes"
principal="${cID}"

$keystore/../../../../example_scripts/c/abac_prover "$keystore" "$role" "$principal"

#echo "$keystore" "$role" "$principal"
#gdb $keystore/../../../../example_scripts/c/abac_prover


