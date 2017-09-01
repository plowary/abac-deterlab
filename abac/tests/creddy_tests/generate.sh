#!/usr/bin/env sh
#generate.sh

if [ -z "${TESTDIR}" ] ; then
    TESTDIR=..
fi
. ${TESTDIR}/test_util.sh

runTest "creddy_tests/generate.sh" "test1", \
"$eloc/creddy --generate --cn Bigbird"  \
0  "simple id credential generation"

runTest "creddy_tests/generate.sh" "test2", \
"$eloc/creddy --generate --cn 12_3"  \
0  "generate with underline in name"

runTest "creddy_tests/generate.sh" "test3", \
"$eloc/creddy --generate --cn Bad$name"  \
0  "generate with special $ as Bad$name, later part just got dropped"

runTest "creddy_tests/generate.sh" "test4", \
"$eloc/creddy --generate --cn abc --cert gen_attr.xml"  \
0  "generate with supplied attribute name"

