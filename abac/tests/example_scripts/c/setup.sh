#!/usr/bin/env sh
# setup.sh

if [ -z "${TESTDIR}" ] ; then
    TESTDIR=../..
fi
. ${TESTDIR}/test_util.sh

$eloc/creddy --generate --cn IceCream
$eloc/creddy --generate --cn Chocolate



