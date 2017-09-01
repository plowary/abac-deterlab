#!/usr/bin/env sh
#roles.sh

if [ -z "${TESTDIR}" ] ; then
    TESTDIR=..
fi
. ${TESTDIR}/test_util.sh

runTest "creddy_tests/role.sh" "test1"  \
"$eloc/creddy --roles --cert Acme_ID.pem" \
 1  "supplied  with a issuer cert"

runTest "creddy_tests/role.sh" "test2"  \
"$eloc/creddy --roles --cert Acme_private.pem" \
 1  "supplied with a privkey"

runTest "creddy_tests/role.sh" "test3"  \
"$eloc/creddy --roles --cert Acme_buy_rockets__Acme_preferred_customer_attr.xml" \
 0  "supplied with right attribute cert"

runTest "creddy_tests/role.sh" "test4"  \
"$eloc/creddy --roles --cert bad_attr.xml" \
 1  "supplied with a none existing cert"

runTest "creddy_tests/role.sh" "test5"  \
"$eloc/creddy --roles --cert priv.xml" \
 0  "supplied with a GENI priviledge cert"

runTest "creddy_tests/role.sh" "test6"  \
"$eloc/creddy --roles --cert not_ss.xml" \
 0  "supplied with a none self signed attribute cert"

runTest "creddy_tests/role.sh" "test7"  \
"$eloc/creddy --roles --cert iProtoGENI.xml" \
 1  "supplied with an expired  GENI signed attribute cert"



