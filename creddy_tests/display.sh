#!/usr/bin/env sh
#display.sh

if [ -z "${TESTDIR}" ] ; then
    TESTDIR=..
fi
. ${TESTDIR}/test_util.sh

runTest "creddy_tests/display.sh" "test1"  \
"$eloc/creddy --display --show=all --cert Acme_ID.pem" \
0  "display an issuer cert"

runTest "creddy_tests/display.sh" "test2"  \
"$eloc/creddy --display --show=all --cert Acme_private.pem" \
1  "display a privkey file"

runTest "creddy_tests/display.sh" "test3"  \
"$eloc/creddy --display --show=all --cert Acme_buy_rockets__Acme_preferred_customer_attr.xml" \
0  "display an attribute cert"

runTest "creddy_tests/display.sh" "test4"  \
"$eloc/creddy --display --show=all --cert Acme_preferred_customer__Coyote_attr.xml" \
0  "display an attribute cert"

runTest "creddy_tests/display.sh" "test5"  \
"$eloc/creddy --display --show=all --cert bad_attr.xml" \
1  "supplied a none existing attribute cert"

runTest "creddy_tests/display.sh" "test6"  \
"$eloc/creddy --display --show=all --cert not_ss.pem" \
0  "display an none self signed issuer cert"

runTest "creddy_tests/display.sh" "test7"  \
"$eloc/creddy --display --show=all --cert not_ss.xml" \
0  "display a none self signed attribute cert"

runTest "creddy_tests/display.sh" "test8"  \
"$eloc/creddy --display --show=all --cert iProtoGENI.xml" \
1  "display an expired GENI signed attribute cert"

#runTest "creddy_tests/display.sh" "test9"  \
#"$eloc/creddy --display --show=all --cert ProtoGENI.xml" \
#0  "FAKE:display a valid GENI signed attribute cert"
# ProtoGENI certificate out of date

runTest "creddy_tests/display.sh" "test10"  \
"$eloc/creddy --display --show=all --cert PGissuer.pem" \
0  "display a GENI issuer cert"

runTest "creddy_tests/display.sh" "test11"  \
"$eloc/creddy --display --show=all --cert priv.xml" \
0  "display a GENI privilege attribute cert"


