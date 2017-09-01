#!/usr/bin/env sh
# keyid.sh

if [ -z "${TESTDIR}" ] ; then
    TESTDIR=..
fi
. ${TESTDIR}/test_util.sh

runTest "creddy_tests/keyid.sh" "test1"  \
"$eloc/creddy --keyid --cert Acme_ID.pem" \
0  "supplied with good identity cert"

runTest "creddy_tests/keyid.sh" "test2"  \
"$eloc/creddy --keyid --cert Acme_private.pem" \
1  "supplied with privkey"

runTest "creddy_tests/keyid.sh" "test3"  \
"$eloc/creddy --keyid --cert Acme_buy_rockets__Acme_preferred_customer_attr.xml" \
1  "supplied with attribute cert instead"

runTest "creddy_tests/keyid.sh" "test4"  \
"$eloc/creddy --keyid --cert bad_attr.xml" \
1  "supplied with non existing attribute cert"

runTest "creddy_tests/keyid.sh" "test5"  \
"$eloc/creddy --keyid --cert not_ss.pem" \
0  "supplied with good none self signed identity cert"

runTest "creddy_tests/keyid.sh" "test6"  \
"$eloc/creddy --keyid --cert not_ss.xml" \
1  "supplied with none self signed attribute cert"

runTest "creddy_tests/keyid.sh" "test7"  \
"$eloc/creddy --keyid --cert priv.xml" \
1  "supplied with GENI privilege attribute cert"

runTest "creddy_tests/keyid.sh" "test8"  \
"$eloc/creddy --keyid --cert PGissuer.pem" \
0  "supplied with GENI issuer cert"

runTest "creddy_tests/keyid.sh" "test9"  \
"$eloc/creddy --keyid --cert ProtoGENI.xml" \
1  "supplied with GENI issued attribute cert"

