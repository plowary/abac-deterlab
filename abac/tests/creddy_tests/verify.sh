#!/usr/bin/env sh
#creddy --verify --cert <issuer> [ --attrcert <cert> ]
#verify.sh

if [ -z "${TESTDIR}" ] ; then
    TESTDIR=..
fi
. ${TESTDIR}/test_util.sh

runXTest "creddy_tests/verify.sh" "test1" \
"$eloc/creddy --verify --cert Coyote_ID.pem --attrcert Acme_buy_rockets__Acme_preferred_customer_attr.xml" \
0  "have mismatched principals" "ID and attr are still valid but differ in principals"

runTest "creddy_tests/verify.sh" "test2" \
"$eloc/creddy --verify --cert Acme_ID.pem --attrcert Acme_buy_rockets__Acme_preferred_customer_attr.xml" \
0  "matching principal and attribute"

runTest "creddy_tests/verify.sh" "test3" \
"$eloc/creddy --verify --cert Acme_private.pem" \
1 "verify with just a privkey"

## this should really fail with a specific error code, 
runTest "creddy_tests/verify.sh" "test4" \
"$eloc/creddy --verify --cert Acme_ID.pem --attrcert bad_attr.xml" \
0  "verify with non existing attribute, but still pass because issuer is okay"

runTest "creddy_tests/verify.sh" "test5"  \
"$eloc/creddy --verify --cert Acme_buy_rockets__Acme_preferred_customer_attr.xml " \
1  "verify with just an attribute"

runTest "creddy_tests/verify.sh" "test6"  \
"$eloc/creddy --verify --cert bad_attr.xml" \
1  "verify with just a none existing attribute"

runTest "creddy_tests/verify.sh" "test7"  \
"$eloc/creddy --verify --cert Coyote_ID.pem" \
0  "verify just an issuer"

runTest "creddy_tests/verify.sh" "test8"  \
"$eloc/creddy --verify --cert not_ss.pem" \
0  "verify just a none self signed principal pem"

runTest "creddy_tests/verify.sh" "test9" \
"$eloc/creddy --verify --attrcert not_ss.xml" \
1  "verify just a none self signed attribute"

runTest "creddy_tests/verify.sh" "test10" \
"$eloc/creddy --verify --cert not_ss.xml" \
1  "incorrectly trying to verify a none self signed attribute as an issuer cert"

runTest "creddy_tests/verify.sh" "test11"  \
"$eloc/creddy --verify --cert priv.xml" \
1  "trying to verify GENI privilege attribute as an issuer cert"

runTest "creddy_tests/verify.sh" "test12"  \
"$eloc/creddy --verify --cert PGissuer.pem" \
0  "verify a GENI's issuer pem"

runTest "creddy_tests/verify.sh" "test13"  \
"$eloc/creddy --verify --cert ProtoGENI.xml" \
1  "incorrectly trying to verify a GENI issued attribute as issuer cert"


