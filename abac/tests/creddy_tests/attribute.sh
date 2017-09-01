#!/usr/bin/env sh
#attribute.sh

if [ -z "${TESTDIR}" ] ; then
    TESTDIR=..
fi
. ${TESTDIR}/test_util.sh

runTest "creddy_tests/attribute.sh" "test1"  \
"$eloc/creddy --attribute \
       --issuer Acme_ID.pem --key Acme_private.pem --role roleOne \
       --subject-cert Acme_ID.pem --subject-role simple_subject_role \
       --out Acme_roleOne__Acme_simple_subject_role_attr.xml" \
0  "simple role attribute creation with same issuer"

runTest "creddy_tests/attribute.sh" "test2"  \
"$eloc/creddy --attribute \
       --issuer Acme_ID.pem --role roleTwo \
       --subject-cert Acme_ID.pem --subject-role simple_subject_role \
       --out Acme_roleTwo__Acme_simple_subject_role_attr.xml" \
1  "simple role attribute creation without privkey key"

runTest "creddy_tests/attribute.sh" "test3"  \
"$eloc/creddy --attribute \
       --issuer Acme_ID.pem --key Acme_private.pem --role roleThree \
       --subject-cert Coyote_ID.pem --subject-role simple_subject_role \
       --out Acme_roleThree__Coyote_simple_subject_role_attr.xml" \
0  "simple role attribute creation with differ issuer certs"

runTest "creddy_tests/attribute.sh" "test4"  \
"$eloc/creddy --attribute \
       --issuer Acme_ID.pem --key Coyote_private.pem --role roleFour \
       --subject-cert Coyote_ID.pem --subject-role simple_subject_role \
       --out Acme_roleFour__Coyote_simple_subject_role_attr.xml" \
1  "simple role attribute creation with wrong privkey key"

