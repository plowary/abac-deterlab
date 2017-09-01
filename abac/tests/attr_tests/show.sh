#!/usr/bin/env sh
#show.sh

if [ -z "${TESTDIR}" ] ; then
    TESTDIR=../../../..
fi
. ${TESTDIR}/test_util.sh

#expect 1 rule
runCTest "attr_tests/show.sh" "test1" \
"$eloc/creddy --roles --cert abac_attr.xml" \
0 "show a V0 abac attribute-1 rule" "<-" 1

#expect 6 rule
runCTest "attr_tests/show.sh" "test2" \
"$eloc/creddy --roles --cert privilege_attr.xml" \
0 "show a V0 GENI privilege attribute-6 rules" "<-" 6

#expect 1 rule
runCTest "attr_tests/show.sh" "test3" \
"$eloc/creddy --roles --cert not_ss.xml" \
0 "show a V0 abac not self signed attribute-1 rule" "<-" 1


