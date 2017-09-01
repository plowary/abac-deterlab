#!/usr/bin/env sh
#attribute_rule.sh

if [ -z "${TESTDIR}" ] ; then
    TESTDIR=..
fi
. ${TESTDIR}/test_util.sh

bigbird=`$eloc/creddy --keyid --cert Bigbird_ID.pem`
coyote=`$eloc/creddy --keyid --cert Coyote_ID.pem`

rule="$coyote.sneaky_friend<-$bigbird"

runTest "creddy_tests/attribute_rule.sh" "test1"  \
"$eloc/creddy --attribute \
       --issuer Coyote_ID.pem --key Coyote_private.pem \
       --attrrule "$rule" \
       --out Coyote_sneakyFriend__Bigbird_attr.xml"  \
0  "trying making attribute using attrrule option"

runTest "creddy_tests/attribute_rule.sh" "test2"  \
"$eloc/creddy --roles --cert Coyote_sneakyFriend__Bigbird_attr.xml"  \
0  "double check on the attribute made with atttrrule option"

