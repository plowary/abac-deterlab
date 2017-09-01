#!/usr/bin/env sh

#Acme.buy_rockets <- Acme.preferred_customer
#Acme.preferred_customer <- Coyote

if [ -z "${TESTDIR}" ] ; then
    TESTDIR=..
fi
. ${TESTDIR}/test_util.sh

$eloc/creddy --generate --cn Acme 1>/dev/null 2>&1
$eloc/creddy --generate --cn Coyote 1>/dev/null 2>&1

$eloc/creddy --generate --cn Bigbird 1>/dev/null 2>& 1
$eloc/creddy --generate --cn Coyote 1>/dev/null 2>& 1

$eloc/creddy --attribute \
       --issuer Acme_ID.pem --key Acme_private.pem --role buy_rockets \
       --subject-cert Acme_ID.pem --subject-role preferred_customer \
       --out Acme_buy_rockets__Acme_preferred_customer_attr.xml

$eloc/creddy --attribute \
       --issuer Acme_ID.pem --key Acme_private.pem --role preferred_customer \
       --subject-cert Coyote_ID.pem \
       --out Acme_preferred_customer__Coyote_attr.xml

cp not_ss.pem_save not_ss.pem
cp not_ss.xml_save not_ss.xml
cp priv.xml_save priv.xml
cp PGissuer.pem_save PGissuer.pem
cp iProtoGENI.xml_save iProtoGENI.xml
## This will be valid for 3 years starting from 7/15/2013
cp vProtoGENI.xml_save ProtoGENI.xml

