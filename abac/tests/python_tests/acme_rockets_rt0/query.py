#!/usr/bin/env python

"""
Run the queries described in README

cmd: env keystore=`pwd` ./query.py

"""

import os
import ABAC

from test_util import runTest

ctxt = ABAC.Context()

# Keystore is the directory containing the principal credentials.
# Load existing principals and/or policy credentials
if (os.environ.has_key("keystore")) :
    keystore=os.environ["keystore"]
    ctxt.load_directory(keystore)
else:
    print("keystore is not set, using current directory...")
    ctxt.load_directory(".")

# retrieve principals' keyid value from local credential files
acmeID=ABAC.ID("Acme_ID.pem");
acmeID.load_privkey("Acme_private.pem");
acme=acmeID.keyid()

coyoteID=ABAC.ID("Coyote_ID.pem");
coyoteID.load_privkey("Coyote_private.pem");
coyote=coyoteID.keyid()

bigbirdID=ABAC.ID("Bigbird_ID.pem");
bigbirdID.load_privkey("Bigbird_private.pem");
bigbird=bigbirdID.keyid()

##########################################################################
# dump the loaded attribute policies
#
print "\n...policy attribute set..."
credentials = ctxt.credentials()
for credential in credentials:
    print "context: %s <- %s" % (credential.head().string(), credential.tail().string())

##########################################################################
# is coyote a preferred_customer of Acme ?
# role=[keyid:Acme].role:preferred_customer
# p =[keyid:coyote]
print "===good============ Acme.preferred_customer <- Coyote"
runTest("python_tests/acme_rockets_rt0","test1",ctxt,"%s.preferred_customer" % acme, coyote, 1, "simple single rule matchup")

##########################################################################
# can coyote buy rockets from Acme ?
# role=[keyid:Acme].role:buy_rockets
# p =[keyid:coyote]
print "===good============ Acme.buy_rockets <- Coyote"
runTest("python_tests/acme_rockets_rt0","test2",ctxt,"%s.buy_rockets" % acme, coyote, 1, "very simplequery")

##########################################################################
# is Acme a friend of coyote ?
# role=[keyid:Coyote].role:friend
# p=[keyid:Acme] 
print "===bad=============== Coyote.friend <- Acme"
runTest("python_tests/acme_rockets_rt0","test3",ctxt,"%s.friend" % coyote, acme, 0, "none existing relation")

##########################################################################
# using complex role to ask a question.. expecting to fail 
# role=[keyid:Acme].role:buy_rockets 
# p=[keyid:Acme].role:preferred_customer
print "===bad?=============== Acme.buy_rockets <- Acme.preferred_customer"
runTest("python_tests/acme_rockets_rt0","test4",ctxt,"%s.buy_rockets" % acme, "%s.preferred_customer" % acme, 1, "complex role query should fail")

