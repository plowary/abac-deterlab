#!/usr/bin/env python

"""
Run the queries described in README

cmd:env keystore=`pwd` ./query.py 
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

warnerbrosID=ABAC.ID("WarnerBros_ID.pem");
warnerbrosID.load_privkey("WarnerBros_private.pem");
warnerbros=warnerbrosID.keyid()

batmanID=ABAC.ID("Batman_ID.pem");
batmanID.load_privkey("Batman_private.pem");
batman=batmanID.keyid()

##########################################################################
# dump the loaded principals/policies
#
print "\n...policy attribute set..."
credentials = ctxt.credentials()
for credential in credentials:
    print "context: %s <- %s" % (credential.head().string(), credential.tail().string())

##########################################################################
# can coyote buy rockets from Acme ?
# role = "[keyid:Acme].role:buy_rockets"
# p = "[keyid:coyote]" 
print "===good============ Acme.buy_rockets <- Coyote"
runTest("python_tests/acme_rockets_intersection_rt0","test1",ctxt,"%s.buy_rockets" % acme, coyote, 1, "query in python with intersect")

##########################################################################
# can batman buy rockets from Acme ?
# role = "[keyid:Acme].role:buy_rockets"
# p = "[keyid:batman]" 
print "===bad============ Acme.buy_rockets <- Batman"
runTest("python_tests/acme_rockets_intersection_rt0","test2",ctxt,"%s.buy_rockets" % acme, batman, 0, "expected failure, no such relation in db")


