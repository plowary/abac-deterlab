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
ctxt.load_id_chunk(acmeID.cert_chunk())
acme=acmeID.keyid()

bobID=ABAC.ID("Bob_ID.pem");
bobID.load_privkey("Bob_private.pem");
ctxt.load_id_chunk(bobID.cert_chunk())
bob=bobID.keyid()

aliceID=ABAC.ID("Alice_ID.pem");
aliceID.load_privkey("Alice_private.pem");
ctxt.load_id_chunk(aliceID.cert_chunk())
alice=aliceID.keyid()

globotronID=ABAC.ID("Globotron_ID.pem");
globotronID.load_privkey("Globotron_private.pem");
ctxt.load_id_chunk(globotronID.cert_chunk())
globotron=globotronID.keyid()

##########################################################################
# dump the loaded attribute policies
#
print "\n...policy attribute set..."
credentials = ctxt.credentials()
for credential in credentials:
    print "context: %s <- %s" % (credential.head().string(), credential.tail().string())

##########################################################################
# is alice a admin at Globotron ?
# role=[keyid:Globotron].role:admin 
# p=[keyid:Alice]
print "===good=============== Globotron.admin <- Alice"
runTest("python_tests/experiment_create_rt0","test1",ctxt,"%s.admin" % globotron, alice, 1, "query in python")

##########################################################################
# is bob a admin at Globotron ?
# role=[keyid:Globotron].role:admin 
# p=[keyid:Bob]
print "===bad=============== Globotron.admin <- Bob"
runTest("python_tests/experiment_create_rt0","test2",ctxt,"%s.admin" % globotron, bob, 0, "no linking relation")

##########################################################################
# can bob create experiment at Acme ?
# role=[keyid:Acme].role:experiment_create 
# p=[keyid:Bob]
print "===good=============== Acme.experiment_create <- Bob"
runTest("python_tests/experiment_create_rt0","test3",ctxt,"%s.experiment_create" % acme, bob, 1, "query python with inference")

