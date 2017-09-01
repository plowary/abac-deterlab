#!/usr/bin/env python

"""
  to test with python

cmd1:env keystore=`pwd` ./query.py 

"""

import os
import ABAC

from test_util import runTest

ctxt = ABAC.Context()

def print_a(ctxt, msg, dotdot):
    print "%s rule set..." % msg
    credentials = ctxt.credentials()
    for credential in credentials:
        print "%s:%s<-%s" % (dotdot,credential.head().string(), credential.tail().string())

# Keystore is the directory containing the principal credentials.
# Load existing principals and/or policy credentials
if (os.environ.has_key("keystore")) :
    keystore=os.environ["keystore"]
else:
    print("keystore is not set, using current directory...")
    ctxt.load_directory(".")

superKID=ABAC.ID("SuperK_ID.pem");
superKID.load_privkey("SuperK_private.pem");
ctxt.load_id_chunk(superKID.cert_chunk())
superK=superKID.keyid()

jackID=ABAC.ID("Jack_ID.pem");
jackID.load_privkey("Jack_private.pem");
ctxt.load_id_chunk(jackID.cert_chunk())
jack=jackID.keyid()

bobID=ABAC.ID("Bob_ID.pem");
bobID.load_privkey("Bob_private.pem");
ctxt.load_id_chunk(bobID.cert_chunk())
bob=bobID.keyid()

maryID=ABAC.ID("Mary_ID.pem");
maryID.load_privkey("Mary_private.pem");
ctxt.load_id_chunk(maryID.cert_chunk())
mary=maryID.keyid()

#case 1:
#Only employee of SuperK can park
#[keyid:SuperK].role:park <- [keyid:SuperK].role:employee
attr = ABAC.Attribute(superKID, "park", 0)
attr.role(superK,"employee")
attr.bake()
attr.write_file("SuperK_park__SuperK_employee_attr.xml")
ctxt.load_attribute_file("SuperK_park__SuperK_employee_attr.xml")
print_a(ctxt,"case1","..")

#case 2:
#Jack is an employee of SuperK
#[keyid:SuperK].role:employee <- [keyid:Jack]
attr = ABAC.Attribute(superKID, "employee", 0)
attr.principal(jack)
attr.bake()
# create a policy file at the file system
attr.write_file("SuperK_employee__Jack_attr.xml")
ctxt.load_attribute_chunk(attr.cert_chunk());
print_a(ctxt,"case2","....")
##########################################################################
#Jack of SuperK can park?
print "===good============ SuperK.park <-?- Jack"
runTest("python_tests/basic_attribute","test1",ctxt,"%s.park" % superK, jack, 1, "check loading of attribute as cert chunk")

#case 3:
#Bob is an employee of SuperK
#[keyid:SuperK].role:employee <- [keyid:Bob]
attr = ABAC.Attribute(superKID, "employee", 0)
attr.principal(bob)
attr.bake()
#chunk=attr.cert_chunk()
#nattr=ABAC.Attribute_chunk(chunk)
#ctxt.load_attribute(nattr);
#print_a(ctxt,"case3", "....")

#case 4:
#Mary is an employee of SuperK
#[keyid:SuperK].role:employee <- [keyid:Mary]
attr = ABAC.Attribute(superKID, "employee", 0)
attr.principal(mary)
attr.bake()
chunk=attr.cert_chunk()
ctxt.load_attribute_chunk(chunk);
print_a(ctxt,"case4","......")
##########################################################################
#is Mary an employee of superK?
print "===good============ SuperK.employee <-?- Mary"
runTest("python_tests/basic_attribute","test2",ctxt,"%s.employee" % superK, mary, 1, "check loading of attribute as chunk")

