#!/usr/bin/env python

"""
     abac_attr.py

     To demonstrate how to use ABAC's api in python 
  
     call:   attr_abac IceCream_ID.pem IceCream_private.pem IceCream_attr.xml Chocolate_ID.pem
  
     pre-conditions: generate IceCream_ID.pem and IceCream_private.pem with
             creddy --generate --cn IceCream
                     generate Chocolate_ID.pem and Chocolate_private.pem with
             creddy --generate --cn Chocolate
  
     This program will generate an attribute rule, write it out to an external
             file and also load it into the context (prolog db)
             IceCream.delicious <- Chocolate
  
     Then, a query is made against the context to see if it is populated correctly.
  
     Note: Chocolate's principal is loaded without it private key. It does not
           need to because it is not being used to generate attribute credential
  
"""

from sys import argv, exit
from ABAC import Context
from ABAC import ID, Attribute, Role

debug=0

## initial context
ctxt = Context()

print len(argv)

if len(argv) != 5:
    print "Usage: abac_attr.py <cert.pem> <key.pem> <attr.xml> <pcert.pem>"
    exit(1)

# load the ID and its key
id = None
cid = None

try:
    id = ID(argv[1])
    id.load_privkey(argv[2])
    cid = ID(argv[4])
except Exception, e:
    print "Problem loading ID cert: %s" % e
    exit(1)

# load the id into the context
ctxt.load_id_chunk(id.cert_chunk())
# another way to load the id into the context
#XXX  not implemented yet...ctxt.load_id(cid)
ctxt.load_id_chunk(cid.cert_chunk())

#out = ctxt.credentials()
#print "\n...final principal set..."
#for x in out[1]:
#    print "%s " % x.string()

# create an attribute cert
# iceCream.delicous <- chocolate
attr = Attribute(id, "delicious", 0)
attr.principal(cid.keyid())
attr.bake()

# load attribute cert into the context
ctxt.load_attribute_chunk(attr.cert_chunk())

# another way to load the attribute cert into the context,
# not implemented, ctxt.load_attribute(attr)

# yet another way to load the attribute cert into the context,
attr.write_file(argv[3])
# ctxt.load_attribute_file(argv[3])

# run a proof
(success, credentials) = ctxt.query("%s.delicious" % id.keyid(), cid.keyid())

if success:
    print "success!"

for credential in credentials:
    print "credential %s <- %s" % (credential.head().string(), credential.tail().string())


