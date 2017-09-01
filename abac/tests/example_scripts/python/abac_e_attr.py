#!/usr/bin/env python

"""
   abac_e_attr.py

   To demonstrate how to use ABAC's api in python with principal credential that uses
   encrypted private key

   call:   attr_e_abac Soda_ID.pem Soda_private.pem Soda_attr.der pfile Cream_ID.pem

   pre-conditions: make a passpphrase file and
                   generate a Soda_private.pem with passphrase with openssl
                   generate Soda_ID.pem with creddy with supplied private key
                   generate Cream_ID.pem and clear Cream_private.pem with
                          creddy --generate --cn Cream

   This program will generate an attribute rule, write it out to an external
           file and also load it into the context 
           Soda.delicious <- Cream

   Then, a query is made against the context to see if it is populated correctly.

   Note: Cream's principal is loaded without it private key. It does not
         need to because it is not being used to generate attribute credential

"""




from sys import argv, exit
from ABAC import Context
from ABAC import ID, Attribute, Role

debug=0

## initial context
ctxt = Context()

if len(argv) != 6:
    print "Usage: abac_attr.py <cert.pem> <key.pem> <attr.xml> <pfile> <c_cert.pem>"
    exit(1)

# load the ID and its key
id = None
try:
    id = ID(argv[1])
    id.load_privkey(argv[2])
    cream_id = ID(argv[5])
except Exception, e:
    print "Problem loading ID cert: %s" % e
    exit(1)

# load the id into the context
ctxt.load_id_chunk(id.cert_chunk())
# another way to load the id into the context
# ctxt.load_id(cream_id), not implemented
ctxt.load_id_chunk(cream_id.cert_chunk())

# create an attribute cert
attr = Attribute(id, "delicious", 1000)
attr.principal(cream_id.keyid())
attr.bake()

# load attribute cert into the context
ctxt.load_attribute_chunk(attr.cert_chunk())

# another way to load the attribute cert into the context,
# ctxt.load_attribute(attr)

# yet another way to load the attribute cert into the context,
attr.write_file(argv[3])
# ctxt.load_attribute_file(argv[3])

print '---------'
(credentials) = ctxt.credentials()
for credential in credentials:
    print "credential %s <- %s" % (credential.head().string(), credential.tail().string())
print '---------'


(success, credentials) = ctxt.query("%s.delicious" % id.keyid(), cream_id.keyid())
if success:
    print "success!"
for credential in credentials:
    print "credential %s <- %s" % (credential.head().string(), credential.tail().string())

