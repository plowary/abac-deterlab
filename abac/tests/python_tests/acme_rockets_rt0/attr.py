#!/usr/bin/env python

"""
See README in this directory for the semantics of the example.  This file
constructs the credentials described and puts copies into this directory

cmd: ./attr.py 
"""
import os
import ABAC

ctxt = ABAC.Context()

# retrieve principals' keyid value from local credential files
acmeID=ABAC.ID("Acme_ID.pem");
acmeID.load_privkey("Acme_private.pem");
ctxt.load_id_chunk(acmeID.cert_chunk())
acme=acmeID.keyid()

coyoteID=ABAC.ID("Coyote_ID.pem");
coyoteID.load_privkey("Coyote_private.pem");
ctxt.load_id_chunk(coyoteID.cert_chunk())
coyote=coyoteID.keyid()

bigbirdID=ABAC.ID("Bigbird_ID.pem");
bigbirdID.load_privkey("Bigbird_private.pem");
ctxt.load_id_chunk(bigbirdID.cert_chunk())
bigbird=bigbirdID.keyid()

################################################
# Credential 1, only preferred_customer of Acme can buy_rockets
#[keyid:Acme].role:buy_rockets <- [keyid:Acme].role:preferred_customer

# compose the attribute of a basic rt0 role rule
attr = ABAC.Attribute(acmeID, "buy_rockets", 0)
attr.role(acme,"preferred_customer")

# finalize the policy
attr.bake()

# create a policy file at the file system
attr.write_file("Acme_buy_rockets__Acme_preferred_customer_attr.xml")

# load the policy into current context by with the newly created policy file
ctxt.load_attribute_file("Acme_buy_rockets__Acme_preferred_customer_attr.xml")

#################################################
# Credential 2
#[keyid:Acme].role:preferred_customer <- [keyid:Coyote]
attr = ABAC.Attribute(acmeID, "preferred_customer", 0)
attr.principal(coyote)
attr.bake()

attr.write_file("Acme_preferred_customer__Coyote_attr.xml")
ctxt.load_attribute_file("Acme_preferred_customer__Coyote_attr.xml")

#################################################
# Credential 3
#[keyid:Coyote].role:friend <- [keyid:Bigbird]
attr = ABAC.Attribute(coyoteID, "friend", 0)
attr.principal(bigbird)
attr.bake()

attr.write_file("Coyote_friend__Bigbird_attr.xml")
ctxt.load_attribute_chunk(attr.cert_chunk())

#################################################
credentials = ctxt.credentials()
for credential in credentials:
    print "context: %s <- %s" % (credential.head().string(), credential.tail().string())
