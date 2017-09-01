#!/usr/bin/env python

"""
See README in this directory for the semantics of the example.  This file
constructs the credentials described and puts copies into this directory

cmd1: ./attr.py 
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

warnerbrosID=ABAC.ID("WarnerBros_ID.pem");
warnerbrosID.load_privkey("WarnerBros_private.pem");
ctxt.load_id_chunk(warnerbrosID.cert_chunk())
warnerbros=warnerbrosID.keyid()

batmanID=ABAC.ID("Batman_ID.pem");
batmanID.load_privkey("Batman_private.pem");
ctxt.load_id_chunk(batmanID.cert_chunk())
batman=batmanID.keyid()


################################################
# Credential 1, establish the intersection rule on who can buy
# rockets from Acme
#[keyid:Acme].role:buy_rockets <- [keyid:Acme].role:preferred_customer 
#                                    & [keyid:WarnerBros].role:charater
attr = ABAC.Attribute(acmeID, "buy_rockets", 0)

# to add intersection, just add multiple roles
attr.role(acme,"preferred_customer")
attr.role(warnerbros,"character")

# finalize the rule
attr.bake()

# create a policy file at the file system
attr.write_file("Acme_buy_rockets__Acme_preferred_customer_and_WarnerBros_character_attr.xml")

# load the policy into current context by with the newly created policy file
ctxt.load_attribute_file("Acme_buy_rockets__Acme_preferred_customer_and_WarnerBros_character_attr.xml")

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
#[keyid:Acme].role:preferred_customer <- [keyid:Batman]
attr = ABAC.Attribute(acmeID, "preferred_customer", 0)
attr.principal(batman)
attr.bake()

attr.write_file("Acme_preferred_customer__Batman_attr.xml")
ctxt.load_attribute_file("Acme_preferred_customer__Batman_attr.xml")

################################################
# Credential 4
#[keyid:WarnerBros].role:character <- [keyid:Coyote]
attr = ABAC.Attribute(warnerbrosID, "character", 0)
attr.principal(coyote)
attr.bake()

attr.write_file("WarnerBros_character__Coyote_attr.xml")
ctxt.load_attribute_file("WarnerBros_character__Coyote_attr.xml")

# demonstrate how attribute can be load from structure insted of a file
ctxt.load_attribute_chunk(attr.cert_chunk())

