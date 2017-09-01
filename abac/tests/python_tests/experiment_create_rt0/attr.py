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

################################################
# Credential 1, Anyone who is allowed to create experiment by Acme's
#               partners can create experiment at Acme
# [keyid:Acme].role:experiment_create 
#           <- [keyid:Acme].role:partner.role:experiment_create

# compose the policy attribute
attr = ABAC.Attribute(acmeID, "experiment_create", 0)
# creating a linking role
tail = attr.linking_role(acme,"partner","experiment_create")
# finalize the policy
attr.bake()

# write out the policy to an external file
attr.write_file("Acme_experiment_create__Acme_partner_experiment_create_attr.xml")
# load the policy into the context by accessing that external file
ctxt.load_attribute_file("Acme_experiment_create__Acme_partner_experiment_create_attr.xml")

#################################################
# Credential 2
# [keyid:Acme].role:partner <- [keyid:Globotron]
#
attr = ABAC.Attribute(acmeID, "partner", 0)
attr.principal(globotron)
attr.bake()
attr.write_file("Acme_partner__Globotron_attr.xml")
ctxt.load_attribute_file("Acme_partner__Globotron_attr.xml")

#################################################
# Credential 3
# [keyid:Globotron].role:expriment_create 
#           <- [keyid:Globotron].role:admin.role:power_user
attr = ABAC.Attribute(globotronID, "experiment_create", 0)
attr.linking_role(globotron,"admin","power_user")
attr.bake()
attr.write_file("Globotron_experiment_create__Globotron_admin_power_user_attr.xml")
ctxt.load_attribute_file("Globotron_experiment_create__Globotron_admin_power_user_attr.xml")

#################################################
# Credential 4,
# [keyid:Globotron].role:admin <- [keyid:Alice]
attr = ABAC.Attribute(globotronID, "admin", 0)
attr.principal(alice)
attr.bake()
attr.write_file("Globotron_admin__Alice_attr.xml")
ctxt.load_attribute_file("Globotron_admin__Alice_attr.xml")

#################################################
# Credential 5, 
# [keyid:Alice].role:power_user <- [keyid:Bob]
attr = ABAC.Attribute(aliceID, "power_user", 0)
attr.principal(bob)
attr.bake()
attr.write_file("Alice_power_user__Bob_attr.xml")
ctxt.load_attribute_file("Alice_power_user__Bob_attr.xml")

