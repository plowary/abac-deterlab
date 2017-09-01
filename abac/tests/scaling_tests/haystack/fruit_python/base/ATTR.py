#!/usr/bin/env python

"""
See README in this directory for the semantics of the example.  This file
constructs the credentials described and puts copies into this directory

cmd1:env keystore=`pwd` ./attr.py 
"""

import os
import ABAC

ctxt = ABAC.Context()
print "ABAC version %s" % ctxt.version()

# Keystore is the directory containing the principal credentials.
# Load existing principals and/or policy credentials
if (os.environ.has_key("keystore")) :
    keystore=os.environ["keystore"]
    ctxt.load_directory(keystore)
else:
    print("keystore is not set...")
    exit(1)

# retrieve principals' keyid value from local credential files
ralphsID=ABAC.ID("Ralphs_ID.pem");
ralphsID.id_load_privkey_file("Ralphs_private.pem");
ralphs=ralphsID.id_keyid()

bobID=ABAC.ID("Bob_ID.pem");
bobID.id_load_privkey_file("Bob_private.pem");
bob=bobID.id_keyid()

maryID=ABAC.ID("Mary_ID.pem");
maryID.id_load_privkey_file("Mary_private.pem");
mary=maryID.id_keyid()

################################################
# Credential 1, what kind of fruit Mary would eat. Anything not costing more
#               than 2 dollars
# [keyid:mary].oset:what2eat
#      <- [keyid:ralphs].oset:fruitprice([float:?P:[..2.00]])
head = ABAC.Oset(mary,"what2eat")

# initialize a float range constraint
cond=ABAC.Constraint("float")

# add the upper max to the range, and only the max
cond.constraint_add_float_max(2.00)

# create the data term with the constraint
param=ABAC.DataTerm("float", "P", cond)
tail = ABAC.Oset(ralphs,"fruitprice")
tail.oset_add_data_term(param)

# compose the attribute policy
attr=ABAC.Attribute(head, 1800)
attr.attribute_add_tail(tail)

#finalize the policy
attr.attribute_bake()

#write out the policy to a credential file
attr.attribute_write_cert("mary_what2eat__ralphs_fruitprice_qP_attr.der")


################################################
# Credential 2,
# [keyid:bob].oset:what2eat
#      <- [keyid:ralphs].oset:fruitprice([float:?P:[1.00..5.00]])
head = ABAC.Oset(bob,"what2eat")

# initialze a float range constraint
cond=ABAC.Constraint("float")

# add the min and max value to the range
cond.constraint_add_float_min(1.00)
cond.constraint_add_float_max(5.00)
param=ABAC.DataTerm("float", "P", cond)
tail = ABAC.Oset(ralphs,"fruitprice")
tail.oset_add_data_term(param)

#create attribute policy
attr=ABAC.Attribute(head, 1800)
attr.attribute_add_tail(tail)

#finalize the policy
attr.attribute_bake()
attr.attribute_write_cert("bob_what2eat__ralphs_fruitprice_qP_attr.der")

#################################################
# Credential 3
# [keyid:ralphs].oset:fruitprice([float:1.50]) <- [string:'apple']
param=ABAC.DataTerm("float", "1.50")
head = ABAC.Oset(ralphs,"fruitprice")
head.oset_add_data_term(param)
param=ABAC.DataTerm("string", "'apple'")
tail = ABAC.Oset(param)
attr=ABAC.Attribute(head, 1800)
attr.attribute_add_tail(tail)
attr.attribute_bake()
attr.attribute_write_cert("Ralphs_fruitprice__apple_attr.der")

#################################################
# Credential 4
# [keyid:ralphs].oset:fruitprice([float:1.50]) <- [string:'kiwi']
param=ABAC.DataTerm("float", "1.50")
head = ABAC.Oset(ralphs,"fruitprice")
head.oset_add_data_term(param)
param=ABAC.DataTerm("string", "'kiwi'")
tail = ABAC.Oset(param)
attr=ABAC.Attribute(head, 1800)
attr.attribute_add_tail(tail)
attr.attribute_bake()
attr.attribute_write_cert("Ralphs_fruitprice__kiwi_attr.der")

#################################################
# Credential 5
# [keyid:ralphs].oset:fruitprice([float:2.50]) <- [string:'black berry']
param=ABAC.DataTerm("float", "2.50")
head = ABAC.Oset(ralphs,"fruitprice")
head.oset_add_data_term(param)
param=ABAC.DataTerm("string", "'black berry'")
tail = ABAC.Oset(param)
attr=ABAC.Attribute(head, 1800)
attr.attribute_add_tail(tail)
attr.attribute_bake()
attr.attribute_write_cert("Ralphs_fruitprice__blackberry_attr.der")

#################################################
# Credential 6
# [keyid:ralphs].oset:fruitprice([float:0.50]) <- [string:'navel orange']
param=ABAC.DataTerm("float", "0.50")
head = ABAC.Oset(ralphs,"fruitprice")
head.oset_add_data_term(param)
param=ABAC.DataTerm("string", "'navel orange'")
tail = ABAC.Oset(param)
attr=ABAC.Attribute(head, 1800)
attr.attribute_add_tail(tail)
attr.attribute_bake()
attr.attribute_write_cert("Ralphs_fruitprice__navelorange_attr.der")


########### NOISE #######################################
# [keyid:Ralphs].oset:fruitprice([float:X.00])  <- [string:bananaY]
i=1
while i <= #VAL#:
    p="%s.00"%i
    n="'banana%s'"%i
    nn="banana%s"%i
    f="Ralphs_fruitprice__%s_attr.der"%nn
    param=ABAC.DataTerm("float", p)
    head = ABAC.Oset(ralphs,"fruitprice")
    head.oset_add_data_term(param)
    param=ABAC.DataTerm("string", n)
    tail = ABAC.Oset(param)
    attr=ABAC.Attribute(head, 1800)
    attr.attribute_add_tail(tail)
    attr.attribute_bake()
    attr.attribute_write_cert(f)
    i=i+1

# [keyid:johnX].oset:what2eat
#        <- [keyid:ralphs].oset:fruitprice([float:?P:[1.00..5.00]])
i=1
while i <= #VAL#:
    j="john%s"%i
    jid="%s_ID.pem"%j
    jp="%s_private.pem"%j
    f="%s_what2eat__ralphs_fruitprice_qP_attr.der"%j

    jID=ABAC.ID(jid);
    jID.id_load_privkey_file(jp);
    john=jID.id_keyid()

    head = ABAC.Oset(john,"what2eat")
    cond=ABAC.Constraint("float")
    cond.constraint_add_float_min(1.00)
    cond.constraint_add_float_max(5.00)
    param=ABAC.DataTerm("float", "P", cond)
    tail = ABAC.Oset(ralphs,"fruitprice")
    tail.oset_add_data_term(param)

    attr=ABAC.Attribute(head, 1800)
    attr.attribute_add_tail(tail)
    attr.attribute_bake()
    attr.attribute_write_cert(f)
    i=i+1


