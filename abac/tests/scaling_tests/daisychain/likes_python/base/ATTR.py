#!/usr/bin/env python

"""
See README in this directory for the semantics of the example.  This file
constructs the credentials described and puts copies into this directory

cmd1:env keystore=`pwd` ./attr.py 
"""

import os
import ABAC

ctxt = ABAC.Context()

# Keystore is the directory containing the principal credentials.
# Load existing principals and/or policy credentials
if (os.environ.has_key("keystore")) :
    keystore=os.environ["keystore"]
    ctxt.load_directory(keystore)
else:
    print("keystore is not set...")
    exit(1)

################################################
# [keyid:john0].role:likes  <- [keyid:john0]
a="John0_ID.pem"
ap="John0_private.pem"
f="John0_likes__John0_attr.xml" 
   
aID=ABAC.ID(a);
aID.load_privkey(ap);
aid=aID.keyid()

attr = ABAC.Attribute(aID, "likes", 0)
attr.principal(aid)
attr.bake()
attr.write_file(f)

# [keyid:john1].role:likes  <- [keyid:john0].role:likes
i=1
while i <= #VAL#:
    n=i-1

    a="John%s_ID.pem"%i
    ap="John%s_private.pem"%i
    b="John%s_ID.pem"%n
    f="John%s_likes__John%s_likes_attr.xml" %(i,n)
   
    aID=ABAC.ID(a);
    aID.load_privkey(ap);
    aid=aID.keyid()
    bID=ABAC.ID(b);
    bid=bID.keyid()

    attr = ABAC.Attribute(aID,"likes", 0)
    attr.role(bid,"likes")
    attr.bake()
    attr.write_file(f)
    i=i+1

