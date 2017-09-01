#!/usr/bin/env python

"""
  to test when an id gets loaded into the session
vs when it gets loaded into a context

cmd:env keystore=`pwd` ./id_ctxt.py 

-- can not run in rt0 yet
"""

import os
import ABAC

def pSZ(CTXT,msg):
   psz= CTXT.principal_count()
   csz= CTXT.credential_count()
   print "context [%s] %d principals, %d credentials" % (msg,psz,csz)

ctxtA = ABAC.Context()
ctxtB = ABAC.Context()

ABAC.dump_debug_info("first")
pSZ(ctxtA, "A")
pSZ(ctxtB, "B")

## creating and writing out using libabac ID
id=ABAC.ID("Ella", 0)
print "adding -> %s(good) to session" % id.id_name()
id.id_write_cert("Ella_ID.pem")
id.id_write_privkey("Ella_private.pem")

ABAC.dump_debug_info("second")
pSZ(ctxtA, "A")
pSZ(ctxtB, "B")

## load principal with id/key file pair
## note, with this, we do not have handle on the keyid
## to Ella but it will be in the db
print "loading -> %s to ctxtA" % id.id_name()
ctxtA.load_id_files("Ella_ID.pem","Ella_private.pem")

print "loading -> Bob to ctxtB"
ctxtB.load_id_files("Bob_ID.pem","Bob_private.pem")

ABAC.dump_debug_info("third")
pSZ(ctxtA, "A")
pSZ(ctxtB, "B")
