#!/usr/bin/env python
"""
ctxtQuery3.py
  
shows auto loading of self-contained attribute 

  externally,
      make a,
      make b,
      make c,
      make a.yes <- c
      make b.no <- c

  load a
  load a.yes <-c
  load b.no <- c

  query b.no <-?-c
  query a.yes <-?-c

  todo, dump principals
"""
import os

import ABAC
ctxt = ABAC.Context()

aID=ABAC.ID("A_ID.pem");
a=aID.keyid()
bID=ABAC.ID("B_ID.pem");
b=bID.keyid()
cID=ABAC.ID("C_ID.pem");
c=cID.keyid()

ctxt.load_id_chunk(aID.cert_chunk())
ctxt.load_attribute_file("A_yes__C_attr.xml")
ctxt.load_attribute_file("B_no__C_attr.xml")

# Same code as above to initialize the ids and load the context

ok, proof = ctxt.query(a + ".yes", c)
print "regular, ok? %d" %ok

ok, proof = ctxt.query(b + ".no", c)
print "self contain, ok? %d" %ok

## should also dump the context principal to make sure b is not in the
## context
