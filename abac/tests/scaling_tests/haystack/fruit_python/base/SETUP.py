#!/usr/bin/env python

"""
See README for the semantics.  This creates principals
used by the example.
"""
import os
import ABAC

ctxt = ABAC.Context()

ralphsID=ABAC.ID("Ralphs", 0)
ralphsID.id_write_cert("Ralphs_ID.pem")
ralphsID.id_write_privkey("Ralphs_private.pem")

bobID=ABAC.ID("Bob", 0)
bobID.id_write_cert("Bob_ID.pem")
bobID.id_write_privkey("Bob_private.pem")

maryID=ABAC.ID("Mary", 0)
maryID.id_write_cert("Mary_ID.pem")
maryID.id_write_privkey("Mary_private.pem")

######## NOISE ##################################

i=1
while i <= #VAL#:
     n="john%s"%i 
     nid="%s_ID.pem"%n
     np="%s_private.pem"%n
     aD=ABAC.ID(n, 0)
     aD.id_write_cert(nid)
     aD.id_write_privkey(np)
     i = i+1



