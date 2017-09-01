#!/usr/bin/env python

"""
See README for the semantics.  This creates principals
used by the example.
"""
import os
import ABAC

ctxt = ABAC.Context()

i=0
while i <= #VAL#:
     n="John%s"%i 
     nid="%s_ID.pem"%n
     np="%s_private.pem"%n
     aD=ABAC.ID(n, 0)
     aD.write_cert_file(nid)
     aD.write_privkey_file(np)
     i = i+1



