#!/usr/bin/env python

"""
See README for the semantics.  This creates principals
using ID and write out the credential file pair, cert/privkey
"""
import os
import ABAC

jackID=ABAC.ID("SuperK", 0)
jackID.write_cert_file("SuperK_ID.pem")
jackID.write_privkey_file("SuperK_private.pem")

jackID=ABAC.ID("Jack", 0)
jackID.write_cert_file("Jack_ID.pem")
jackID.write_privkey_file("Jack_private.pem")

bobID=ABAC.ID("Bob", 0)
bobID.write_cert_file("Bob_ID.pem")
bobID.write_privkey_file("Bob_private.pem")

maryID=ABAC.ID("Mary", 0)
maryID.write_cert_file("Mary_ID.pem")
maryID.write_privkey_file("Mary_private.pem")

