#!/usr/bin/env python

"""
See README for the semantics.  This creates principals
using ID and write out the credential file pair, cert/privkey
"""
import os
import ABAC

jackID=ABAC.ID("Jack", 0)
jackID.write_cert_file("Jack_ID.pem")
jackID.write_privkey_file("Jack_private.pem")

bobID=ABAC.ID("Bob", 0)
bobID.write_cert_file("Bob_ID.pem")
bobID.write_privkey_file("Bob_private.pem")

markID=ABAC.ID("Mark2", 0)
markID.write_privkey_file("Mark2_IDKEY.pem")
markID.write_cert_file("Mark2_IDKEY.pem")

johnID=ABAC.ID("John2", 0)
johnID.write_cert_file("John2_other.pem")

tomID=ABAC.ID("Tom2", 0)
tomID.write_privkey_file("Tom2_IDKEY.pem")

loriID=ABAC.ID("Lori2", 0)
loriID.write_cert_file("Lori2_IDKEY.pem")


