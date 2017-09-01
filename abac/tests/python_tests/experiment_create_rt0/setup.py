#!/usr/bin/env python

"""
See README for the semantics.  This creates principals
used by the example.
"""
import os
import ABAC

acme=ABAC.ID("Acme", 0)
acme.write_cert_file("Acme_ID.pem")
acme.write_privkey_file("Acme_private.pem")

bobID=ABAC.ID("Bob", 0)
bobID.write_cert_file("Bob_ID.pem")
bobID.write_privkey_file("Bob_private.pem")

aliceID=ABAC.ID("Alice", 0)
aliceID.write_cert_file("Alice_ID.pem")
aliceID.write_privkey_file("Alice_private.pem")

globotronID=ABAC.ID("Globotron", 0)
globotronID.write_cert_file("Globotron_ID.pem")
globotronID.write_privkey_file("Globotron_private.pem")


