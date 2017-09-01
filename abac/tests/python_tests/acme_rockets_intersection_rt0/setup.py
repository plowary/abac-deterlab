#!/usr/bin/env python

"""
See README for the semantics.  This creates four principals used
by the example.

"""
import os
import ABAC

ctxt = ABAC.Context()

acme=ABAC.ID("Acme", 0)
acme.write_cert_file("Acme_ID.pem")
acme.write_privkey_file("Acme_private.pem")

coyote=ABAC.ID("Coyote", 0)
coyote.write_cert_file("Coyote_ID.pem")
coyote.write_privkey_file("Coyote_private.pem")

warnerbros=ABAC.ID("WarnerBros", 0)
warnerbros.write_cert_file("WarnerBros_ID.pem")
warnerbros.write_privkey_file("WarnerBros_private.pem")

batman=ABAC.ID("Batman", 0)
batman.write_cert_file("Batman_ID.pem")
batman.write_privkey_file("Batman_private.pem")

