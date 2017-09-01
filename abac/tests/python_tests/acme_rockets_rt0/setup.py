#!/usr/bin/env python

"""
See README for the semantics. 
sets up 2 (Acme, Coyote) principal ID credentials
"""
import os
import ABAC

acme=ABAC.ID("Acme", 0)
acme.write_cert_file("Acme_ID.pem")
acme.write_privkey_file("Acme_private.pem")

coyote=ABAC.ID("Coyote", 0)
coyote.write_cert_file("Coyote_ID.pem")
coyote.write_privkey_file("Coyote_private.pem")

bigbird=ABAC.ID("Bigbird", 0)
bigbird.write_cert_file("Bigbird_ID.pem")
bigbird.write_privkey_file("Bigbird_private.pem")

