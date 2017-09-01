#!/usr/bin/env python
"""
ctxtQuery4_setup.py
  
creating a abac attribute credential
   acme.experiment_create <- acme

"""
import os
import sys
import ABAC

ctx = ABAC.Context()

## note id did not get loaded into ctx and so keyid map is not generated
## hence no mnemonic table
acme = ABAC.ID("Acme", 24 * 3600 * 365 * 20)
attr = ABAC.Attribute(acme, "experiment_create", 24 * 3600 * 365 * 20)
attr.principal(acme.keyid())
attr.bake(ctx)
attr.write_file("abac_cred.xml")

coyote = ABAC.ID("Coyote", 24 * 3600 * 365 * 20)
ctx.load_id_chunk(coyote.cert_chunk())
attr2 = ABAC.Attribute(coyote, "lives_dangerously", 24 * 3600 * 365 * 20)
attr2.principal(acme.keyid())
attr2.bake(ctx)
attr2.write_file("coyote.xml")

bird = ABAC.ID("BigBird", 24 * 3600 * 365 * 20)
ctx.load_id_chunk(bird.cert_chunk())
attr3 = ABAC.Attribute(bird, "nice", 24 * 3600 * 365 * 20)
attr3.principal(acme.keyid())
attr3.bake(ctx)
attr3.write_file("bird.xml")

