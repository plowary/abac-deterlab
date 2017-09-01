#!/usr/bin/env python
"""
ctxtQuery4.py
  
shows use of mnemonic name for principals

"""
import os
import ABAC

ctx = ABAC.Context()

ctx.load_attribute_file('./abac_cred.xml')
ctx.load_attribute_file('./coyote.xml')

for c in ctx.credentials():
    print "Raw: %s -> %s" % (c.head().string(), c.tail().string())
    print "Short: %s -> %s" % (c.head().short_string(ctx), c.tail().short_string(ctx))

# Collect the identity keyids into ids
ids = []
for c in ctx.credentials():
    i = ABAC.ID_chunk(c.issuer_cert())
    if i.keyid() not in ids:
        ids.append(i.keyid())

# Change all the nicknames
for n, i in enumerate(ids):
    print ctx.set_nickname(i, "identity%d" % n)

# Print the credentials with the new nicknames
print ""
print "After modifications"
print ""
for c in ctx.credentials():
    print "Raw: %s -> %s" % (c.head().string(), c.tail().string())
    print "Short: %s -> %s" % (c.head().short_string(ctx), c.tail().short_string(ctx))

