#!/usr/bin/env python
"""
ctxtQuery2.py
"""
import os
import sys
import ABAC

ctxt = ABAC.Context()

a = ABAC.ID("A", 24 * 3600 * 365 * 20)
b = ABAC.ID("B", 24 * 3600 * 365 * 20)
c = ABAC.ID("C", 24 * 3600 * 365 * 20)

attr = ABAC.Attribute(a, "friendly_admin", 24 * 3600 * 365 * 20)
attr.role(a.keyid(), "friendly")
attr.role(a.keyid(), "admin")
attr.bake()

ctxt.load_id_chunk(a.cert_chunk())
ctxt.load_attribute_chunk(attr.cert_chunk())

attr = ABAC.Attribute(a, "friendly", 24 * 3600 * 365 * 20)
attr.principal(b.keyid()) 
attr.bake()
ctxt.load_attribute_chunk(attr.cert_chunk())


attr = ABAC.Attribute(a, "admin", 24 * 3600 * 365 * 20)
attr.principal(b.keyid())
attr.bake()
ctxt.load_attribute_chunk(attr.cert_chunk())

attr = ABAC.Attribute(a, "admin", 24 * 3600 * 365 * 20)
attr.principal(c.keyid())
attr.bake()
ctxt.load_attribute_chunk(attr.cert_chunk())

ok, proof = ctxt.query(a.keyid() + ".friendly_admin", b.keyid())

if not ok:
    sys.exit(1)

for i, c in enumerate(proof):
    print "%s <- %s" % (c.head().string(), c.tail().string())
    open("./id%d.pem" % i, "w").write(c.issuer_cert())
    open("./attr%d.xml" % i, "w").write(c.attribute_cert())

print "ok? %d" %ok


