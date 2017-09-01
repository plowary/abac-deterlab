#!/usr/bin/env python
"""
ctxtQuery1.py
"""
import os

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

# Same code as above to initialize the ids and load the context

ok, proof = ctxt.query(a.keyid() + ".friendly_admin", b.keyid())

print "ok? %d" %ok
