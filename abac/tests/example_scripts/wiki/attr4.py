#!/usr/bin/env python
"""
attr4.py

generate an attribute with principal initialized
with nickname

"""
import os
import sys
import ABAC

ctx = ABAC.Context()

## this would replace
ctx.load_id_file('./issuer.pem')
i = ABAC.ID('./issuer.pem')
ctx.set_nickname(i.keyid(), "Ted")
a = ABAC.Attribute(i, 'ABAC_Guy', 20 * 365 * 24 * 3600)
a.principal(i.keyid())
a.bake(ctx)
a.write_file("Ted_attr.xml")
a.write(sys.stdout)


## this would not replace
ctx.load_id_file('./issuer2.pem')
i2 = ABAC.ID('./issuer2.pem')
ctx.set_nickname(i2.keyid(), "AnotherTed")
a2 = ABAC.Attribute(i2, 'ABAC_Guy', 20 * 365 * 24 * 3600)
a2.principal(i.keyid())
a2.bake()
a2.write_file("AnotherTed_attr.xml")
a2.write(sys.stdout)

## this would be mixed ?
ctx.set_nickname(i.keyid(), "OtherTed")
a3 = ABAC.Attribute(i, 'ABAC_Guy', 20 * 365 * 24 * 3600)
a3.principal(i2.keyid())
a3.bake(ctx)
a3.write_file("OtherTed_attr.xml")
a3.write(sys.stdout)


## this would replace with original common name..
ctx.load_id_file('./issuer3.pem')
i3 = ABAC.ID('./issuer3.pem')
a3 = ABAC.Attribute(i3, 'ABAC_Guy', 20 * 365 * 24 * 3600)
a3.principal(i3.keyid())
a3.bake(ctx)
a3.write_file("NotTed_attr.xml")
a3.write(sys.stdout)

