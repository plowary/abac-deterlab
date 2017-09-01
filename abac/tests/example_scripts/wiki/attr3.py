#!/usr/bin/env python
"""
attr3.py

  test different versions of attribute rule xml format

"""
import os
import ABAC

i = ABAC.ID("TestPrincipal", 10 * 356 * 24 * 3600)
a = ABAC.Attribute(i, "role", 3600)
# Here's the format change
a.set_output_format("GENIv1.0")
# Format change above
a.principal(i.keyid());
a.bake()
a.write_file("V1_attr.xml")

####
i2 = ABAC.ID("TestPrincipal", 10 * 356 * 24 * 3600)
a2 = ABAC.Attribute(i, "role", 3600)
# Here's the format change
a2.set_output_format("GENIv1.1")
# Format change above

a2.principal(i2.keyid());
a2.bake()
a2.write_file("V1_1_attr.xml")

####
i3 = ABAC.ID("TestPrincipal", 10 * 356 * 24 * 3600)
a3 = ABAC.Attribute(i, "role", 3600)
a3.principal(i3.keyid());
a3.bake()
a3.write_file("V1_1b_attr.xml")

print a.get_output_format()+a2.get_output_format()+a3.get_output_format()


