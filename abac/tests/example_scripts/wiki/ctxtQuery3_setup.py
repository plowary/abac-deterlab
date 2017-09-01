#!/usr/bin/env python
"""
ctxtQuery3_setup.py
  
shows auto loading of self-contained attribute 

  externally,
      make a,
      make b,
      make c,
      make a.yes <- c
      make b.no <- c

"""
import os
import ABAC

a = ABAC.ID("A", 24 * 3600 * 365 * 20)
a.write_cert_file("A_ID.pem")
b = ABAC.ID("B", 24 * 3600 * 365 * 20)
b.write_cert_file("B_ID.pem")
c = ABAC.ID("C", 24 * 3600 * 365 * 20)
c.write_cert_file("C_ID.pem")

attr = ABAC.Attribute(a, "yes", 24 * 3600 * 365 * 20)
attr.principal(c.keyid())
attr.bake()
attr.write_file("A_yes__C_attr.xml")

attr2 = ABAC.Attribute(b, "no", 24 * 3600 * 365 * 20)
attr2.principal(c.keyid())
attr2.bake()
attr2.write_file("B_no__C_attr.xml")

