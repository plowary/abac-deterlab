#!/usr/bin/env python
"""
attr1.py
"""
import os
import ABAC

a = ABAC.ID("A", 24 * 3600 * 365 * 20)
b = ABAC.ID("B", 24 * 3600 * 365 * 20)

attr = ABAC.Attribute(a, "admin", 24 * 3600 * 365 * 20)
attr.principal(b.keyid())
attr.bake()

attr.write_file("attr.xml")

