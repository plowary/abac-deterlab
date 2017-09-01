#!/usr/bin/env python
"""
attr2.py
"""
import os
import ABAC

a = ABAC.ID("A", 24 * 3600 * 365 * 20)

attr = ABAC.Attribute(a, "friendly_admin", 24 * 3600 * 365 * 20)
attr.role(a.keyid(), "friendly")
attr.role(a.keyid(), "admin")
attr.bake()

attr.write_file("attr.xml")


