#!/usr/bin/env python
"""
id.py
"""
import os
import ABAC

id=ABAC.ID("newGuy",100)
id.write_cert_file("./newGuy.pem")

print id.keyid()
