#!/usr/bin/env python
"""
attr4_setup.py
  
  generate an issuer principal
"""
import os
import ABAC

a = ABAC.ID("ZARO", 24 * 3600 * 365 * 20)
a.write_cert_file("issuer.pem")
a.write_privkey_file("issuer.pem")

b = ABAC.ID("FRIDAY", 24 * 3600 * 365 * 20)
b.write_cert_file("issuer2.pem")
b.write_privkey_file("issuer2.pem")

c = ABAC.ID("HORSE", 24 * 3600 * 365 * 20)
c.write_cert_file("issuer3.pem")
c.write_privkey_file("issuer3.pem")


