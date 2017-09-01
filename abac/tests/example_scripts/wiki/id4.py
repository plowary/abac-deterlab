#!/usr/bin/env python
"""
id4.py
"""
import os
import ABAC

id = ABAC.ID("newGuy", 5*365*3600*24)

id.write_cert_file("./newGuy.pem")
id.write_privkey_file("./newGuy_key.pem")

id1 = ABAC.ID("./newGuy.pem")
id1.load_privkey("./newGuy_key.pem")

try:
    f = open("./newGuy.pem")
    id2 = ABAC.ID_chunk(f.read())
    f.close()
except:
    pass

print "id has privkey %d" % id.has_privkey()
print "id1 has privkey %d" % id1.has_privkey()
print "id2 has privkey %d" % id2.has_privkey()
