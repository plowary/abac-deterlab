#!/usr/bin/env python
"""
id4.py
"""
import os
import ABAC

id = ABAC.ID("newGuy", 5*365*3600*24)
oid = ABAC.ID("oldGuy", 5*365*3600*24)

oid.write_cert_file("./oldGuy.pem")

id.write_cert_file("./newGuy.pem")
id.write_privkey_file("./newGuy.pem")

id1 = ABAC.ID("./newGuy.pem")
id1.load_privkey("./newGuy.pem")

id2 = ABAC.ID("./newGuy.pem")

try:
    f = open("./newGuy.pem")
    id3 = ABAC.ID_chunk(f.read())
    f.close()
except:
    pass

try:
    f = open("./newGuy.pem")
    id4 = ABAC.ID_chunk(f.read())
    f.seek(0,0) 
    id4.load_privkey_chunk(f.read())
    f.close()
except:
    pass

id5 = ABAC.ID("./oldGuy.pem")

## can not test out this,
#id6 = ABAC.ID("./oldGuy.pem")
#id6.load_privkey("./newGuy.pem")
#id7 = ABAC.ID("./oldGuy.pem")
#id7.load_privkey("./oldGuy.pem")

print "id has privkey %d" % id.has_privkey()
print "id1 has privkey %d" % id1.has_privkey()
print "id2 has privkey %d" % id2.has_privkey()
print "id3 has privkey %d" % id3.has_privkey()
print "id4 has privkey %d" % id4.has_privkey()

print "id5 has privkey %d" % id5.has_privkey()
#print "id6 has privkey %d" % id6.has_privkey()
#print "id7 has privkey %d" % id7.has_privkey()
