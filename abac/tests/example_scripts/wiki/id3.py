#!/usr/bin/env python
"""
id3.py
"""

import os
import ABAC

id = ABAC.ID("newGuy", 5*365*3600*24)

id.write_cert_file("./newGuy.pem")

id1 = ABAC.ID("./newGuy.pem")

try:
    f = open("./newGuy.pem")
    id2 = ABAC.ID_chunk(f.read())
    f.close()
except:
    pass

print "%s %s %s" % (id.keyid(), id1.keyid(), id2.keyid())
