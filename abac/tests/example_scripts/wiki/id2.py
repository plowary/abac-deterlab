#!/usr/bin/env python
"""
id2.py
"""

import os
import ABAC

id1=ABAC.ID("./newGuy.pem")

try:
    f = open("./newGuy.pem")
    id2 = ABAC.ID_chunk(f.read())
    f.close()
except:
    pass

print "%s %s" % (id1.keyid(), id2.keyid())

