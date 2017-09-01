#!/usr/bin/env python

"""
  abac_keyid.py

   To demonstrate how to use ABAC's api in python to access keyid of a 
principal credential

   pre-condition: generate IceCream_ID.pem and IceCream_private.pem with
           creddy --generate --cn IceCream

   keyid of the loaded principal credential is printed

"""

from sys import argv, exit
from ABAC import ID

if len(argv) < 2:
    print "Usage: abac_keyid.py <cert.pem>"
    exit(1)

id = None
try:
    print argv[1]
    id = ID(argv[1])
except Exception, e:
    print "Problem loading cert: %s" % e
    exit(1)

print id.keyid()
print "okay"

