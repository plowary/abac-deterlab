#!/usr/bin/env python

"""
   abac_prover.py
    
   To demonstrate how to use ABAC's api in python to make a query

   call:   abac_prover "keystorestring" "rolestring" "principalstring"

   pre-condition: run make attr_abac  generate IceCream_ID.pem and IceCream_private.pem with

   This program will make a prover call using
           rolestring <- principalstring

"""

import getopt
import sys
from ABAC import Context


def usage():
    print "Usage: abac_prover.py \\"
    print "        --keystore <keystore> \\"
    print "        --role <role> --principal <principal> "
    print "    loads the keystore and runs the query role <-?- principal"
    sys.exit(1)

keystore = ''
role = ''
principal = ''

try:
    opts, args = getopt.getopt(sys.argv[1:], '', ['keystore=', 'role=', 'principal='])
except getopt.GetoptError, err:
    print str(err)
    sys.exit(1)

for o, a in opts:
    if o == '--keystore':
        keystore = a
    elif o == '--role':
        role = a
    elif o == '--principal':
        principal = a
    else:
        assert False, "WAT"

if keystore == '' or role == '' or principal == '':
    usage()

# code begins here! sorry about that

print keystore
print role
print principal

ctx = Context()
ctx.load_directory(keystore)

(success, credentials) = ctx.query(role, principal)

if success:
    print "success"

for credential in credentials:
    print "credential %s <- %s" % (credential.head().string(), credential.tail().string())

