#!/usr/bin/python

import getopt
import sys
from ABAC import *
import pprint

def usage():
    print "Usage: abac_prover.py \\"
    print "        --keystore <keystore> \\"
    print "        --role <role> --principal"
    print "    loads the keystore and runs the query role <-?- principal"
    sys.exit(1)

pp = pprint.PrettyPrinter(indent=4)

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

ctx = Context()
ctx.load_directory(keystore)

(success, credentials) = ctx.query(role, principal)

if success:
    print "success"
else:
    print "fail, here's a partial proof"

for credential in credentials:
    print "credential %s <- %s" % (credential.head().string(), credential.tail().string())
    # pp.pprint(credential)
