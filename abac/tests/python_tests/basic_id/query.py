#!/usr/bin/env python

"""
  to test with python

cmd:env keystore=`pwd` ./query.py 

No real query (originally id.py)
"""

import os
import ABAC

ctxt = ABAC.Context()

# Keystore is the directory containing the principal credentials.
# Load existing principals and/or policy credentials
if (os.environ.has_key("keystore")) :
    keystore=os.environ["keystore"]
#    ctxt.load_directory(keystore)
else:
    print("keystore is not set, using current directory...")
    ctxt.load_directory(".")

## case 1
## creating and writing out using libabac ID
id=ABAC.ID("Mary", 0)
print "adding -> %s(Mary/good)" % id.keyid()
id.write_cert_file("Mary_ID.pem")
id.write_privkey_file("Mary_private.pem")
## load principal with id/key file pair
## note, with this, we do not have handle on the keyid
## to Mary but it will be in the db
#XXX# ctxt.load_id_files("Mary_ID.pem","Mary_private.pem")

## case 2
## creating principal using ID
id2=ABAC.ID("Jack2", 0)
print "adding -> %s(Jack2/good)" % id2.keyid()
## load principal directly with the ID, no external
## credential files were created
#XXX# ctxt.load_id(id2)

## case 3
## creating principal using ID
id3=ABAC.ID("Mark", 0)
print "adding -> %s(Mark/good)" % id3.keyid()
## write cert and key content to a combo file. One is appended
## after another
id3.write_privkey_file("Mark_IDKEY.pem")
id3.write_cert_file("Mark_IDKEY.pem")
## load principal in with the combo file with the tandem format
ctxt.load_id_file("Mark_IDKEY.pem")

## case 4
## creating principal using ID
id4=ABAC.ID("John", 0)
print "adding -> %s(John/good,invisible)" % id4.keyid()
id4.write_cert_file("John_other.pem")
## load id without the key file
ctxt.load_id_file("John_other.pem")

## case 5
## creating principal using ID
id5=ABAC.ID("Lori", 0)
print "adding -> %s(Lori/good,nokey)" % id5.keyid()
## write just cert into the combo file
id5.write_cert_file("Lori_IDKEY.pem")
##load principal from a combo file that only contains cert part
ctxt.load_id_file("Lori2_IDKEY.pem")

## case 6
## creating principal using ID
id6=ABAC.ID("Tom", 0)
print "adding -> %s(Tom/bad,nocert)" % id6.keyid()
## write just key into the combo file
id6.write_privkey_file("Tom_IDKEY.pem")
## load principal from combo file that only contains key part
ctxt.load_id_file("Tom_IDKEY.pem")

## case 7
## creating ID using chunk
## this already created a Tim with private key and
## stored in the master list
id7=ABAC.ID("Tim", 0)
chunk=id7.cert_chunk() 
id77=ABAC.ID_chunk(chunk)
## load principal from new id
ctxt.load_id_chunk(id77.cert_chunk())

## case 8
## load directly using chunk
## this already created a Stanley with private key
## and stored in the master list
id8=ABAC.ID("Stanley", 0)
chunk=id8.cert_chunk() 
## load principal as chunk
ctxt.load_id_chunk(chunk)

## case 9
## failure case, loading a non-existing combo file
print "adding -> Casper(bad,unknown file)"
ctxt.load_id_file("Casper_IDKEY.pem")

