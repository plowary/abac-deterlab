#!/usr/bin/env python

"""
Run the queries described in README

cmd: env ABAC_CN=1 keystore=`pwd` ./query.py

number of credentials,
     3 + 6 + 3 x #VAL#

"""

import os
import sys
import ABAC
import time
import datetime
import math

debug=0

ctxt = ABAC.Context()
ctxt.set_no_partial_proof()

cred_count = 3 + 6 + 3 * #VAL#

def get_msec(e_time) :
    msec_delta=0
    if( int(e_time.seconds) !=0 ) :
        msec_delta= int(e_time.seconds) *1000
    if( int(e_time.microseconds) !=0) :
        msec_delta = msec_delta + int(e_time.microseconds)/1000
    return msec_delta

def get_micro(e_time) :
    micro_delta=0
    if( int(e_time.seconds) !=0 ) :
        micro_delta= int(e_time.seconds) *1000000
    if( int(e_time.microseconds) !=0) :
        micro_delta = micro_delta + int(e_time.microseconds)
    return micro_delta

def extract_delta(starttime, endtime) :
    """ given a start time, and a endtime, extract delta """
    elapsed_time = (endtime - starttime)
# Only handle in seconds/microseconds
    if ( int(elapsed_time.days) != 0 ) :
        sys.stderr.write("%s is longer than a day !!!" % msg)
        exit(1)
    return elapsed_time

# Keystore is the directory containing the principal credentials.
# Load existing principals and/or policy credentials
if (os.environ.has_key("keystore")) :
    keystore=os.environ["keystore"]
    starttime = datetime.datetime.now()
    ctxt.load_directory(keystore)
    endtime = datetime.datetime.now()
    elapsed_load=extract_delta(starttime, endtime)
    elapsed_msec=get_msec(elapsed_load)
    sys.stderr.write("%d %d LOAD(msec)\n" % (cred_count,elapsed_msec))
else:
    print("keystore is not set...")
    exit(1)

# retrieve principals' keyid value from local credential files
ralphsID=ABAC.ID("Ralphs_ID.pem");
ralphs=ralphsID.id_keyid()

bobID=ABAC.ID("Bob_ID.pem");
bob=bobID.id_keyid()

maryID=ABAC.ID("Mary_ID.pem");
mary=maryID.id_keyid()

##########################################################################
# dump the loaded principals/policies
#

fd=os.open("creds_dump",os.O_WRONLY|os.O_CREAT)
out = ctxt.context_principals()
for x in out[1]:
    os.write(fd, x.string())
    os.write(fd,"\n")
out = ctxt.context_credentials()
for c in out[1]:
    string="%s <- %s\n" % (c.head_string(), c.tail_string())
    os.write(fd,string) 
os.close(fd)

##########################################################################
# Would Mary eat navel orange ?
# oset = [keyid:mary].oset:what2eat 
# p [string:'navel orange'] 
def maryQuery(pr) :
    oset = ABAC.Oset(mary,"what2eat")
    term=ABAC.DataTerm("string", "'navel orange'")
    p = ABAC.Oset(term)

    if(pr) :
        print "\n===good============ mary.what2eat <- navel orange"
    starttime = datetime.datetime.now()
    out = ctxt.query(oset, p)
    endtime = datetime.datetime.now()
    if(pr) :
        for c in out[1]:
            print "%s <- %s" % (c.head_string(), c.tail_string())
    return extract_delta(starttime, endtime)

# skip the first one
e_time=maryQuery(1)
elapsed_micro=get_micro(e_time)
sys.stderr.write("%d %d GOOD_f(micro)\n" % (cred_count,elapsed_micro))

k=100
tlist=[]
while(k):
    e_time=maryQuery(0)
    elapsed_micro=get_micro(e_time)
    tlist.append(elapsed_micro)
    k=k-1
    if(debug):
        sys.stderr.write("%d %d GOOD_%d(micro)\n" % (cred_count,elapsed_micro,k))

sum=0
for i in tlist:
    sum=sum+i
ave=sum/100
dlist = [(x-ave) for x in tlist ]
slist = [ (x-ave)*(x-ave) for x in tlist]
sum=0
for i in slist:
    sum=sum+i
sd=math.sqrt(sum/99)
sys.stderr.write("%d %d %d GOOD_t(micro)\n" % (cred_count,ave,sd))
sys.stderr.write("%d 100 %s GOOD_list(micro)\n" % (cred_count,tlist))

##########################################################################
# Would Mary eat kiwi ?
# oset = [keyid:mary].oset:what2eat 
# p [string:'kiwi'] 
oset = ABAC.Oset(mary,"what2eat")
term=ABAC.DataTerm("string", "'kiwi'")
p = ABAC.Oset(term)

print "\n===good============ mary.what2eat <- kiwi"
out = ctxt.query(oset, p)
for c in out[1]:
    print "%s <- %s" % (c.head_string(), c.tail_string())

##########################################################################
# Would Bob eat navel orange ?
# oset = [keyid:bob].oset:what2eat 
# p [string:'navel orange'] 
def bobQuery(pr) :
    oset = ABAC.Oset(bob,"what2eat")
    term=ABAC.DataTerm("string", "'navel orange'")
    p = ABAC.Oset(term)

    if(pr) :
        print "\n===bad============ bob.what2eat <- navel orange"
    starttime = datetime.datetime.now()
    out = ctxt.query(oset, p)
    endtime = datetime.datetime.now()
    if(pr) :
        for c in out[1]:
            print "%s <- %s" % (c.head_string(), c.tail_string())
    return extract_delta(starttime, endtime)

# skip the first one
e_time=bobQuery(1)
elapsed_micro=get_micro(e_time)
sys.stderr.write("%d %d BAD_f(micro)\n" % (cred_count,elapsed_micro))

k=100
tlist=[]
while(k):
    e_time=bobQuery(0)
    elapsed_micro=get_micro(e_time)
    tlist.append(elapsed_micro)
    k=k-1
    if(debug):
        sys.stderr.write("%d %d BAD_%d(micro)\n" % (cred_count,elapsed_micro,k))

sum=0
for i in tlist:
    sum=sum+i
ave=sum/100
dlist = [(x-ave) for x in tlist ]
slist = [ (x-ave)*(x-ave) for x in tlist]
sum=0
for i in slist:
    sum=sum+i
sd=math.sqrt(sum/99)
sys.stderr.write("%d %d %d BAD_t(micro)\n" % (cred_count,ave, sd))
sys.stderr.write("%d 100 %s BAD_list(micro)\n" % (cred_count,tlist))

##########################################################################
# Is Apple 1.50 at Ralphs ?
# oset = [keyid:$ralphs].oset:fruitprice([float:1.50]) 
# p = [string:'apple'] 
param=ABAC.DataTerm("float", "1.50")
oset = ABAC.Oset(ralphs,"fruitprice")
oset.oset_add_data_term(param)
term=ABAC.DataTerm("string", "'apple'")
p = ABAC.Oset(term)

print "\n===good============ ralphs.fruitprice(1.50) <- apple"
out = ctxt.query(oset, p)
for c in out[1]:
    print "%s <- %s" % (c.head_string(), c.tail_string())

##########################################################################
# Is green apple 1.50 at Ralphs ?
# oset = [keyid:$ralphs].oset:fruitprice([float:1.50]) 
# p = [string:'green apple'] 
param=ABAC.DataTerm("float", "1.50")
oset = ABAC.Oset(ralphs,"fruitprice")
oset.oset_add_data_term(param)
term=ABAC.DataTerm("string", "'green apple'")
p = ABAC.Oset(term)

print "\n===bad============ ralphs.fruitprice(1.50) <- green apple"
out = ctxt.query(oset, p)
for c in out[1]:
    print "%s <- %s" % (c.head_string(), c.tail_string())

##########################################################################
# dump the yap dB
#
#ctxt.dump_yap_db()

