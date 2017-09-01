#!/usr/bin/env python

"""
Run the queries described in README

cmd: env keystore=`pwd` ./query.py

"""

import os
import sys
import ABAC
import time
import datetime
import math

from test_util import runTest

debug=0

ctxt = ABAC.Context()

cred_count = 2 + 2 * #VAL#

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
        sys.stderr,write("%s is longer than a day !!!" % msg)
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

##########################################################################
# dump the loaded principals/policies
#

fd=os.open("creds_dump",os.O_WRONLY|os.O_CREAT)
credentials = ctxt.credentials()
for cred in credentials:
    string="%s <- %s" % (cred.head().string(), cred.tail().string())
    os.write(fd,string) 
    os.write(fd,"\n")
os.close(fd)

##########################################################################
# Does JohnX likes John0 ?
# role = [keyid:JohnX].role:after 
# p [Keyid:john0]
def goodQuery() :
    aid="John%s_ID.pem"% #VAL#
    aID=ABAC.ID(aid)
    bID=ABAC.ID("John0_ID.pem")

    print "\n===good============ johnX.likes <- john0 "
    starttime = datetime.datetime.now()

#    (success, credentials) = ctxt.query("%s.likes" % aID.keyid(), bID.keyid())
#    if success:
#        print "success"
#    else:
#        print "failure"

    runTest("scaling_tests/daisychain/#VAL#","test1",ctxt,"%s.likes" % aID.keyid(), bID.keyid(), 1, "cascaing johnX.likes<-john0,expect success")

    endtime = datetime.datetime.now()
    if(debug):
        print "good query start-> %s\n" % starttime
        print "good query end  -> %s\n" % endtime
    for cred in credentials:
        print "%s <- %s" % (cred.head().string(), cred.tail().string())
    return extract_delta(starttime, endtime)
    

##########################################################################
# Does John0 likes JohnX ?
# role = [keyid:JohnX].role:after 
# p [Keyid:john0]
def badQuery() :
    bid="John%s_ID.pem"% #VAL#
    bID=ABAC.ID(bid)
    aID=ABAC.ID("John0_ID.pem")

    print "\n===bad============ john0.likes <- johnX "
    starttime = datetime.datetime.now()
#    (success, credentials) = ctxt.query("%s.likes" % aID.keyid(), bID.keyid())
#    if success:
#        print "success"
#    else:
#        print "failure"
    runTest("scaling_tests/daisychain/#VAL#","test2",ctxt,"%s.likes" % aID.keyid(), bID.keyid(), 1, "cascaing john0.likes<-johnX,expect failure")
    endtime = datetime.datetime.now()
    for cred in credentials:
        print "%s <- %s" % (cred.head().string(), cred.tail().string())
    return extract_delta(starttime, endtime)
        
##############################################################

#skip the first one
e_time=goodQuery()
elapsed_micro=get_micro(e_time)
sys.stderr.write("%d %d GOOD_f(micro)\n" % (cred_count,elapsed_micro))

tlist=[]
k=100
while(k):
    e_time=goodQuery()
    elapsed_micro=get_micro(e_time)
    k=k-1
    tlist.append(elapsed_micro)
    if(k==99):
       sys.stderr.write("%d %d GOOD_s(micro)\n" % (cred_count,elapsed_micro))

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


###############################################################

e_time=badQuery()
elapsed_micro=get_micro(e_time)
sys.stderr.write("%d %d BAD_f(micro)\n" % (cred_count,elapsed_micro))

tlist=[]
k=100
while(k):
    e_time=badQuery()
    elapsed_micro=get_micro(e_time)
    tlist.append(elapsed_micro)
    k=k-1
    if(k==99):
        sys.stderr.write("%d %d BAD_s(micro)\n" % (cred_count,elapsed_micro))

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
