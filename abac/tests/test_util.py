#!/usr/bin/env python

debug=0

import os
import ABAC

# EXPECT 1, success, 0, failure
def runTest(FNAME,LABEL,CTXT,ROLE,PRIN,EXPECT,MSG):
    (success, credentials) = CTXT.query(ROLE,PRIN)
    if EXPECT:
#expect success, got success
        if success:  
            print "GOOD:%s:%s:%s" %(FNAME,LABEL,MSG)
#expect success, got failure
        else:
            print "BAD:%s:%s:did not expect failure,%s" %(FNAME,LABEL,MSG)
    else:
#expect failure, got success
        if success:
            print "BAD:%s:%s:expected failure but got success,%s" %(FNAME,LABEL,MSG)
#expect failure, got failure
        else:
            print "GOOD:%s:%s:expected failure,%s" %(FNAME,LABEL,MSG)

    if debug:
        for credential in credentials:
            print "credential %s <- %s" % (credential.head().string(), credential.tail().string())
