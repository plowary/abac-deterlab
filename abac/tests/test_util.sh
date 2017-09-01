#!/bin/sh

debug=0

# look for creddy,
if [ -n "${CREDDY_LOCATION}" ]; then
    eloc=${CREDDY_LOCATION}
    if ! [ -e $eloc/creddy ] ; then
        echo "ERROR: has CREDDY_LOCATION but creddy is not there!!!"
        exit 1
    fi
else
    eloc=`which creddy | sed 's/\/creddy//'`
    if [ -z "$eloc" ]; then
        echo "ERROR: creddy is not in the search path nor CREDDY_LOCATION defined!!!"
        exit 1
    fi
fi

# look for abac_prover,
if [ -n "${PROVER_LOCATION}" ]; then
    ploc=${PROVER_LOCATION}
    if ! [ -e $ploc/abac_prover ] ; then
        echo "ERROR: has PROVER_LOCATION but abac_provery is not there!!!"
        exit 1
    fi
else
    ploc=`which abac_prover | sed 's/\/abac_prover//'`
    if [ -z "$ploc" ]; then
        echo "ERROR: abac_prover is not in the search path nor PROVER_LOCATION defined!!!"
        exit 1
    fi
fi


# runTest fname test1 testbody expect msg
# if expect success, expect=0
# if expect failure, expect=1
runTest() {
    FNAME=$1
    LABEL=$2
    TESTBODY=$3
    EXPECT=$4
    MSG=$5
    rc=`${TESTBODY} 2>&1`
    if [ $? -eq $EXPECT ]; then
        echo "GOOD:${FNAME}:${LABEL}:${MSG}"
    else
        if [ $EXPECT -eq 1 ]; then
           echo "BAD:${FNAME}:${LABEL}:expected failure but got success,${MSG}"
        else
           echo "BAD:${FNAME}:${LABEL}:${MSG}"
        fi
    fi
    if [ $debug -eq 1 ]; then
	echo ${EXPECT}
	echo ${TESTBODY}
        echo $rc
    fi
}

# runXTest fname test1 testbody expect matchResult msg
# if expect success, expect=0
# if expect failure, expect=1
runXTest() {
    FNAME=$1
    LABEL=$2
    TESTBODY=$3
    EXPECT=$4
    MATCH=$5
    MSG=$6
    rc=`${TESTBODY} 2>&1`
    if [ $? -eq $EXPECT ]; then
        match=`echo "${rc}" | grep "${MATCH}" | wc -l`
        if [ $match -eq 1 ]; then
            echo "GOOD:${FNAME}:${LABEL}:${MSG}"
        else
            echo "BADX:${FNAME}:${LABEL}:${MSG}, but result is not as expected"
        fi
    else
        echo "BAD:${FNAME}:${LABEL}:${MSG}"
    fi
    if [ $debug -eq 1 ]; then
        echo $rc
    fi
}

# runCTest fname test1 testbody expect msg pattern count
# if expect success, expect=0
# if expect failure, expect=1
runCTest() {
    FNAME=$1
    LABEL=$2
    TESTBODY=$3
    EXPECT=$4
    MSG=$5
    PATTERN=$6
    COUNT=$7
    rc=`${TESTBODY} 1>atmp 2>/dev/null`
    if [ $? -eq $EXPECT ]; then
        cnt=`grep "$PATTERN" atmp | wc -l`
        if [ $cnt -eq $COUNT ]; then
            echo "GOOD:${FNAME}:${LABEL}:${MSG}"
        else
            echo "BAD:${FNAME}:${LABEL}:${MSG},did not have expected output"
        fi
    else
        if [ $EXPECT ]; then
           echo "BAD:${FNAME}:${LABEL}:expected failure but got success,${MSG}"
        else
           echo "BAD:${FNAME}:${LABEL}:${MSG}"
        fi
    fi
    rm -rf atmp
    return 0
}
