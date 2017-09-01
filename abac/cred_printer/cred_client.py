#!/usr/local/bin/python

import sys
import os

from M2Crypto import SSL
from M2Crypto.SSL import SSLError
from xmlrpclib import ServerProxy, dumps, loads, Fault, Error, Binary

# This disables server hostname checking in SSL as a side effect.
from cred_printer.util import ssl_context, SSLTransport

from string import join
from optparse import OptionParser


class OptParser(OptionParser):
    """
    Option parsing for clients.  Should be self-explanatory.
    """
    def __init__(self):
	OptionParser.__init__(self)
	if 'CRED_URL' in os.environ: default_url = os.environ['CRED_URL']
	else: default_url = 'http://localhost:13232'

	self.add_option('--url', dest='url', default=default_url,
		help='URL of the server')
	self.add_option('--cert', dest='cert', default=None,
		help='My identity certificate (and key)')
	self.add_option('--verbose', dest='verbose', default=False,
		action='store_true')

def print_attr(a, label):
    '''
    Print the fields of an attribute dict
    '''
    print '\t%s:' % label
    for an in ('pretty_principal', 'principal', 'role', 'linked_role'):
	if an in a: print '\t\t%s: %s' % (an, a[an])

def print_cred(e, verbose=False):
    '''
    Print the credential (e), either as one line of 
	id type string auxstring 
    or 
	id Error, code n

    If verbose is True, print the head and tail components of valid attribute
    credentials indented.
    '''

    if e['errcode'] == 0:
	print "%s: %s %s %s" % (e['id'], e['type'], e['str'], e['auxstr'])
	if verbose and e['type'] == 'attribute':
	    for en in ('head', 'tail'):
		if en in e: print_attr(e[en], en)
    else:
	print "%s: Error, code %d" % (e['id'], e['errcode'])


# Parse the args
parser = OptParser()
opts, args = parser.parse_args()

if opts.cert:
    # If a certificate is given, use an SSL-protected connection
    try:
	ctx = ssl_context(opts.cert)
    except SSLError, e:
	sys.exit("Cannot load %s: %s" % (opts.cert, e))

    transport=SSLTransport(ctx)
else:
    transport=None


creds = []
for fn in args:
    # Collect the contents of the filenames into the creds list
    try:
	# The list comprehension and join are a compact way to read the whole
	# file into a string.
	creds.append(join([l for l in open(fn)], ''))
    except EnvironmentError, e:
	# warn if there's an error reading one of the files
	print >>sys.stderr, "Cannot read %s: %s" % (fn, e.strerror)

# This builds a list of structs with the ID (an integer printed to 3 places)
# and the contents of the file as an XMLRPC binary.
req = [ {'id': "%03d" % i, 'credential': Binary(c) } 
	for i, c in enumerate(creds)]

# Call the server
proxy = ServerProxy(opts.url, transport=transport)
try:
    resp = proxy.translate(req)
except SSLError, e:
    sys.exit("SSL error: %s" %e)
except EnvironmentError, e:
    sys.exit("IOError: %s" %e)
except:
    t, e = sys.exc_info()[0:2]
    sys.exit('Unexpected error: %s %s' % (t,e))

# Sort by ID
resp.sort(key=lambda x: x['id'])

# Output the response
for e in resp:
    print_cred(e, opts.verbose)
