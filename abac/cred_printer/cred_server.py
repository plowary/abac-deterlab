#!/usr/local/bin/python

import sys

import re
import select
from signal import signal, SIGINT, SIGTERM

from cred_printer.server import xmlrpc_handler, server, simpleServer
from cred_printer.service_error import service_error
from cred_printer.util import ssl_context

from xmlrpclib import Binary
from tempfile import NamedTemporaryFile
from string import join

from optparse import OptionParser

import ABAC

class OptParser(OptionParser):
    """
    Option parsing for clients.  Should be self-explanatory.
    """
    def __init__(self):
	OptionParser.__init__(self)
	self.add_option('--port', dest='port', type='int', default=13232,
		help='port to listen on')
	self.add_option('--cert', dest='cert', default=None,
		help='My identity certificate (and key)')


class credential_printer:
    """
    The implementation passed to the server to handle incoming requests.
    Specifically, translate_creds will be called when the translate method is
    invoked on the server.
    """
    def __init__(self):
	"""
	Initialize the method -> function dict.
	"""
	self.xmlrpc_services = { 'translate': self.translate_creds }

    @staticmethod
    def get_cred_data(d):
	"""
	Get the credential data from one of the aprameter dicts
	"""
	return d.get('credential', Binary()).data

    @staticmethod
    def attr_cred_to_string(r):
	"""
	Parse a an ABAC.Credential into a string representation.
	"""
	return "%s <- %s" % (r.head().string(), r.tail().string())

    @staticmethod
    def repl_IDs(s, id_dict):
	"""
	Replace all the keyids in the string with the name they map to in the
	dict.  id_dict maps an ID certificate's keyid to a human-readable name.
	"""
	for k, n in id_dict.items():
	    if re.search(k, s):
		s = re.sub(k, n, s)
	return s

    def make_ID(self, cred):
	"""
	Create a Creddy.ID from the given binary, if possible.  Because
	Creddy.ID doesn't take a binary blob, this writes a temp file and
	creates the ID from that.  If successful, the ID is returned.
	Otherwise None is returned.
	"""
	i = None
	try:
	    i = ABAC.ID_chunk(cred)
	except:
	    pass
	finally:
	    return i

    def split_certs(self, cred_dict):
	"""
	A list of dicts of the form { id: identifier, credential: bits} is
	divided into two such lists, one where the bits are attribute
	certificates and one where they are IDs.  Dicts the ID cert list have
	their 'type', 'str', 'auxstr' fields set to 'identity', the keyid, and
	the common name in the certificate.  The temporary 'chunk' key is set
	to the binary representation fo the credential.  The return value is a
	tuple of ID dicts and attr dicts in that order.
	"""
	ids = [ ]
	attrs = [ ]
	for e in cred_dict:
	    abac_ID = self.make_ID(self.get_cred_data(e))
	    if abac_ID:
		id_name = abac_ID.cert_filename()
		if id_name.endswith('_ID.pem'):
		    id_name = id_name[0:-7]
		e['type'] = 'identity'
		e['str'] = abac_ID.keyid()
		e['auxstr'] = id_name
		e['chunk'] = abac_ID.cert_chunk()
		ids.append(e)
	    else:
		attrs.append(e)

	return (ids, attrs)


    def translate_attr(self, a, c, id_dict):
	"""
	Set the 'str' and 'auxstr' fields in the given attribute dict (a) by
	importing it into a clone of the given context and parsing the result.
	The 'errcode' key is set as well.
	"""
	cc = ABAC.Context(c)
	errcode = cc.load_attribute_chunk(self.get_cred_data(a))
	if errcode == ABAC.ABAC_CERT_SUCCESS:
	    # Success, pull it out and parse it.
	    creds = cc.credentials()
	    # There should only be one credential in the list.  If not, throw
	    # an error
	    if len(creds) == 1:
		a['str'] = self.attr_cred_to_string(creds[0])
		a['auxstr'] = self.repl_IDs(a['str'], id_dict)
		a['type'] = 'attribute'
                # Process the attribute head
                head = creds[0].head()
                a['head'] = dict()
                a['head']['principal'] = head.principal()
                a['head']['role'] = head.role_name()
                a['head']['pretty_principal'] = self.repl_IDs(head.principal(),
                                                              id_dict)
                # Process the attribute tail
                tail = creds[0].tail()
                a['tail'] = dict()
                a['tail']['principal'] = tail.principal()
                a['tail']['pretty_principal'] = self.repl_IDs(tail.principal(),
                                                              id_dict)
                if tail.is_role():
                    a['tail']['role'] = tail.role_name()
                elif tail.is_linking():
                    a['tail']['role'] = tail.role_name()
                    a['tail']['linked_role'] = tail.linked_role()
	    else:
		raise service_error(service_error.server_config, 
			'Multiple credentials in Context!?')
	else:
	    # Fail, clear the keys
	    a['str'] = ''
	    a['auxstr']= ''
	    a['type'] = 'unknown'
	a['errcode'] = errcode


    def translate_creds(self, req, fid):
	"""
	Base translation routine: split the credential dicts into IDs and
	attributes, initialize an ABAC context with all the known IDs, and
	parse out each attribute.  Return a single list of all the modified
	certificate dicts.  The server will encode that and return it or
	convert any service_errors raised into an XMLRPC Fault.
	"""
	ids, attrs = self.split_certs(req[0])
	ctxt = ABAC.Context()
	id_dict = { }	# Used to create auxstrs.  It maps ID cert keyid->CN
	for i in ids:
	    if 'chunk' in i: 
		errcode = ctxt.load_id_chunk(i['chunk'])
		del i['chunk']
	    else: 
		errcode = ABAC.ABAC_CERT_INVALID

	    if errcode == ABAC.ABAC_CERT_SUCCESS:
		id_dict[i['str']] = i['auxstr']
	    i['errcode'] = errcode
	for a in attrs:
	    self.translate_attr(a, ctxt, id_dict)
	return ids + attrs


def shutdown(sig, frame):
    """
    Signal handler.  Set the global active variable false if a terminating
    signal is received.
    """
    global active
    active = False

# Main code

# Parse args
parser = OptParser()
opts, args = parser.parse_args()

if opts.cert:
    # There's a certificate specified, set up as an SSL server.
    try:
	ctx = ssl_context(opts.cert)
    except SSLError, e:
	sys.exit("Cannot load %s: %s" % (opts.cert, e))

    s = server(('localhost', opts.port), xmlrpc_handler, ctx, 
	    credential_printer(), True)
else:
    # No certificate.  Be an open server
    s = simpleServer(('localhost', opts.port), xmlrpc_handler, 
	    credential_printer(), True)

# Catch SIGINT and SIGTERM
signal(SIGINT, shutdown)
signal(SIGTERM, shutdown)

# Do it.
active = True
while active:
    try:
	# When a request comes in handle it.  This extra selecting gives us
	# space to catch terminating signals.
	i, o, e = select.select((s,), (), (), 1.0)
	if s in i: s.handle_request()
    except select.error, e:
	if e[0] == 4: pass
	else: sys.exit("Unexpected error: %s" % e)

sys.exit(0)
