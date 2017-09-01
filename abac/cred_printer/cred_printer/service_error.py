#!/usr/local/bin/python

# This is used to make the service error reporting independent of the
# transport.  The XMLRPC and SOAP dispatchers will convert it into
# transport-specific errors.
# Cribbed directly from fedd, because it's so convenient.  Some of the error
# codes are inapplicable to the credential interpreter.
class service_error(RuntimeError):
    access = 1
    protocol= 2
    req = 3
    server_config = 4
    internal = 5
    partial = 6
    federant = 7
    connect = 8
    code_str = { 
	access : "Access Denied",
	protocol : "Protocol Error",
	req : "Badly Formed Request",
	server_config: "Server Configuration Error",
	internal : "Internal Error",
	partial: "Partial Embedding",
	federant: "Federant Error",
	connect: "Connection Error",
    }
    str_code = dict([ (v, k) for k, v in code_str.iteritems() ])
    client_errors = ( req, partial)
    server_errors = ( access, protocol, server_config, internal,
	    federant, connect)

    def __init__(self, code=None, desc=None, from_string=None, proof=None):
	self.code = code
	self.desc = desc
	self.proof = proof or []
	if not isinstance (self.proof, list): self.proof = [ proof ]
	if code == None:
	    self.set_code_from_string(from_string)
	RuntimeError.__init__(self, desc)

    def code_string(self, code=None):
	code = code or self.code
	return service_error.code_str.get(code)
    
    def set_code_from_string(self, errstr):
	self.code = service_error.str_code.get(errstr, service_error.internal)
	return self.code
    
    def is_client_error(self):
	return self.code in service_error.client_errors

    def is_server_error(self):
	return self.code in service_error.server_errors
