#!/usr/local/bin/python

import sys
from M2Crypto import SSL

# Turn off the matching of hostname to certificate ID
SSL.Connection.clientPostConnectionCheck = None

class ssl_context(SSL.Context):
    """
    Simple wrapper around an M2Crypto.SSL.Context to initialize it for use with
    self-signed certs.
    """
    def __init__(self, my_cert, trusted_certs=None, password=None):
	"""
	construct a cred_ssl_context

	@param my_cert: PEM file with my certificate in it
	@param trusted_certs: PEM file with trusted certs in it (optional)
	"""
	SSL.Context.__init__(self)

	# load_cert takes a callback to get a password, not a password, so if
	# the caller provided a password, this creates a nonce callback using a
	# lambda form.
	if password != None and not callable(password):
	    # This is cute.  password = lambda *args: password produces a
	    # function object that returns itself rather than one that returns
	    # the object itself.  This is because password is an object
	    # reference and after the assignment it's a lambda.  So we assign
	    # to a temp.
	    pwd = str(password)
	    password =lambda *args: pwd

	# The calls to str below (and above) are because the underlying SSL
	# stuff is intolerant of unicode.
	if password != None:
	    self.load_cert(str(my_cert), callback=password)
	else:
	    self.load_cert(str(my_cert))

	# If no trusted certificates are specified, allow unknown CAs.
	if trusted_certs: 
	    self.load_verify_locations(trusted_certs)
	    self.set_verify(SSL.verify_peer, 10)
	else:
	    callb = getattr(SSL.cb, "ssl_verify_callback")
	    self.set_allow_unknown_ca(True)
	    self.set_verify(SSL.verify_peer, 10, 
		    callback=SSL.cb.ssl_verify_callback_allow_unknown_ca)

# Python 2.7 broke the MCrypto 2.1 SSL_Transport.  If this is an older python,
# use SSL_Transport unchanged, otherwise use a tweaked version.  Export them as
# SSLTransport.
if sys.version_info == 2 and sys.version_info < 7:
    from M2Crypto.m2xmlrpclib import SSL_Transport
    class SSLTransport(SSL_Transport): pass
else:
    # Most of this is directly from M2Crypto
    import base64, string, sys

    from xmlrpclib import *
    import M2Crypto
    import M2Crypto.SSL, M2Crypto.httpslib, M2Crypto.m2urllib

    __version__ = M2Crypto.version

    class SSLTransport(Transport):

	user_agent = "M2Crypto_XMLRPC/%s - %s" % (__version__, 
		Transport.user_agent)

	def __init__(self, ssl_context=None, *args, **kw):
	    if getattr(Transport, '__init__', None) is not None:
		Transport.__init__(self, *args, **kw)
	    if ssl_context is None:
		self.ssl_ctx=M2Crypto.SSL.Context('sslv23')
	    else:
		self.ssl_ctx=ssl_context

	def request(self, host, handler, request_body, verbose=0):
	    # Handle username and password.
	    user_passwd, host_port = M2Crypto.m2urllib.splituser(host)
	    _host, _port = M2Crypto.m2urllib.splitport(host_port)

	    # This is a difference, was an (obsolete) HTTPS object, but
	    # HTTPSConnection is more supported and clear --tvf
	    h = M2Crypto.httpslib.HTTPSConnection(_host, int(_port), 
		    ssl_context=self.ssl_ctx)
	    if verbose:
		h.set_debuglevel(1)

	    # What follows is as in xmlrpclib.Transport. (Except the authz bit.)
	    h.putrequest("POST", handler)

	    # required by HTTP/1.1
	    h.putheader("Host", _host)

	    # required by XML-RPC
	    h.putheader("User-Agent", self.user_agent)
	    h.putheader("Content-Type", "text/xml")
	    h.putheader("Content-Length", str(len(request_body)))

	    # Authorisation.
	    if user_passwd is not None:
		auth=string.strip(base64.encodestring(user_passwd))
		h.putheader('Authorization', 'Basic %s' % auth)

	    h.endheaders()

	    if request_body:
		h.send(request_body)

	    # These are the modifications -- tvf

	    resp = h.getresponse()
	    errcode = resp.status
	    errmsg = resp.reason

	    # end mods -- tvf

	    if errcode != 200:
		raise ProtocolError(
		    host + handler,
		    errcode, errmsg,
		    headers
		    )

	    self.verbose = verbose
	    return self.parse_response(resp)

