#!/usr/local/bin/python

import sys

from BaseHTTPServer import BaseHTTPRequestHandler

from M2Crypto import SSL
from M2Crypto.SSL.SSLServer import SSLServer
from SocketServer import TCPServer

from service_error import service_error
import xmlrpclib

import os.path

import logging
import traceback

# The SSL server here is based on the implementation described at
# http://www.xml.com/pub/a/ws/2004/01/20/salz.html

# Turn off the matching of hostname to certificate ID
SSL.Connection.clientPostConnectionCheck = None

class error_handlers:
    """
    Class to encapsulate the debugging and non-debugging error handlers.
    """
    def __init__(self, debug):
	"""
	Set the error handler
	"""
	if debug: self.handle_error = self.handle_error_debug
	else: self.handle_error = self.handle_error_standard

    def handle_error_debug(self, request=None, client_address=None):
	"""
	Debugging error handler.  Prints a stack trace.
	"""
	print '-'*40
	traceback.print_exc()
	print '-'*40


    def handle_error_standard(self, request=None, address=None):
	"""
	Print standard error output, suitable for human consumption.
	"""
	if request or address:
	    self.log.warn("[credd] Error on incoming connection: %s %s" % \
		    (request or "", address or ""))
	else:
	    self.log.warn("[credd] Error on incoming connection " + \
		    "(Likely SSL error)")



class server(SSLServer, error_handlers):
    """
    Overloads a TCPServer to hold an XMLRPC implementation.  The implementation
    needs to inclide an xmlrpc_services dist that maps from method name to
    callable mamber that takes a single parameter (usually a list or dict) and
    a certificate.
    """
    def __init__(self, ME, handler, ssl_ctx, impl, debug=False):
	"""
	Create an SSL server that handles the transport in handler using the
	credentials in ssl_ctx, and interfacing to the implementation of fedd
	services in fedd.  ME is the host port pair on which to bind.
	"""
	SSLServer.__init__(self, ME, handler, ssl_ctx)
	error_handlers.__init__(self, debug)
	self.impl = impl
	self.xmlrpc_methods = impl.xmlrpc_services
	self.log = logging.getLogger("creds")

class simpleServer(TCPServer, error_handlers):
    """
    Presents the same interface as server to a threaded TCP server.  Allows a
    binding of the same implementation and handler classes to
    unencrypted/authenticated connections.
    """
    def __init__(self, ME, handler, impl, debug=False):
	TCPServer.__init__(self, ME, handler)
	error_handlers.__init__(self, debug)
	self.impl = impl
	self.xmlrpc_methods = impl.xmlrpc_services
	self.log = logging.getLogger("creds")


class xmlrpc_handler(BaseHTTPRequestHandler):
    """
    Standard connection between XMLRPC and the services in impl.

    Much of this is boilerplate from 
    http://www.xml.com/pub/a/ws/2004/01/20/salz.html
    """
    server_version = "credd/0.2 " + BaseHTTPRequestHandler.server_version

    def send_xml(self, text, code=200):
	"""Send an XML document as reply"""
	self.send_response(code)
	self.send_header('Content-type', 'text/xml; charset="utf-8"')
	self.send_header('Content-Length', str(len(text)))
	self.end_headers()
	self.wfile.write(text)
	self.wfile.flush()
	# Make sure to close the socket when we're done
	self.request.close()
	#self.request.socket.close()

    def do_POST(self):
	"""Treat an HTTP POST request as an XMLRPC service call"""
	# NB: XMLRPC faults are not HTTP errors, so the code is always 200,
	# unless an HTTP error occurs, which we don't handle.

	resp = None
	data = None
	method = None
	cl = int(self.headers['content-length'])
	data = self.rfile.read(cl)

	try:
	    params, method = xmlrpclib.loads(data)
	except xmlrpclib.ResponseError:
	    data = xmlrpclib.dumps(xmlrpclib.Fault("Client", 
		"Malformed request"), methodresponse=True)

	# Simple servers don't have peer certificates.
	if getattr(self.request, 'get_peer_cert', None):
	    fid = self.request.get_peer_cert()
	else:
	    fid = None


	if method != None:
	    try:
		resp = self.xmlrpc_dispatch(method, params, fid)
		data = xmlrpclib.dumps((resp,), encoding='UTF-8', 
			methodresponse=True)
	    except xmlrpclib.Fault, f:
		data = xmlrpclib.dumps(f, methodresponse=True)
		resp = None

	self.send_xml(data)

    def log_request(self, code=0, size=0):
	"""
	Log request to the fedd logger
	"""
	self.server.log.info("Successful XMLRPC request code %d" % code)


    def xmlrpc_dispatch(self, method, req, fid):
	"""
	The connection to the implementation, using the  method maps

	The implementation provides a mapping from XMLRPC method name to the
	method in the implementation that provides the service.
	"""
	if self.server.xmlrpc_methods.has_key(method):
	    try:
		return self.server.xmlrpc_methods[method](req, fid)
	    except service_error, e:
		raise xmlrpclib.Fault(e.code_string(), e.desc)

	else:
	    raise xmlrpclib.Fault(100, "Unknown method: %s" % method)

