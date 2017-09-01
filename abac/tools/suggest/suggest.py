#!/usr/local/bin/python

import gtk
import gobject

import ABAC
import Creddy

import sys, os
import re
import copy
import base64
import ConfigParser

from tempfile import mkdtemp
from shutil import rmtree

class proof:
    def __init__(self, name, prover, role, principal, creds):
	self.name = name
	self.prover = prover
	self.role = role
	self.principal = principal
	self.ctxt = ABAC.Context()
	self.keyid_to_cn = { }
	self.cn_to_keyid = { }
	attrs = []
	try:
	    d = mkdtemp()
	    for c in creds:
		cc = self.pem_to_der(c)
		succ = self.ctxt.load_id_chunk(cc) 
		if succ == ABAC.ABAC_CERT_SUCCESS: 
		    try:
			fn = os.path.join(d, 'file.pem')
			f = open(fn, 'w')
			f.write(cc)
			f.close()
			cid = Creddy.ID(fn)
			base_cn = cn = re.sub('_ID.pem$','',cid.cert_filename())
			i = 0
			while cn in self.cn_to_keyid:
			    cn = '%s%03d' % (base_cn, i)
			    i += 1
			self.cn_to_keyid[cn] = cid.keyid()
			self.keyid_to_cn[cid.keyid()] = cn
		    except EnvironmentError, e:
			print >>sys.stderr, '%s: %s' % (e.filename, e.strerror)
		else:
		    attrs.append(cc)
	    for c in attrs:
		self.ctxt.load_attribute_chunk(c) 
	finally:
	    rmtree(d)


    @staticmethod
    def pem_to_der(c):
	pat = '-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE'
	m = re.match(pat, c, re.DOTALL)
	if m: return base64.b64decode(m.group(1))
	else: return c

    def replace_keyids(self, s):
	for k, v in self.keyid_to_cn.items():
	    s = re.sub(k, v, s)
	return s

    def __str__(self):
	s = 'Name: %s\n' % self.name
	s += 'Prover: %s\n' % self.prover
	s += 'Principal: %s\n' % self.principal
	s += 'Role: %s\n' % self.role
	s += 'Creds: \n'
	for c in self.ctxt.credentials():
	    s += self.replace_keyids(
		    '%s <- %s\n' % ( c.head().string(), c.tail().string()))
	return s

class window(gtk.Window):
    '''
    The main GUI class.  It presents the various TreeViews and menus to
    save/load/add, to add credentials, identities and actions and to change the
    policy translation variable.  It keeps its current size and location in the
    .abac_policy_tool.cfg file in the user's home.
    '''

    # Definition of the menus
    ui_def = '''
    <ui>
	<menubar>
	    <menu action="FileMenu">
		<menuitem name="Load" action="FileLoad"/>
		<menuitem name="Quit" action="FileQuit"/>
	    </menu>
	</menubar>
    </ui>
    '''
    # Path to the configuration
    cfg_path = os.path.join(os.path.expanduser('~'), '.abac_proof_explainer.cfg')

    @staticmethod
    def wrapit(widget):
	'''
	Put widget into a ScrolledWindow with automatic scrollbars on both
	directions, and return the ScrolledWindow.
	'''
	sw = gtk.ScrolledWindow()
	sw.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
	sw.add(widget)
	return sw

    def translate_keyids(self, s):
	for k, n in self.key_to_name:
	    s = re.sub(k, n, s)
	return s

    def makeListView(self, l, title):
	lm = gtk.ListStore(gobject.TYPE_STRING)
	tv = gtk.TreeView(lm)
	tv.append_column(gtk.TreeViewColumn(title, 
	    gtk.CellRendererText(), text=0))
	for v in l:
	    lm.append((self.translate_keyids(v),))
	return tv


    def report_error(self, message):
	'''
	Put a MessageDialog up with the given message.  This is a member method
	so that it can be centered on the window.
	'''
	md = gtk.MessageDialog(self, gtk.DIALOG_MODAL, 
		gtk.MESSAGE_ERROR, gtk.BUTTONS_CLOSE, 
		message)
	md.run()
	md.destroy()

    def __init__(self, fn):
	'''
	Initialize all the GTK hooks for menus, put the various TreeViews up
	(connected to the policy) and read teh configuration for current
	position.
	'''
	gtk.Window.__init__(self, gtk.WINDOW_TOPLEVEL)
	self.key_to_name = []
	try:
	    f = open('./names', 'r')
	    for l in f:
		m = re.match('(\\S+)\s+(\\S+)', l)
		if m:
		    self.key_to_name.append((m.group(1), m.group(2)))
	    f.close()
	except EnvironmentError:
	    pass

	self.set_title('ABAC Policy Tool')
	self.connect('destroy', self.quit)
	self.connect('show', self.shown)
	self.connect('configure-event', self.changed)
	self.pos = (0,0)
	self.size = (500, 500)
	self.read_config()
	self.proofs = []

	# Make the Menus real
	ui = gtk.UIManager()
	ag = gtk.ActionGroup('action')
	ag.add_actions((
	    ('FileMenu', None, 'File'),
	    ('FileQuit', gtk.STOCK_QUIT, None, None, None, self.quit),
	    ))
	# load and append call the same method with different user data -
	# whether to clear current policy or not.
	ag.add_actions((
	    ('FileLoad', gtk.STOCK_OPEN, None, None, None, self.load),
	    ), True)
	ui.insert_action_group(ag, -1)
	ui.add_ui_from_string(window.ui_def)

	# Put it all together and show it.
	mb = ui.get_widget('ui/menubar')
	vb = gtk.VBox()
	vb.pack_start(mb, False, False, 0)
	#vb.pack_start(nb, True, True, 0)

	self.add(vb)
	if fn is not None:
	    self.read_proofs(fn)
	    # XXX multiple proofs
	    self.get_child().add(self.interpret_proof(self.proofs[0]))
	self.show_all()
    
    def quit(self, widget=None, data=None):
	'''
	Called from File->Quit in the menu.  Save location/size and exit
	'''
	self.save_config()
	gtk.main_quit()

    def load(self, widget=None, data=None):
	'''
	Called to either load or append to the loaded policy.  data is the
	clearit parameter to the load call.  Other than that, just put up a
	requester and do the thing.
	'''
	d = gtk.FileChooserDialog('Load file', self, 
		gtk.FILE_CHOOSER_ACTION_OPEN, (
	    gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
	    gtk.STOCK_OK, gtk.RESPONSE_OK))
	d.set_select_multiple(False)
	d.set_current_folder('.')
	d.set_do_overwrite_confirmation(True)
	rv = d.run()
	d.hide()
	if rv == gtk.RESPONSE_OK:
	    self.read_proofs(d.get_filename())
	    # XXX multiple proofs
	    self.get_child().add(self.interpret_proof(self.proofs[0]))
	    self.show_all()
	d.destroy()


    def shown(self, w):
	'''
	Handles an event where the window appears.  Move to the saved position
	and size.
	'''
	self.move(*self.pos)
	self.resize(*self.size)

    def changed(self, w, e):
	'''
	Handles an event where the window changes (resizes or moves).  Remember
	the size and position.
	'''
	self.pos = self.get_position()
	self.size = self.get_size()

    def get_intpair(self, sect, opt):
	'''
	Utility to pull a pair of integers from a configuration file.  The size
	and position are thsi kind of data, so this is used a couple places.
	'''
	if not self.cfg.has_section(sect):
	    self.cfg.add_section(sect)

	if self.cfg.has_option(sect, opt):
	    try:
		return [int(x) for x in self.cfg.get(sect, opt).split(',', 1)]
	    except ValueError:
		return None
	else:
	    return None

    def read_config(self):
	'''
	Get the saved size and position from the config file, if any
	'''
	self.cfg = ConfigParser.SafeConfigParser()
	self.cfg.read(window.cfg_path)

	self.pos = self.get_intpair('geom', 'pos') or ( 0, 0)
	self.size = self.get_intpair('geom', 'size') or ( 500, 500)


    def save_config(self):
	'''
	Save the current postion to the default config file.
	'''
	self.cfg.set('geom', 'pos', '%d,%d' % self.pos)
	self.cfg.set('geom', 'size', '%d,%d' % self.size)
	try:
	    f = open(window.cfg_path, 'w')
	    self.cfg.write(f)
	    f.close()
	except EnvironmentError, e:
	    pass

    def read_proofs(self, fn):
	self.proofs = []
	try:
	    f = open(fn, 'r')
	    creds = []
	    for line in f:
		line = line.strip()
		if line == '<proof>':
		    prover = None
		    principal = None
		    role = None
		    creds = []
		elif line == '</proof>' :
		    p = proof(name, prover, role, principal, creds)
		    ok, pp = p.ctxt.query(role, principal)
		    if not ok: self.proofs.append(p)
	       
		m = re.match('<comment>(.*)</comment>', line)
		if m is not None:
		    name = m.group(1)

		m = re.match('<principal>([0-9a-f]+)</principal>', line)
		if m is not None:
		    principal = m.group(1)

		m = re.match('<prover>([0-9a-f]+)</prover>', line)
		if m is not None:
		    prover = m.group(1)

		m = re.match('<attribute>(.*)</attribute>', line)
		if m is not None:
		    role = m.group(1)

		m = re.match('<credential>(.*)</credential>', line)
		if m is not None:
		    creds.append(base64.b64decode(m.group(1)))
	    f.close()
	except EnvironmentError, e:
	    self.report_error("Cannot open %s: %s" % (e.filename, e.strerror))
	    return

    def interpret_proof(self, p):
	roles = set()
	direct_roles = {}
	groles = set()
	principals = set()
	goals = set()
	attrs = set()
	ok, proof = p.ctxt.query(p.role, p.principal)
	for c in p.ctxt.credentials():
	    role = c.tail()
	    if role.is_principal():
		if role.string() != p.principal: 
		    principals.add(role.string())
		else:
		    assigner, r = c.head().string().split('.')
		    direct_roles[r] = assigner
	    else: 
		r = role.string()
		for s in r.split('&'):
		    roles.add(s.strip())
		groles.add(r)

	    role = c.head()
	    roles.add(role.string())
	    groles.add(role.string())

	for r in groles:
	    ok, proof =  p.ctxt.query(p.role, r)
	    if ok :
		goals.add(r)
	for r in roles:
	    ok, proof = p.ctxt.query(r, p.principal)
	    if ok:
		attrs.add(r)


	split_goals = [ [s.strip() for s in g.split('&')] for g in goals ]
	plans = []
	for sg in split_goals:
	    pl = []
	    for g in sg:
		if g in attrs:
		    continue
		if g.count('.') == 2:
		    # linking role
		    pr, rr, lr = g.split('.')
		    if lr in direct_roles:
			pl.append('add %s to %s' % (direct_roles[lr], rr))
		    else:
			pl.append('someone with %s.%s must delegate %s to %s' % \
				(pr, rr, lr, p.principal))
		elif g.count('.') == 1:
		    pl.append('add %s to %s' % (g, principal))
	    plans.append('\n'.join(pl))

	vb = gtk.VBox()
	vb.set_border_width(20)
	vb.pack_start(
		self.wrapit(
		    self.makeListView([p.prover], "Entity Blocking Access")
		), True, True,0)
	vb.pack_start(
		self.wrapit(
		    self.makeListView(plans, "Suggested Actions")
		), True, True,0)
	vb.pack_start(
		self.wrapit(
		    self.makeListView(goals, "Required Slice Attributes")
		), True, True,0)

	vb.pack_start(
		self.wrapit(
		    self.makeListView(attrs, "Slice Attributes Present")
		), True, True,0)
	vb.show_all()
	return vb 

if len(sys.argv) > 1:
    fn = sys.argv[1]
else:
    fn = None
w = window(fn)
gtk.main()
