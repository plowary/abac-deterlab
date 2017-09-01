package net.deterlab.abac;

import java.io.*;
import java.math.*;
import java.text.*;

import java.util.*;

import java.security.*;
import java.security.cert.*;

import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.*;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.*;

import org.xml.sax.*;
import org.w3c.dom.*;

/**
 * An ABAC credential formatted as an abac-type GENI credential, version 1.1.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public class GENICredentialv1_1 extends GENICredential 
    implements Comparable, MapsKeyIDs {

    protected KeyIDMap keyMap;
    /**
     * Create an empty Credential.
     */
    public GENICredentialv1_1() {
	super();
	keyMap = new KeyIDMap();
    }
    /**
     * Create a credential from a head and tail role.  This credential has no
     * underlying certificate, and cannot be exported or used in real proofs.
     * make_cert can create a certificate for a credential initialized this
     * way.
     * @param head the Role at the head of the credential
     * @param tail the Role at the tail of the credential
     */
    public GENICredentialv1_1(Role head, Role tail) {
	super(head, tail);
	keyMap = new KeyIDMap();
    }

    /**
     * Create a credential from a head and tail role.  This credential has no
     * underlying certificate, and cannot be exported or used in real proofs.
     * make_cert can create a certificate for a credential initialized this
     * way.  The keymap will be used to annotate the names.
     * @param head the Role at the head of the credential
     * @param tail the Role at the tail of the credential
     * @param km a KeyIDmap used to map nicknames to actual roles if one is
     *		already in use.
     */
    public GENICredentialv1_1(Role head, Role tail, KeyIDMap km) {
	super(head, tail);
	keyMap = new KeyIDMap(km);
    }
    /**
     * Create a credential from an attribute cert in a file. Throws an
     * exception if the cert file can't be opened or if there's a format
     * problem with the cert.  Note that catching
     * java.security.GeneralSecurityException catches most of the exceptions
     * this throws.
     * @param filename a String containing the filename to read
     * @param ids a Collection of Identities to use in validating the cert
     * @throws CertInvalidException if the stream is unparsable
     * @throws MissingIssuerException if none of the Identities can validate the
     *				    certificate
     * @throws BadSignatureException if the signature check fails
     */
    GENICredentialv1_1(String filename, Collection<Identity> ids) 
	throws ABACException { 
	super(filename, ids);
	/* Parsers should create a keyMap in load_roles(), but create one here
	 * if not */
	if ( keyMap == null ) keyMap = new KeyIDMap();
    }

    /**
     * Create a credential from an attribute cert in a file. Throws an
     * exception if the cert file can't be opened or if there's a format
     * problem with the cert.  Note that catching
     * java.security.GeneralSecurityException catches most of the exceptions
     * this throws.
     * @param file the File to read
     * @param ids a Collection of Identities to use in validating the cert
     * @throws CertInvalidException if the stream is unparsable
     * @throws MissingIssuerException if none of the Identities can validate the
     *				    certificate
     * @throws BadSignatureException if the signature check fails
     */
    GENICredentialv1_1(File file, Collection<Identity> ids) 
	    throws ABACException {
	super(file, ids);
	/* Parsers should create a keyMap in load_roles(), but create one here
	 * if not */
	if ( keyMap == null ) keyMap = new KeyIDMap();
    }

    /**
     * Create a credential from an InputStream.  Throws an exception if the
     * stream can't be parsed or if there's a format problem with the cert.
     * Note that catching java.security.GeneralSecurityException catches most
     * of the exceptions this throws.
     * @param s the InputStream to read
     * @param ids a Collection of Identities to use in validating the cert
     * @throws CertInvalidException if the stream is unparsable
     * @throws MissingIssuerException if none of the Identities can validate the
     *				    certificate
     * @throws BadSignatureException if the signature check fails
     */
    GENICredentialv1_1(InputStream s, Collection<Identity> ids) 
	    throws ABACException { 
	super(s, ids);
	/* Parsers should create a keyMap in load_roles(), but create one here
	 * if not */
	if ( keyMap == null ) keyMap = new KeyIDMap();
    }

    protected void add_structured_role(Role r, Node top) {
	if ( r.is_principal()) {
	    Element p = doc.createElement("ABACprincipal");
	    Element k = doc.createElement("keyid");
	    String ms = keyMap.keyToNickname(r.principal());
	    Element m = (ms != null ) ? doc.createElement("mnemonic") : null;

	    k.appendChild(doc.createTextNode(r.principal()));
	    p.appendChild(k);

	    if (m != null ) {
		m.appendChild(doc.createTextNode(ms));
		p.appendChild(m);
	    }
	    top.appendChild(p);
	} else if ( r.is_role() ) {
	    Element p = doc.createElement("ABACprincipal");
	    Element k = doc.createElement("keyid");
	    String ms = keyMap.keyToNickname(r.principal());
	    Element m = (ms != null ) ? doc.createElement("mnemonic") : null;
	    Element rr = doc.createElement("role");

	    k.appendChild(doc.createTextNode(r.principal()));
	    rr.appendChild(doc.createTextNode(r.role_name()));
	    p.appendChild(k);
	    if (m != null ) {
		m.appendChild(doc.createTextNode(ms));
		p.appendChild(m);
	    }
	    top.appendChild(p);
	    top.appendChild(rr);
	} else {
	    Element p = doc.createElement("ABACprincipal");
	    Element k = doc.createElement("keyid");
	    String ms = keyMap.keyToNickname(r.principal());
	    Element m = (ms != null ) ? doc.createElement("mnemonic") : null;
	    Element rr = doc.createElement("role");
	    Element lr = doc.createElement("linking_role");

	    k.appendChild(doc.createTextNode(r.principal()));
	    rr.appendChild(doc.createTextNode(r.role_name()));
	    lr.appendChild(doc.createTextNode(r.linking_role()));
	    p.appendChild(k);
	    if (m != null ) {
		m.appendChild(doc.createTextNode(ms));
		p.appendChild(m);
	    }
	    top.appendChild(p);
	    top.appendChild(rr);
	    top.appendChild(lr);
	}
    }

    protected Node make_structured_rt0() {
	Element a = doc.createElement("rt0");
	Element v = doc.createElement("version");
	Element n = doc.createElement("head");
	Role[] tailRoles = null;

	v.appendChild(doc.createTextNode("1.1"));
	a.appendChild(v);
	add_structured_role(head(), n);
	a.appendChild(n);
	
	if (tail().is_intersection()) {
	    try { 
		tailRoles = tail().prereqs();
	    } catch (ABACException ignored ) { }
	} else {
	    tailRoles = new Role[] { tail() };
	}

	for ( Role tr: tailRoles ) {
	    n = doc.createElement("tail");
	    add_structured_role(tr, n);
	    a.appendChild(n);
	}
	return a;
    }

    /**
     * Encode the abac credential's XML and set the validity.  This is straight
     * line code that directly builds the credential.
     * @param validity a long holding the number of seconds that the credential
     * is valid for.
     * @return a Node, the place to attach signatures
     * @throws ABACException if any of the XML construction fails
     */
    protected Node make_rt0_content(long validity) throws ABACException {
	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	DocumentBuilder db = null;
	SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
	StringBuffer expBuf = new StringBuffer();

	/* This is a weirdness to cope with the GENI format.  They have a naked
	 * xml:id specifier without any namespace declarations in the
	 * credential.  Notice that this is the opposite of the setting used in
	 * init to read a credential. */
	dbf.setNamespaceAware(false);

	if ( dbf == null ) 
	    throw new ABACException("Cannot get DocumentBuilderFactory!?");

	try {
	    db = dbf.newDocumentBuilder();
	}
	catch (ParserConfigurationException pe) {
	    throw new ABACException("Cannot get DocumentBuilder!?" + 
		    pe.getMessage(), pe);
	}

	doc = db.newDocument();
	if ( doc == null ) 
	    throw new ABACException("No Document");

	Element root = doc.createElement("signed-credential"); 
	Element cred = doc.createElement("credential");
	Element serial = doc.createElement("serial");
	Element owner_gid = doc.createElement("owner_gid");
	Element target_gid = doc.createElement("target_gid");
	Element uuid = doc.createElement("uuid");
	Element sig = doc.createElement("signatures");
	Element e = doc.createElement("type");
	Node text = doc.createTextNode("abac");

	doc.appendChild(root);

	cred.setAttribute("xml:id", "ref0");
	/* So that the signing code can find the section to sign */
	cred.setIdAttribute("xml:id", true);

	root.appendChild(cred);
	e.appendChild(text);
	for (Element ele : new Element[] 
		{serial, owner_gid, target_gid, uuid, sig, e })
	    cred.appendChild(ele);

	m_expiration = new Date(System.currentTimeMillis() + 
		(1000L * validity ));
	df.setTimeZone(new SimpleTimeZone(0, "Z"));
	df.format(m_expiration, expBuf, new FieldPosition(0));
	e = doc.createElement("expires");
	text = doc.createTextNode(expBuf.toString());
	e.appendChild(text);
	cred.appendChild(e);

	e = doc.createElement("abac");
	e.appendChild(make_structured_rt0());
	cred.appendChild(e);

	root.appendChild(sig);
	return sig;
    }

    protected Role parse_structured_rt0(Node srt)  throws CertInvalidException {
	Node p = getChildByName(srt, "ABACprincipal");
	Node k = null;
	Node mn = null;
	Node r = getChildByName(srt, "role");
	Node lr = getChildByName(srt, "linking_role");
	String ks = null;
	String mns = null;
	String rs = ( r != null ) ? r.getTextContent() : null;
	String lrs = ( lr!= null ) ? lr.getTextContent() : null;
	Role rv = null;

	if (p == null ) 
	    throw new CertInvalidException("No principal!?");

	if ( (k = getChildByName(p, "keyid")) == null ) 
	    throw new CertInvalidException("Principal w/o keyid");

	if ( (ks = k.getTextContent()) == null ) 
	    throw new CertInvalidException("Empty keyid");

	if ( (mn = getChildByName(p, "mnemonic")) != null )
	    mns = mn.getTextContent();

	if ( lrs != null ) {
	    if ( rs == null ) {
		throw new CertInvalidException("Linking role without role");
	    }
	    rv = new Role(ks + "." + lrs + "." + rs);
	} else if ( rs == null ) {
	    rv = new Role(ks);
	} else {
	    rv = new Role(ks + "." + rs);
	}
	if ( mns != null ) keyMap.addNickname(ks, mns);
	return rv;
    }

    /**
     * Load the roles off the attribute cert.
     * @throws CertInvalidException if the certificate is badly formatted
     */
    protected void load_roles() throws CertInvalidException {
	if ( doc == null ) 
            throw new CertInvalidException("No credential");

	if ( keyMap == null ) keyMap = new KeyIDMap();

	NodeList nodes = doc.getElementsByTagName("credential");
	Node node = null;
	Node type = null;
	Node rt0 = null;
	Node v = null;
	String vs = null;

	if (nodes == null || nodes.getLength() != 1) 
            throw new CertInvalidException("More than one credential?");

	node = nodes.item(0);
	if ( node == null ) 
            throw new CertInvalidException("bad credential element?");

	if ( (type = getChildByName(node, "type")) == null ) {
	    throw new CertInvalidException("No Type field");
	}

	if ( !"abac".equals(type.getTextContent()) ) 
            throw new CertInvalidException("Not an abac type credential");

	// Walk down to the abac and rt0 field using the rt0 variable.
	if ( (rt0 = getChildByName(node, "abac")) == null ) {
	    throw new CertInvalidException("No abac field");
	}
	if ( (rt0 = getChildByName(rt0, "rt0")) == null ) {
	    throw new CertInvalidException("No rt0 field");
	}

	if ( (v = getChildByName(rt0, "version")) == null ) {
	    throw new CertInvalidException("No version field");
	}
	if ( (vs = v.getTextContent()) == null) {
	    throw new CertInvalidException("empty version field");
	}
	if ( ! vs.trim().equals("1.1")) {
	    throw new CertInvalidException("bad version: expected 1.1 got "+vs);
	}

	m_head = null;
	m_tail = null;

	for (Node n = rt0.getFirstChild(); n != null; n = n.getNextSibling()) {
	    String nname = null;

	    if ( n.getNodeType() != Node.ELEMENT_NODE) continue;
	    nname = n.getNodeName();
	    if (nname == null ) continue;

	    if (nname.equals("head")) {
		if ( m_head != null ) 
		    throw new CertInvalidException("2 head elements");
		try {
		    m_head = parse_structured_rt0(n);
		} catch (CertInvalidException ce) {
		    throw new CertInvalidException("Error parsing head: " + 
			    ce.getMessage());
		}
	    } else if (nname.equals("tail")) {
		Role t = null;

		try {
		    t = parse_structured_rt0(n);
		} catch (CertInvalidException ce) {
		    throw new CertInvalidException("Error parsing tail: " + 
			    ce.getMessage());
		}
		// This is a little wasteful in processing terms, but simply
		// appends the new tail entry to a new intersection role.
		if ( m_tail != null ) 
		    m_tail = new Role(m_tail.toString()  + " & " + 
			    t.toString());
		else m_tail = t;
	    }
	}
    }
    /**
     * Return the keymap.
     * @return a KeyIDMap, this class's keymap
     */
    public KeyIDMap getMapping() { return keyMap; }
    /**
     * Return a CredentialCredentialFactorySpecialization for 
     * GENICredentialsv1_1.  Used by the CredentialFactory to parse and generate
     * these kind of credentials.  It basically wraps constuctor calls.
     * @return a CredentialFactorySpecialization for this kind of credential.
     */
    static public CredentialFactorySpecialization 
	    getCredentialFactorySpecialization() {
	return new CredentialFactorySpecialization() {
	    public Credential[] parseCredential(InputStream is, 
		    Collection<Identity> ids) throws ABACException {
		return new Credential[] { new GENICredentialv1_1(is, ids) }; 
	    }
	    public Credential generateCredential(Role head, Role tail,
		    KeyIDMap aliases) {
		return new GENICredentialv1_1(head, tail, aliases);
	    }
	};
    }
}
