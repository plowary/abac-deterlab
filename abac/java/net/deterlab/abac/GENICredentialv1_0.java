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
 * An ABAC credential formatted as a soon-to-be deprecated  abac-type version
 * 1.0 GENI credential.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public class GENICredentialv1_0 extends GENICredential implements Comparable {
	/**
	 * Create an empty Credential.
	 */
	public GENICredentialv1_0() {
		super();
	}
	/**
	 * Create a credential from a head and tail role.  This credential has no
	 * underlying certificate, and cannot be exported or used in real proofs.
	 * make_cert can create a certificate for a credential initialized this
	 * way.
	 * @param head the Role at the head of the credential
	 * @param tail the Role at the tail of the credential
	 */
	public GENICredentialv1_0(Role head, Role tail) {
		super(head, tail);
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
	GENICredentialv1_0(String filename, Collection<Identity> ids)
			throws ABACException {
		super(filename, ids);
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
	GENICredentialv1_0(File file, Collection<Identity> ids)
			throws ABACException {
		super(file, ids);
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
	GENICredentialv1_0(InputStream s, Collection<Identity> ids)
			throws ABACException {
		super(s, ids);
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
		Element sig = doc.createElement("signatures");
		Element e = doc.createElement("type");
		Node text = doc.createTextNode("abac");

		doc.appendChild(root);

		cred.setAttribute("xml:id", "ref0");
	/* So that the signing code can find the section to sign */
		cred.setIdAttribute("xml:id", true);

		root.appendChild(cred);
		e.appendChild(text);
		cred.appendChild(e);

		m_expiration = new Date(System.currentTimeMillis() +
				(1000L * validity ));
		df.setTimeZone(new SimpleTimeZone(0, "Z"));
		df.format(m_expiration, expBuf, new FieldPosition(0));
		e = doc.createElement("expires");
		text = doc.createTextNode(expBuf.toString());
		e.appendChild(text);
		cred.appendChild(e);

		e = doc.createElement("version");
		text = doc.createTextNode("1.0");
		e.appendChild(text);
		cred.appendChild(e);

		e = doc.createElement("rt0");
		text = doc.createTextNode(m_head + "<-" + m_tail);
		e.appendChild(text);
		cred.appendChild(e);

		root.appendChild(sig);
		return sig;
	}

	/**
	 * Load the roles off the attribute cert.
	 * @throws CertInvalidException if the certificate is badly formatted
	 */
	protected void load_roles() throws CertInvalidException {
		if ( doc == null )
			throw new CertInvalidException("No credential");

		NodeList nodes = doc.getElementsByTagName("type");
		Node node = null;
		String roles = null;

		if (nodes == null || nodes.getLength() != 1)
			throw new CertInvalidException("More than one type element?");

		node = nodes.item(0);
		if ( node == null )
			throw new CertInvalidException("bad rt0 element?");

		if ( !"abac".equals(node.getTextContent()) )
			throw new CertInvalidException("Not an abac type credential");

		nodes = doc.getElementsByTagName("rt0");
		if (nodes == null || nodes.getLength() != 1)
			throw new CertInvalidException("More than one rt0 element?");

		node = nodes.item(0);

		if ( node == null )
			throw new CertInvalidException("bad rt0 element?");

		if ( (roles = node.getTextContent()) == null )
			throw new CertInvalidException("bad rt0 element (no text)?");

		String[] parts = roles.split("\\s*<--?\\s*");
		if (parts.length != 2)
			throw new CertInvalidException("Invalid attribute: " + roles);

		m_head = new Role(parts[0]);
		m_tail = new Role(parts[1]);
	}

	/**
	 * Return a CredentialCredentialFactorySpecialization for GENICredentials.
	 * Used by the CredentialFactory to parse and generate these kind of
	 * credentials.  It basically wraps constuctor calls.
	 * @return a CredentialFactorySpecialization for this kind of credential.
	 */
	static public CredentialFactorySpecialization
	getCredentialFactorySpecialization() {
		return new CredentialFactorySpecialization() {
			public Credential[] parseCredential(InputStream is,
												Collection<Identity> ids) throws ABACException {

				return new Credential[] { new GENICredentialv1_0(is, ids) };
			}
			public Credential generateCredential(Role head, Role tail,
												 KeyIDMap aliases) {
				return new GENICredentialv1_0(head, tail);
			}
		};
	}
}
