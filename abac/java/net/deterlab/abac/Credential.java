package net.deterlab.abac;

import java.io.*;
import java.math.*;

import java.util.*;
import java.security.*;
import java.security.cert.*;

import javax.security.auth.x500.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.*;
import org.bouncycastle.x509.util.*;
import org.bouncycastle.openssl.*;

/**
 * An ABAC credential, with or without an underlying certificate that
 * represents it.  These are edges in proof graphs and can be constructed from
 * their constituent Roles.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public abstract class Credential implements Comparable {
    /** Default validity period (in seconds) */
    static public long defaultValidity = 3600L * 24L * 365L;
    /** The role at the head */
    protected Role m_head
    /** The role at the tail */;
    protected Role m_tail;
    /** The identity that issued the certificate */
    protected Identity id;
    /** The expiration time of the credential */
    protected Date m_expiration;
    /** 
     * Suggested file suffix to save this format credential under.  Subclasses
      should override it.
     */
    protected String suffix;
    /** Default file suffix. */
    private static final String defSuffix = ".cred";

    /**
     * Create an empty Credential.
     */
    Credential() {
	m_head = m_tail = null;
	id = null;
	m_expiration = null;
	suffix = defSuffix;
    }
    /**
     * Create a credential from a head and tail role.  This credential has no
     * underlying certificate, and cannot be exported or used in real proofs.
     * make_cert can create a certificate for a credential initialized this
     * way.
     * @param head the Role at the head of the credential
     * @param tail the Role at the tail of the credential
     */
    Credential(Role head, Role tail) {
        m_head = head;
        m_tail = tail;
	id = null;
	m_expiration = null;
	suffix = defSuffix;
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
    Credential(String filename, Collection<Identity> ids) 
	throws ABACException { this(); }

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
    Credential(File file, Collection<Identity> ids) 
	    throws ABACException { this(); }

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
    Credential(InputStream s, Collection<Identity> ids) 
	    throws ABACException { this(); }

    /**
     * Create a certificate from this credential issued by the given identity,
     * valid for the given time.
     * @param i the Identity that will issue the certificate
     * @param validity a long holding the number of seconds that the credential
     * is valid for.
     * @throws ABACException for Credential-specific errors
     * @throws MissingIssuerException the identity is invalid
     * @throws BadSignatureException if the signature creation fails
     */
    public abstract void make_cert(Identity i, long validity) 
	    throws ABACException;
    /**
     * Create a certificate from this credential issued by the given identity,
     * valid for the default interval.
     * @param i the Identity that will issue the certificate
     * @throws ABACException for Credential-specific errors
     * @throws MissingIssuerException the identity is invalid
     * @throws BadSignatureException if the signature creation fails
     */
    public abstract void make_cert(Identity i) 
	    throws ABACException;

    /**
     * Return true if 2 credentials represent the same ABAC. Two credentials
     * are the same if their roles are the same.
     * @param o an Object to compare
     * @return true if the Credentials have the Roles 
     */
    public boolean equals(Object o) {
	if ( o instanceof Credential ) {
	    Credential c = (Credential) o;

	    if (m_head == null || m_tail == null ) return false;
	    else return (m_head.equals(c.head()) && m_tail.equals(c.tail()));
	}
	else return false;
    }

    /**
     * Return a hash code for the Credential - the hashes of its roles.
     * @return an int, the hashCode
     */
    public int hashCode() {
	if ( m_head == null || m_tail == null) return super.hashCode();

	return m_head.hashCode() + m_tail.hashCode();
    }

    /**
     * Compare 2 credentials for sorting.  They are ordered by their Roles,
     * head then tail.
     * @param o an Object to compare
     * @return -1 if this Credential is before, 0 if they are the same, and 1
     *		    if this Credential is after the given object.
     */
    public int compareTo(Object o) {
	if (o instanceof Credential) {
	    Credential c = (Credential) o;

	    if (head().equals(c.head())) return tail().compareTo(c.tail());
	    else return head().compareTo(c.head());
	}
	else return 1;
    }


    /**
     * Get the head role from the credential.
     * @return the Role in the head
     */
    public Role head() { return m_head; }

    /**
     * Get the tail role from the credential
     * @return the Role in the tail
     */
    public Role tail() { return m_tail; }

    /**
     * Get the expiration Date of the credential.
     * @return the expiration as a Date
     */
    public Date expiration() { return m_expiration; }

    /**
     * Return an untranslated string form of the credential. The format is head
     * &lt;- tail. For example: A.r1 &lt;- B.r2.r3.  Principal names are key
     * identifiers.
     * @return the string form
     */
    public String toString() {
        return m_head + " <- " + m_tail;
    }

    /**
     * Return a translated string form of the credential. The format is head
     * &lt;- tail. For example: A.r1 &lt;- B.r2.r3.  Principal names are
     * shortened to menmonics if the Context knows the identity.
     * @param c the Context to translate names in
     * @return the string form
     */
    public String simpleString(Context c) {
	return m_head.simpleString(c) + " <- " + m_tail.simpleString(c);
    }

    /**
     * Output the external representation of the Credential to the OutputStream
     * given. Subclasses will overload this for their output format.
     * @param s the OutputStream on which to write
     * @throws IOException if there is an error writing.
     */
    public abstract void write(OutputStream s) throws IOException;

    /**
     * Output the external representation of the Credential to the filename
     * given. Subclasses will overload this for their output format.
     * @param fn a String containing the output filename
     * @throws IOException if there is an error writing.
     */
    public abstract void write(String fn) 
	throws IOException;

    /**
     * Return true if this Credential has a certificate associated.  A jabac
     * extension.
     * @return true if this Credential has a certificate associated.
     */
    public abstract boolean hasCertificate();

    /**
     * Return the Identity that issued the underlying certificate (if any).  A
     * jabac extension.
     * @return the Identity that issued the underlying certificate. 
     */
    public Identity issuer() { return id; }

    /**
     * Return an suggested suffix for output files (most start with a ".").
     * @return a String, an optional suffix for output files.
     */
    public String getSuffix() { return suffix; } 

    /**
     * Set the suggested suffix for output files (most start with a ".").
     * Available for subclasses to set the value without knowing the member
     * name.
     * @param suff a String, an optional suffix for output files.
     */
    protected void setSuffix(String suff) { suffix = suff; } 

}
