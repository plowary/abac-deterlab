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
 * An Internal Credential, used to represent extra arcs in the proof graph.  It
 * should never be converted to a cert or output.  They are useful outside as
 * placeholder credentials outside the main jabac library.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public class InternalCredential extends Credential {

    /**
     * Create an empty InternalCredential.
     */
    public InternalCredential() { super(); }
    /**
     * Create a credential from a head and tail role.  This credential has no
     * underlying certificate, and cannot be exported or used in real proofs.
     * @param head the Role at the head of the credential
     * @param tail the Role at the tail of the credential
     */
    public InternalCredential(Role head, Role tail) {super(head, tail); }

    /**
     * Create a certificate from this credential issued by the given identity
     * valid for the given period; this will always fail for an
     * InternalCredential.
     * @param i the Identity that will issue the certificate
     * @param validity a long holding the number of seconds that the credential
     * is valid for.
     * @throws ABACException whenever called.
     */
    public void make_cert(Identity i, long validity) throws ABACException {
	throw new ABACException("Cannot create certificate for " +
		"an InternalCredential");
    }

    /**
     * Create a certificate from this credential issued by the given identity;
     * this will always fail for an InternalCredential.
     * @param i the Identity that will issue the certificate
     * @throws ABACException whenever called.
     */
    public void make_cert(Identity i) throws ABACException {
	throw new ABACException("Cannot create certificate for " +
		"an InternalCredential");
    }

    /**
     * This will always do nothing for an InternalCredential.
     * @param s the OutputStream on which to write
     * @throws IOException never
     */
    public void write(OutputStream s) throws IOException { }

    /**
     * This will always do nothing for an  InternalCredential.
     * @param fn a String containing the output filename
     * @throws IOException never
     */
    public void write(String fn) 
	throws IOException, FileNotFoundException {
	write((OutputStream) null);
    }

    /**
     * Return true if this Credential has a certificate associated; it never
     * will.
     * @return false
     */
    public boolean hasCertificate() { return false; }

}
