package net.deterlab.abac;

import java.io.*;

import java.security.cert.Certificate;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import javax.security.auth.Subject;
import javax.security.auth.x500.*;

import java.math.BigInteger;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.util.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.x509.*;
import org.bouncycastle.openssl.*;


/**
 * An ABAC identity.  An X509 Certificate-encoded public key.  The key
 * identifier is used as the name of the Identity.  This whole class is
 * something of a jabac extension.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public class Identity implements Comparable {
	/** Default validity period (in seconds) */
	static public long defaultValidity = 3600L * 24L * 365L;
	/** The underlying X509 certificate. */
	protected X509Certificate cert;
	/** The public key id used as this principal's name */
	protected String keyid;
	/** The common name in the certificate, used as a mnemonic */
	protected String cn;
	/** The keypair, if any, used to sign for this Identity */
	protected KeyPair kp;
	/** The expiration for this Identity */
	protected Date expiration;

	/** Make sure BouncyCastle is loaded */
	static { Context.loadBouncyCastle(); }

	/**
	 * Initialize from PEM cert in a reader.  Use a PEMParser to get
	 * the certificate, and call init(cert) on it.
	 * @param r a Reader containing the certificate
	 * @throws CertInvalidException if the stream is unparsable
	 * @throws MissingIssuerException if none of the Identities can validate the
	 *				    certificate
	 * @throws BadSignatureException if the signature check fails
	 * @throws ABACException if an uncategorized error occurs
	 */
	protected void init(Reader r) throws ABACException {
		PEMParser pr = new PEMParser(r);
		Object c = null;

		try {
			while ( ( c= pr.readObject()) != null ){
				if (c instanceof X509Certificate) {
					if ( cn == null )
						init((X509Certificate)c);
					else
						throw new CertInvalidException("Two certs in one");
				}
				else if (c instanceof X509CertificateHolder && cn == null) {
					try {
						X509Certificate crt = new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder) c);
						init(crt);
					}
					catch (CertificateException e) {
						System.err.println(e.getMessage());
					}
				}
				else if (c instanceof KeyPair) setKeyPair((KeyPair)c);
				else {
					throw new CertInvalidException(
							"Not an identity certificate");
				}
			}
		}
		catch (IOException e) {
			throw new CertInvalidException(e.getMessage(), e);
		}
		// If there's nothing for the PEM reader to parse, the cert is invalid.
		if (cn == null)
			throw new CertInvalidException("Not an identity certificate");
	}

	/**
	 * Initialize internals from cert.  Confirm it is self signed,  and then
	 * the keyid and common name.  There's some work to get this stuff, but
	 * it's all an incantation of getting the right classes to get the right
	 * data.  Looks more complex than it is.
	 * @param c an X509Certificate to init from
	 * @throws CertInvalidException if the stream is unparsable
	 * @throws MissingIssuerException if none of the Identities can validate the
	 *				    certificate
	 * @throws BadSignatureException if the signature check fails
	 * @throws ABACException if an uncategorized error occurs
	 */
	protected void init(X509Certificate c) throws ABACException {
		cert = (X509Certificate) c;
		try {
			cert.verify(cert.getPublicKey());
		}
		catch (SignatureException e) {
			// XXX: the cert is not signed by the key we provided.  Right now
			// we check each cert as if it were self-signed. Other signing
			// strategies are allowed here by default.  We expect outside
			// sources to validate ID certs if they expect different chains of
		}
		catch (CertificateException e) {
			throw new CertInvalidException(e.getMessage(), e);
		}
		catch (InvalidKeyException e) {
			// XXX: the cert is not signed by the key we provided.  Right now
			// we check each cert as if it were self-signed. Other signing
			// strategies are allowed here by default.  We expect outside
			// sources to validate ID certs if they expect different chains of
			// trust.
		}
		catch (GeneralSecurityException e) {
			throw new ABACException(e.getMessage(), e);
		}

		// So far so good.  Check the validity (dates)
		try {
			cert.checkValidity();
		}
		catch (CertificateException e) {
			// Validity exceprions are derived from CertificateExceptions
			throw new CertInvalidException(e.getMessage(), e);
		}

		// Cert is valid, fill in the CN and keyid
		keyid = Context.extractKeyID(cert.getPublicKey());
		cn = cert.getSubjectDN().getName();
		expiration = cert.getNotAfter();
		/// XXX: better parse
		if (cn.startsWith("CN=")) cn = cn.substring(3);
	}

	/**
	 * Construct from a string, used as a CN.  Keys are generated.  If signer
	 * and signingKey are given, sign the certificate with them.  If neither is
	 * given, self sign it.  If one is given and not the other, throw an
	 * ABACException.
	 * @param cn a String containing the menomnic name
	 * @param validity a long containing the validity period (in seconds)
	 * @param signer an X509Certificate that is signing the Identity
	 * @param signingKey the key with which to sign
	 * @throws CertInvalidException if the stream is unparsable
	 * @throws MissingIssuerException if none of the Identities can validate the
	 *				    certificate
	 * @throws BadSignatureException if the signature check fails
	 * @throws ABACException if an uncategorized error occurs
	 */
	public Identity(String cn, long validity, X509Certificate signer,
					PrivateKey signingKey)
			throws ABACException, OperatorCreationException {

		if ( (signer != null && signingKey == null) ||
				(signer == null && signingKey != null) )
			throw new ABACException("Both signer and signingKey must be "+
					"given or neither");

		// TODO Modernize this code and make sure it works
		try {
			kp = KeyPairGenerator.getInstance("RSA").genKeyPair();
		}
		catch (NoSuchAlgorithmException e) {
			throw new ABACException(e.getMessage(), e);
		}
		X509CertificateHolder holder = null;
		X500Principal signerPrincipal = (signer != null) ? signer.getSubjectX500Principal() : new X500Principal("CN=" + cn);
		PrivateKey signerKey = (signingKey != null) ? signingKey : kp.getPrivate();

		X500Name issuerName = new X500Name(signerPrincipal.getName());
		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
		Date notBeforeDate = new Date(System.currentTimeMillis());
		Date notAfterDate = new Date(System.currentTimeMillis() + 1000L * validity);
		X500Name subjectName = new X500Name("CN=" + cn);
		SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());

		X509v3CertificateBuilder gen = new X509v3CertificateBuilder(issuerName, serial, notBeforeDate, notAfterDate,
				subjectName, spki);
		AlgorithmIdentifier sigAlgID = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSAEncryption");
		AlgorithmIdentifier digAlgID = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgID);
		AsymmetricKeyParameter privKeyParams;
		try {
			privKeyParams = PrivateKeyFactory.createKey(signerKey.getEncoded());
		}
		catch (IOException e) {
			throw new ABACException(e.getMessage(), e);
		}
		ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgID, digAlgID).build(privKeyParams);
		holder = gen.build(sigGen);

		JcaX509CertificateConverter holderToCert = new JcaX509CertificateConverter();
		try {
			cert = holderToCert.setProvider("BC").getCertificate(holder);
		}
		catch (CertificateException e) {
			throw new ABACException(e.getMessage(), e);
		}
		init(cert);
		// Rewrite above this line; original below this line
		/*X509V1CertificateGenerator gen = new X509V1CertificateGenerator();
		try {
			kp = KeyPairGenerator.getInstance("RSA").genKeyPair();
		}
		catch (NoSuchAlgorithmException e) {
			throw new ABACException(e.getMessage(), e);
		}
		X509Certificate a = null;
		X500Principal sp = (signer != null ) ?
			signer.getSubjectX500Principal() : new X500Principal("CN=" + cn);
		PrivateKey sk = (signingKey != null ) ? signingKey : kp.getPrivate();

		gen.setIssuerDN(sp);
		gen.setSubjectDN(new X500Principal("CN=" + cn));
		gen.setNotAfter(new Date(System.currentTimeMillis() +
			1000L * validity));
		gen.setNotBefore(new Date(System.currentTimeMillis()));
		gen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		gen.setPublicKey(kp.getPublic());
		gen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		try {
			a = (X509Certificate) gen.generate(sk, "BC");
		}
		catch (CertificateEncodingException e) {
			throw new CertInvalidException(e.getMessage(), e);
		}
		catch (GeneralSecurityException e) {
			throw new ABACException(e.getMessage(), e);
		}
		*/
	}
	/**
	 * Construct from a string, used as a CN.  Keys are generated.
	 * @param cn a String containing the menomnic name
	 * @param validity a long containing the validity period (in seconds)
	 * @throws CertInvalidException if the stream is unparsable
	 * @throws MissingIssuerException if none of the Identities can validate the
	 *				    certificate
	 * @throws BadSignatureException if the signature check fails
	 * @throws ABACException if an uncategorized error occurs
	 */
	public Identity(String cn, long validity) throws ABACException, OperatorCreationException {
		this(cn, validity, null, null);
	}

	/**
	 * Construct from a string, used as a CN.  Keys are generated.
	 * @param cn a String containing the menomnic name
	 * @throws CertInvalidException if the stream is unparsable
	 * @throws MissingIssuerException if none of the Identities can validate the
	 *				    certificate
	 * @throws BadSignatureException if the signature check fails
	 * @throws ABACException if an uncategorized error occurs
	 */
	public Identity(String cn) throws ABACException, OperatorCreationException {
		this(cn, defaultValidity);
	}

	/**
	 * Construct from a file containing a self-signed PEM certificate.
	 * @param file the File to read
	 * @throws CertInvalidException if the stream is unparsable
	 * @throws MissingIssuerException if none of the Identities can validate the
	 *				    certificate
	 * @throws BadSignatureException if the signature check fails
	 * @throws ABACException if an uncategorized error occurs
	 * @throws FileNotFoundException if the file is invalid
	 */
	public Identity(File file) throws ABACException, FileNotFoundException {
		kp = null;
		init(new FileReader(file));
	}

	/**
	 * Construct from a reader containing a self-signed PEM certificate.
	 * @param r the Reader containing the certificate
	 * @throws CertInvalidException if the stream is unparsable
	 * @throws MissingIssuerException if none of the Identities can validate the
	 *				    certificate
	 * @throws BadSignatureException if the signature check fails
	 * @throws ABACException if an uncategorized error occurs
	 */
	public Identity(Reader r) throws ABACException {
		kp = null;
		init(r);
	}

	/**
	 * Construct from an InputStream containing a self-signed PEM certificate.
	 * @param s the InputStream containing the certificate
	 * @throws CertInvalidException if the stream is unparsable
	 * @throws MissingIssuerException if none of the Identities can validate the
	 *				    certificate
	 * @throws BadSignatureException if the signature check fails
	 * @throws ABACException if an uncategorized error occurs
	 */
	public Identity(InputStream s) throws ABACException {
		kp = null;
		init(new InputStreamReader(s));
	}

	/**
	 * Construct from an X509Certificate
	 * @param cert an X509Certificate to init from
	 * @throws CertInvalidException if the stream is unparsable
	 * @throws MissingIssuerException if none of the Identities can validate the
	 *				    certificate
	 * @throws BadSignatureException if the signature check fails
	 * @throws ABACException if an uncategorized error occurs
	 */
	public Identity(X509Certificate cert) throws ABACException {
		kp = null;
		init(cert);
	}

	/**
	 * Write the PEM key to the given writer.
	 * @param w the Writer
	 * @return true if the Identity had a keypair and wrote the key
	 * @throws IOException if writing fails
	 */
	public boolean writePrivateKey(Writer w) throws IOException {
		if (kp != null ) {
			JcaPEMWriter pw = new JcaPEMWriter(w);
			pw.writeObject(kp.getPrivate());
			pw.flush();
			return true;
		}
		else return false;
	}

	/**
	 * Write the PEM key to a file with the given name.
	 * @param fn a file name to write to
	 * @return true if the Identity had a keypair and wrote the key
	 * @throws IOException if writing fails (including bad file name)
	 */
	public boolean writePrivateKey(String fn) throws IOException {
		return writePrivateKey(new FileWriter(fn));
	}

	/**
	 * Write the PEM key to the given file.
	 * @param fn a String with the output file name
	 * @return true if the Identity had a keypair and wrote the key
	 * @throws IOException if writing fails (including bad file name)
	 */
	public boolean writePrivateKey(File fn) throws IOException {
		return writePrivateKey(new FileWriter(fn));
	}

	/**
	 * Write the PEM key to the given OutputStream.
	 * @param s an OutputStream to write on
	 * @return true if the Identity had a keypair and wrote the key
	 * @throws IOException if writing fails (including bad file name)
	 */
	public boolean writePrivateKey(OutputStream s) throws IOException {
		return writePrivateKey(new OutputStreamWriter(s));
	}


	/**
	 * Write the PEM cert to the given writer.
	 * @param w a Writer to write on
	 * @throws IOException if writing fails
	 */
	public void write(Writer w) throws IOException {
		JcaPEMWriter pw = new JcaPEMWriter(w);
		pw.writeObject(cert);
		pw.flush();
	}

	/**
	 * Write the PEM cert to a file with the given name.
	 * @param fn a file name to write to
	 * @throws IOException if writing fails (including bad file name)
	 */
	public void write(String fn) throws IOException {
		write(new FileWriter(fn));
	}

	/**
	 * Write the PEM cert to the given file.
	 * @param fn a String with the output file name
	 * @throws IOException if writing fails
	 */
	public void write(File fn) throws IOException {
		write(new FileWriter(fn));
	}

	/**
	 * Write the PEM cert to the given OutputStream.
	 * @param s an OutputStream to write on
	 * @throws IOException if writing fails
	 */
	public void write(OutputStream s) throws IOException {
		write(new OutputStreamWriter(s));
	}


	/**
	 * Return the Identity's KeyID
	 * @return the Identity's KeyID
	 */
	public String getKeyID() { return keyid; }
	/**
	 * Return the Identity's mnemonic name
	 * @return the Identity's mnemonic name
	 */
	public String getName() { return cn; }
	/**
	 * Return the Identity's X509 Certificate
	 * @return the Identity's X509 Certificate
	 */
	public X509Certificate getCertificate() { return cert; }

	/**
	 * Return the expiration time of the Identity
	 * @return a Date the expiration time of the Identity
	 */
	public Date getExpiration(){ return expiration; }

	/**
	 * Return a simple string rep of the Identity.
	 * @return a simple string rep of the Identity.
	 */
	public String toString() {
		String s = keyid + " (" + cn ;

		if (getKeyPair() != null ) s += " [keyed]";
		s += ")";
		return s;
	}
	/**
	 * Associate a keypair with this Identity.  If the ID has a certificate,
	 * make sure that the keypair matches it.  If not throw an
	 * IllegalArgumentException.
	 * @param k the KeyPair to connect
	 * @throws IllegalArgumentException if the keypair does not
	 *				    match the pubkey in the X509 certificate
	 */
	public void setKeyPair(KeyPair k) {
		if (keyid != null) {
			String kid = Context.extractKeyID(k.getPublic());

			if ( kid != null && kid.equals(keyid)) kp = k;
			else
				throw new IllegalArgumentException(
						"Keypair does not match certificate");
		}
		else kp = k;
	}

	/**
	 * Return the keypair associated with this Identity (if any)
	 * @return the keypair associated with this Identity (if any)
	 */
	public KeyPair getKeyPair() { return kp; }

	/**
	 * Return true if the two identites refer to teh same key.  Two Identities
	 * are equal if their key ID's match.
	 * @return true if the two key ID's are equal.
	 */
	public boolean equals(Object o) {
		if ( o == null ) return false;
		else if ( ! (o instanceof Identity) ) return false;
		else return getKeyID().equals(((Identity)o).getKeyID());
	}

	/**
	 * Return a hash code for the Identity - the hash of its KeyID()
	 * @return an int, the hashCode
	 */
	public int hashCode() {
		if (keyid == null) return super.hashCode();
		return keyid.hashCode();
	}


	/**
	 * Order 2 identities for sorting.  They are ordered by their key ID's.
	 * @param o an Object to compare
	 * @return -1 if this Identity is before, 0 if they are the same, and 1
	 *		    if this Identity is after the given object.
	 */
	public int compareTo(Object o) {
		if ( ! (o instanceof Identity) ) return 1;
		else return getKeyID().compareTo(((Identity)o).getKeyID());
	}

};
